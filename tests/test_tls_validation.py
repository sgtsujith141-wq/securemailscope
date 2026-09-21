"""Certificate validation, resource bounds and the passive guarantee.

These drive the same fixtures with different configurations, because the
interesting questions are about what changes when you supply a trust store or
an expected identity -- and what must stay NOT_AVAILABLE when you do not.
"""

from __future__ import annotations

import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from securemailscope import AnalysisConfig, analyze_capture

from .conftest import Fixture


def _analyse(fixture: Fixture, **overrides: object):
    config = replace(AnalysisConfig(), **overrides)  # type: ignore[arg-type]
    return analyze_capture(fixture.path, config=config)


def _validation(fixture: Fixture, **overrides: object):
    result = _analyse(fixture, **overrides)
    assert result.tls, f"{fixture.name}: no TLS analysis"
    validation = result.tls[0].certificates.validation
    assert validation is not None
    return validation


# -- chain verification ------------------------------------------------------
def test_chain_is_not_available_without_a_trust_store(fixtures: dict[str, Fixture]) -> None:
    validation = _validation(fixtures["T_R_valid_trusted_chain"])
    check = validation.chain_verified
    assert check.status.value == "NOT_AVAILABLE"
    assert "never falls back to a system trust store" in check.explanation
    assert validation.trust_store.configured is False


def test_chain_verifies_against_a_configured_trust_store(
    fixtures: dict[str, Fixture], trust_store_pem: Path
) -> None:
    validation = _validation(
        fixtures["T_R_valid_trusted_chain"], trust_store_path=str(trust_store_pem)
    )
    check = validation.chain_verified
    assert check.status.value == "PASSED", check.explanation
    assert check.assessment_mode.value == "CAPTURE_TIME"
    assert validation.trust_store.configured is True
    assert validation.trust_store.anchor_count == 1
    assert validation.trust_store.anchor_set_digest
    assert validation.trust_store.policy == "RFC5280_WEB_PKI"
    # A verified path says nothing about revocation.
    assert "revocation" in " ".join(check.limitations).lower()


def test_self_signed_certificate_does_not_chain_to_the_root(
    fixtures: dict[str, Fixture], trust_store_pem: Path
) -> None:
    validation = _validation(
        fixtures["T_Q_self_signed_certificate"], trust_store_path=str(trust_store_pem)
    )
    assert validation.chain_verified.status.value == "FAILED"
    result = _analyse(
        fixtures["T_Q_self_signed_certificate"], trust_store_path=str(trust_store_pem)
    )
    leaf = result.tls[0].certificates.certificates[0]
    # Self-issued is a fact about the certificate, not a trust verdict.
    assert leaf.is_self_issued is True


def test_incomplete_chain_is_distinguished_from_an_invalid_one(
    fixtures: dict[str, Fixture], trust_store_pem: Path
) -> None:
    validation = _validation(
        fixtures["T_S_incomplete_chain"], trust_store_path=str(trust_store_pem)
    )
    check = validation.chain_verified
    assert check.status.value == "FAILED"
    assert "chain appears incomplete" in check.explanation
    assert "different condition" in check.explanation


def test_a_missing_trust_store_file_is_reported_not_ignored(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    validation = _validation(
        fixtures["T_R_valid_trusted_chain"], trust_store_path=str(tmp_path / "absent.pem")
    )
    check = validation.chain_verified
    assert check.status.value == "NOT_AVAILABLE"
    assert check.detail is not None
    assert "not a readable file" in check.detail


# -- hostname verification ---------------------------------------------------
def test_hostname_is_not_available_without_a_reference_identity(
    fixtures: dict[str, Fixture],
) -> None:
    validation = _validation(fixtures["T_T_hostname_scenarios"])
    check = validation.hostname_verified
    assert check.status.value == "NOT_AVAILABLE"
    assert "destination IP address is never used" in check.explanation
    assert validation.reference_identity is None
    assert validation.reference_identity_source == "NONE"


def test_hostname_matches_a_supplied_identity(fixtures: dict[str, Fixture]) -> None:
    validation = _validation(
        fixtures["T_T_hostname_scenarios"], expected_server_identity="mail.example.invalid"
    )
    assert validation.hostname_verified.status.value == "PASSED"
    assert validation.reference_identity_source == "OPERATOR_SUPPLIED"


def test_hostname_wildcard_matches(fixtures: dict[str, Fixture]) -> None:
    validation = _validation(
        fixtures["T_T_hostname_scenarios"],
        expected_server_identity="host.alt.example.invalid",
    )
    assert validation.hostname_verified.status.value == "PASSED"


def test_hostname_mismatch_is_detected(fixtures: dict[str, Fixture]) -> None:
    validation = _validation(
        fixtures["T_T_hostname_scenarios"], expected_server_identity="wrong.example.invalid"
    )
    check = validation.hostname_verified
    assert check.status.value == "FAILED"
    assert "wrong.example.invalid" in check.explanation
    assert "DNS:mail.example.invalid" in check.explanation


def test_observed_sni_is_evidence_not_an_expectation(
    fixtures: dict[str, Fixture],
) -> None:
    """SNI says what the client asked for, not what the analyst expects."""
    fixture = fixtures["T_U_unknown_reference_identity"]
    default = _validation(fixture)
    assert default.observed_sni == "mail.example.invalid"
    assert default.hostname_verified.status.value == "NOT_AVAILABLE"

    # Opting in makes it the reference identity -- and it then does not match.
    elected = _validation(fixture, trust_observed_sni_as_identity=True)
    assert elected.reference_identity == "mail.example.invalid"
    assert elected.reference_identity_source == "OBSERVED_SNI_EXPLICITLY_TRUSTED"
    assert elected.hostname_verified.status.value == "FAILED"


def test_chain_and_hostname_are_independent(
    fixtures: dict[str, Fixture], trust_store_pem: Path
) -> None:
    """A trusted chain with the wrong name fails only the name check."""
    validation = _validation(
        fixtures["T_T_hostname_scenarios"],
        trust_store_path=str(trust_store_pem),
        expected_server_identity="wrong.example.invalid",
    )
    assert validation.chain_verified.status.value == "PASSED"
    assert validation.hostname_verified.status.value == "FAILED"


# -- validity dates ----------------------------------------------------------
def test_expired_at_capture_time(fixtures: dict[str, Fixture]) -> None:
    validation = _validation(fixtures["T_O_expired_certificate"])
    check = validation.validity_dates_checked
    assert check.status.value == "FAILED"
    assert "had already expired" in check.explanation
    assert check.assessment_mode.value == "CAPTURE_TIME"
    assert check.reference_time is not None
    assert check.reference_time.tzinfo is not None


def test_not_yet_valid_at_capture_time(fixtures: dict[str, Fixture]) -> None:
    check = _validation(fixtures["T_P_not_yet_valid_certificate"]).validity_dates_checked
    assert check.status.value == "FAILED"
    assert "was not yet valid" in check.explanation


def test_capture_time_is_used_not_the_analysis_clock(
    fixtures: dict[str, Fixture],
) -> None:
    """The certificate is valid at capture time; the wall clock is irrelevant."""
    check = _validation(fixtures["T_R_valid_trusted_chain"]).validity_dates_checked
    assert check.status.value == "PASSED"
    assert check.assessment_mode.value == "CAPTURE_TIME"
    assert check.reference_time is not None
    assert check.reference_time.year == 2026


def test_current_time_assessment_is_additive_and_labelled(
    fixtures: dict[str, Fixture],
) -> None:
    check = _validation(
        fixtures["T_R_valid_trusted_chain"], assess_certificates_at_current_time=True
    ).validity_dates_checked
    assert check.assessment_mode.value == "CAPTURE_TIME"
    assert any("At analysis time" in text for text in check.limitations)
    assert any("separate assessment" in text for text in check.limitations)


# -- TLS 1.3 honesty ---------------------------------------------------------
def test_tls13_certificate_is_unavailable_not_missing(
    fixtures: dict[str, Fixture], trust_store_pem: Path
) -> None:
    result = _analyse(
        fixtures["T_E_tls13_encrypted_certificate"], trust_store_path=str(trust_store_pem)
    )
    inventory = result.tls[0].certificates
    assert inventory.visibility.value == "ENCRYPTED_TLS13"
    assert "encrypted under handshake traffic keys" in inventory.visibility_explanation
    assert "permanent limit of passive analysis" in inventory.visibility_explanation
    assert inventory.certificates == ()
    # Even with a trust store configured, nothing can be verified.
    validation = inventory.validation
    assert validation is not None
    assert validation.chain_verified.status.value == "NOT_AVAILABLE"


def test_tls13_version_comes_from_the_extension_not_legacy_version(
    fixtures: dict[str, Fixture],
) -> None:
    analysis = _analyse(fixtures["T_D_tls13_negotiation"]).tls[0]
    version = analysis.version
    assert version.selected_version is not None
    assert version.selected_version.name == "TLS 1.3"
    assert version.selected_source == "SUPPORTED_VERSIONS_EXTENSION"
    # The legacy field says 0x0303 by design; it must not drive the answer.
    assert version.server_legacy_version is not None
    assert version.server_legacy_version.value == 0x0303
    assert any("legacy_version field reads 0x0303" in t for t in version.limitations)


def test_tls13_cipher_suite_does_not_encode_key_exchange(
    fixtures: dict[str, Fixture],
) -> None:
    analysis = _analyse(fixtures["T_D_tls13_negotiation"]).tls[0]
    suite = analysis.cipher_suite
    assert suite.decomposition_applicable is False
    assert suite.key_exchange is None
    assert suite.authentication is None
    assert any("only an AEAD" in text for text in suite.limitations)
    # The real answer comes from key_share.
    assert analysis.key_exchange.method_source == "KEY_SHARE_EXTENSION"


def test_client_hello_alone_never_yields_a_negotiated_version(
    fixtures: dict[str, Fixture],
) -> None:
    analysis = _analyse(fixtures["T_G_client_hello_only"]).tls[0]
    assert analysis.version.offered_versions, "offered versions must still be reported"
    assert analysis.version.selected_version is None
    assert analysis.cipher_suite.offered, "offered suites must still be reported"
    assert analysis.cipher_suite.selected is None
    assert analysis.forward_secrecy.status.value == "UNKNOWN_INCOMPLETE_EVIDENCE"
    assert "never what was used" in analysis.forward_secrecy.criteria


# -- resource bounds ---------------------------------------------------------
def test_record_count_limit_is_enforced(fixtures: dict[str, Fixture]) -> None:
    result = _analyse(
        fixtures["T_J_handshake_split_across_records"], max_tls_records_per_direction=2
    )
    analysis = result.tls[0]
    assert analysis.server_record_parse_state.value == "LIMIT_REACHED"
    assert "LIMIT_TLS_RECORDS" in {w.code.value for w in analysis.warnings}


def test_handshake_buffer_limit_is_enforced(fixtures: dict[str, Fixture]) -> None:
    result = _analyse(
        fixtures["T_A_tls12_complete_handshake"], max_tls_handshake_bytes=128
    )
    analysis = result.tls[0]
    assert "LIMIT_TLS_HANDSHAKE_BYTES" in {w.code.value for w in analysis.warnings}


def test_certificate_count_limit_is_enforced() -> None:
    """A certificate_list longer than the limit is truncated with a note."""
    from securemailscope.tls.handshake import parse_certificate_message
    from securemailscope.tls.messages_helper import two_certificate_message

    body = two_certificate_message()
    certificates, notes = parse_certificate_message(
        body, tls13=False, max_certificates=1, max_certificate_bytes=65536
    )
    assert len(certificates) == 1
    assert any("truncated at the configured limit" in note for note in notes)


def test_zero_certificate_limit_is_rejected_as_configuration() -> None:
    from securemailscope.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        AnalysisConfig(max_certificates_per_chain=0)


def test_oversized_certificate_is_refused(fixtures: dict[str, Fixture]) -> None:
    result = _analyse(fixtures["T_A_tls12_complete_handshake"], max_certificate_bytes=16)
    inventory = result.tls[0].certificates
    assert inventory.chain_length == 0
    assert any("exceeds" in text for text in inventory.limitations)


def test_malformed_certificate_lengths_do_not_allocate(
    fixtures: dict[str, Fixture],
) -> None:
    analysis = _analyse(fixtures["T_Y_malformed_certificate_lengths"]).tls[0]
    assert analysis.certificates.visibility.value == "PARSE_FAILED"
    assert analysis.certificates.certificates == ()


# -- the passive guarantee ---------------------------------------------------
def test_tls_analysis_opens_no_socket(
    fixtures: dict[str, Fixture], monkeypatch: pytest.MonkeyPatch, trust_store_pem: Path
) -> None:
    """Chain verification must never fetch an intermediate or hit OCSP."""

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("TLS analysis attempted to open a socket")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket, "getaddrinfo", explode)
    monkeypatch.setattr(subprocess, "run", explode)
    monkeypatch.setattr(subprocess, "Popen", explode)

    result = _analyse(
        fixtures["T_S_incomplete_chain"],
        trust_store_path=str(trust_store_pem),
        expected_server_identity="deep.example.invalid",
    )
    assert result.tls[0].certificates.validation is not None


def test_reports_never_contain_raw_certificate_bytes(
    fixtures: dict[str, Fixture],
) -> None:
    from securemailscope.reporting.json_report import result_to_json

    result = _analyse(fixtures["T_A_tls12_complete_handshake"])
    text = result_to_json(result)
    assert "BEGIN CERTIFICATE" not in text
    assert "der_base64" not in text
    # The fingerprint and size are reported instead.
    leaf = result.tls[0].certificates.certificates[0]
    assert len(leaf.sha256_fingerprint) == 64
    assert leaf.der_size_bytes > 0
