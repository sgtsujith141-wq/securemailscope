"""Manifest-driven verification of the M3 TLS and certificate layer.

Expectations come from the committed fixture manifests. Fixtures built from
live OpenSSL handshakes or randomised certificate signatures are not
byte-reproducible, so their manifests record no capture hash and the semantic
expectations below carry the whole test.
"""

from __future__ import annotations

from typing import Any

import pytest

from securemailscope import analyze_capture

from .conftest import Fixture

TLS_FIXTURES = [
    "T_A_tls12_complete_handshake",
    "T_B_tls12_ecdhe",
    "T_C_tls12_static_rsa",
    "T_D_tls13_negotiation",
    "T_E_tls13_encrypted_certificate",
    "T_F_tls13_resumption",
    "T_G_client_hello_only",
    "T_H_server_hello_only",
    "T_I_record_split_across_packets",
    "T_J_handshake_split_across_records",
    "T_K_multiple_messages_one_record",
    "T_L_truncated_record",
    "T_M_missing_segment_during_handshake",
    "T_N_conflicting_overlapping_bytes",
    "T_O_expired_certificate",
    "T_P_not_yet_valid_certificate",
    "T_Q_self_signed_certificate",
    "T_R_valid_trusted_chain",
    "T_S_incomplete_chain",
    "T_T_hostname_scenarios",
    "T_U_unknown_reference_identity",
    "T_V_implicit_tls_on_email_port",
    "T_W_starttls_then_tls",
    "T_X_starttls_without_client_hello",
    "T_Y_malformed_certificate_lengths",
    "T_Z_alert_aborted_negotiation",
    "T_HRR_hello_retry_request",
]


def _expected(fixture: Fixture) -> list[dict[str, Any]]:
    return fixture.expected_tls


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_session_shape_matches_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    expected_all = _expected(fixture)
    assert len(result.tls) >= len(expected_all), f"{fixture.name}: no TLS analysis produced"

    for expected in expected_all:
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/tls{expected['session_index']}"
        assert analysis.entry_point.value == expected["entry_point"], f"{label}: entry point"
        assert (
            analysis.handshake_state.value == expected["handshake_state"]
        ), f"{label}: handshake state"
        assert (
            analysis.client_record_parse_state.value == expected["client_record_parse_state"]
        ), f"{label}: client record parse state"
        assert (
            analysis.server_record_parse_state.value == expected["server_record_parse_state"]
        ), f"{label}: server record parse state"
        assert (
            analysis.server_name_indication == expected["server_name_indication"]
        ), f"{label}: SNI"
        # Every session analysed must state what it could not establish.
        assert analysis.limitations, f"{label}: limitations are mandatory"


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_version_negotiation_matches_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/version"
        version = analysis.version

        if expected["selected_version"] is None:
            assert version.selected_version is None, f"{label}: nothing was negotiated"
            assert version.negotiation_status.value == "UNKNOWN"
            assert version.limitations, f"{label}: an unknown version must be explained"
        else:
            assert version.selected_version is not None, f"{label}: version missing"
            assert (
                version.selected_version.name == expected["selected_version"]
            ), f"{label}: selected version"
            assert version.negotiation_status.value == "OBSERVED"
        if expected["selected_version_source"] is not None:
            assert (
                version.selected_source == expected["selected_version_source"]
            ), f"{label}: version source"


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_cipher_suite_matches_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/cipher"
        suite = analysis.cipher_suite

        if expected["selected_cipher_suite"] is None:
            assert suite.selected is None or suite.selection_status.value == "UNKNOWN"
        else:
            assert suite.selected is not None, f"{label}: no suite selected"
            assert (
                suite.selected.name == expected["selected_cipher_suite"]
            ), f"{label}: selected suite"
            assert suite.selected.known is True
        assert (
            suite.decomposition_applicable == expected["cipher_decomposition_applicable"]
        ), f"{label}: decomposition applicability"
        assert suite.key_exchange == expected["cipher_key_exchange"], f"{label}: kx field"
        assert suite.registry_source and suite.registry_revision, f"{label}: registry named"


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_key_exchange_and_forward_secrecy_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/kx"
        key_exchange = analysis.key_exchange
        assert key_exchange.method == expected["key_exchange_method"], f"{label}: method"
        if expected["key_exchange_source"] is not None:
            assert (
                key_exchange.method_source == expected["key_exchange_source"]
            ), f"{label}: source"
        if expected["selected_group"] is not None:
            assert key_exchange.selected_group is not None, f"{label}: no group"
            assert (
                key_exchange.selected_group.name == expected["selected_group"]
            ), f"{label}: group"
        assert (
            key_exchange.hello_retry_request_observed == expected["hello_retry_request"]
        ), f"{label}: HRR flag"

        forward_secrecy = analysis.forward_secrecy
        assert (
            forward_secrecy.status.value == expected["forward_secrecy_status"]
        ), f"{label}: forward secrecy"
        assert forward_secrecy.criteria, f"{label}: criteria must be stated"
        # Passive analysis can never verify a handshake completed.
        assert forward_secrecy.handshake_completion_observable is False
        assert forward_secrecy.handshake_completion_explanation


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_handshake_messages_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/messages"
        if not expected["message_types"]:
            continue
        observed = [message.message_type_name for message in analysis.messages]
        assert observed == expected["message_types"], f"{label}: message sequence"
        for message in analysis.messages:
            assert message.packet_refs, f"{label}: {message.message_type_name} has no packets"
            assert message.first_timestamp is not None
            assert message.first_timestamp.tzinfo is not None
            assert message.record_indices, f"{label}: no contributing records recorded"


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_certificates_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        label = f"{fixture.name}/certificates"
        inventory = analysis.certificates
        assert (
            inventory.visibility.value == expected["certificate_visibility"]
        ), f"{label}: visibility"
        assert inventory.visibility_explanation, f"{label}: visibility must be explained"
        assert (
            inventory.chain_length == expected["certificate_count"]
        ), f"{label}: chain length"

        for observation, wanted in zip(
            inventory.certificates, expected["certificates"], strict=False
        ):
            assert observation.subject == wanted["subject"], f"{label}: subject"
            assert observation.issuer == wanted["issuer"], f"{label}: issuer"
            assert (
                observation.public_key.algorithm == wanted["public_key_algorithm"]
            ), f"{label}: key algorithm"
            assert (
                observation.public_key.size_bits == wanted["public_key_size_bits"]
            ), f"{label}: key size"
            assert (
                observation.signature_algorithm == wanted["signature_algorithm"]
            ), f"{label}: signature algorithm"
            assert sorted(observation.subject_alternative_names) == sorted(
                wanted["subject_alternative_names"]
            ), f"{label}: SANs"
            assert observation.is_self_issued == wanted["is_self_issued"], f"{label}: self"
            assert len(observation.sha256_fingerprint) == 64
            assert observation.packet_refs, f"{label}: certificate has no provenance"


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_validation_checks_are_independent_and_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        wanted = expected["validation"]
        if wanted is None:
            continue
        label = f"{fixture.name}/validation"
        validation = analysis.certificates.validation
        assert validation is not None, f"{label}: no validation block"
        for field, status in (
            ("certificate_observed", wanted["certificate_observed"]),
            ("validity_dates_checked", wanted["validity_dates_checked"]),
            ("chain_verified", wanted["chain_verified"]),
            ("hostname_verified", wanted["hostname_verified"]),
            ("revocation_checked", wanted["revocation_checked"]),
        ):
            check = getattr(validation, field)
            assert check.status.value == status, f"{label}: {field}"
            assert check.explanation, f"{label}: {field} must explain itself"
        # Revocation is never performed, whatever else passed.
        assert validation.revocation_checked.status.value == "NOT_AVAILABLE"
        assert "no network requests" in validation.revocation_checked.explanation


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_warning_codes_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.tls[expected["session_index"]]
        observed = {warning.code.value for warning in analysis.warnings}
        for code in expected["expected_warning_codes"]:
            assert code in observed, (
                f"{fixture.name}: expected warning {code}; saw {sorted(observed)}"
            )


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_no_handshake_is_ever_claimed_verified(fixture: Fixture) -> None:
    """The guarantee that must hold for every session M3 produces."""
    result = analyze_capture(fixture.path)
    assert result.tls_inventory.handshakes_cryptographically_verified == 0
    assert result.tls_inventory.revocation_checks_performed == 0
    for analysis in result.tls:
        assert analysis.forward_secrecy.handshake_completion_observable is False


@pytest.mark.parametrize("fixture", TLS_FIXTURES, indirect=True)
def test_records_carry_provenance(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for analysis in result.tls:
        for record in analysis.records:
            assert record.packet_refs, "every record must name the packets that carried it"
            assert record.end_offset >= record.stream_offset
            assert record.limitations, "framing evidence must state what it does not prove"
            if record.encrypted:
                assert record.body_interpreted is False
