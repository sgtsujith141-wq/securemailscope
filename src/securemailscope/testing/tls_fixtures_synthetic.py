"""M3 fixtures G-Z: constructed handshakes and certificate scenarios.

These are assembled byte by byte from the RFC structures, which is the only
way to produce the cases that matter most for a forensic parser: a record
split across TCP packets, a handshake message split across records, several
messages in one record, a truncated record, a hole mid-handshake, and bytes
two TCP segments disagree about.  OpenSSL cannot be asked for any of those.

Fixtures whose certificates are signed by the synthetic CA inherit ECDSA's
randomised signatures and are marked ``byte_reproducible=False``; the purely
structural ones are reproducible and assert a capture hash.
"""

from __future__ import annotations

from typing import Any, Final

from .certs import IssuedCertificate
from .dialogue import Dialogue
from .fixtures import FixtureSpec
from .manifest import ExpectedCertificate, ExpectedTLS, ExpectedValidation
from .tls_fixtures import (
    CAPTURE_TIMESTAMP_NS,
    SERVER_IDENTITY,
    SMTP_EHLO,
    SMTP_EHLO_TLS,
    SMTP_GREETING,
    SMTP_READY,
    SMTP_STARTTLS,
    WRONG_IDENTITY,
    _ca,
    _expected_leaf,
    _spec,
)
from .tls_messages import (
    CONTENT_HANDSHAKE,
    TLS12,
    TLS13,
    alert,
    certificate_message,
    change_cipher_spec,
    client_hello,
    hello_retry_request,
    record,
    records_for,
    server_hello,
    server_hello_done,
    server_key_exchange_ecdhe,
)

__all__ = ["build_synthetic_tls_fixtures"]

_ECDHE_ECDSA: Final = 0xC02B
_X25519: Final = 0x001D
_SECP256R1: Final = 0x0017


def _d(port: int = 993, *, handshake: bool = True) -> Dialogue:
    return Dialogue(server_port=port, handshake=handshake, start_ns=CAPTURE_TIMESTAMP_NS)


def _ch(**kwargs: Any) -> bytes:
    defaults: dict[str, Any] = {
        "cipher_suites": [_ECDHE_ECDSA],
        "server_name": SERVER_IDENTITY,
        "supported_groups": [_X25519, _SECP256R1],
        "signature_algorithms": [0x0403, 0x0804],
    }
    defaults.update(kwargs)
    return client_hello(**defaults)


def _tls12_server_flight(certificates: list[bytes]) -> bytes:
    return (
        server_hello(cipher_suite=_ECDHE_ECDSA, legacy_version=TLS12)
        + certificate_message(certificates)
        + server_key_exchange_ecdhe(named_curve=_SECP256R1)
        + server_hello_done()
    )


def _cert_validation(
    *, dates: str, chain: str, hostname: str, identity: str | None
) -> ExpectedValidation:
    return ExpectedValidation(
        certificate_observed="PASSED",
        validity_dates_checked=dates,
        chain_verified=chain,
        hostname_verified=hostname,
        revocation_checked="NOT_AVAILABLE",
        trust_store_configured=chain != "NOT_AVAILABLE",
        reference_identity=identity,
    )


def _tls12_expected(
    *,
    handshake_state: str = "SERVER_FLIGHT_COMPLETE",
    certificates: list[ExpectedCertificate] | None = None,
    certificate_count: int = 1,
    visibility: str = "OBSERVED",
    validation: ExpectedValidation | None = None,
    message_types: list[str] | None = None,
    client_state: str = "COMPLETE",
    server_state: str = "COMPLETE",
    forward_secrecy: str = "EPHEMERAL_OBSERVED",
    warnings: list[str] | None = None,
    entry_point: str = "IMPLICIT",
    sni: str | None = SERVER_IDENTITY,
) -> ExpectedTLS:
    return ExpectedTLS(
        session_index=0,
        entry_point=entry_point,
        handshake_state=handshake_state,
        client_record_parse_state=client_state,
        server_record_parse_state=server_state,
        selected_version="TLS 1.2",
        selected_version_source="LEGACY_VERSION",
        selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        cipher_decomposition_applicable=True,
        cipher_key_exchange="ECDHE",
        key_exchange_method="ECDHE",
        key_exchange_source="CIPHER_SUITE",
        selected_group="secp256r1",
        forward_secrecy_status=forward_secrecy,
        certificate_visibility=visibility,
        certificate_count=certificate_count,
        certificates=certificates or [],
        message_types=message_types
        or [
            "client_hello",
            "server_hello",
            "certificate",
            "server_key_exchange",
            "server_hello_done",
        ],
        server_name_indication=sni,
        validation=validation,
        expected_warning_codes=warnings or [],
    )


# ---------------------------------------------------------------------------
# G-H: one-sided handshakes
# ---------------------------------------------------------------------------
def _fixture_g() -> FixtureSpec:
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch(supported_versions=[TLS13, TLS12],
                                                key_share_groups=[_X25519])))
    d.ack_server()
    return _spec(
        "T_G_client_hello_only",
        "t_g_client_hello_only.pcap",
        "A ClientHello with no ServerHello. Offered versions and cipher suites must be "
        "reported as capability; the selected version and suite must stay UNKNOWN. The "
        "highest offered version must never be promoted to a negotiated one.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_g",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="CLIENT_HELLO_ONLY",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="NOT_TLS",
                selected_version=None,
                selected_cipher_suite=None,
                key_exchange_method="UNKNOWN",
                forward_secrecy_status="UNKNOWN_INCOMPLETE_EVIDENCE",
                certificate_visibility="NOT_OBSERVED",
                message_types=["client_hello"],
                server_name_indication=SERVER_IDENTITY,
                validation=ExpectedValidation(
                    certificate_observed="FAILED",
                    validity_dates_checked="NOT_AVAILABLE",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=True,
    )


def _fixture_h() -> FixtureSpec:
    d = _d(handshake=False)
    d.send_server(record(CONTENT_HANDSHAKE, server_hello(cipher_suite=_ECDHE_ECDSA)))
    d.ack_client()
    return _spec(
        "T_H_server_hello_only",
        "t_h_server_hello_only.pcap",
        "A ServerHello with no preceding ClientHello, as a midstream capture produces. "
        "The negotiated parameters are observable but the client's offers are not.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_h",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="SERVER_HELLO_WITHOUT_CLIENT_HELLO",
                client_record_parse_state="NOT_TLS",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="CAPABLE_NEGOTIATED",
                certificate_visibility="NOT_OBSERVED",
                message_types=["server_hello"],
                server_name_indication=None,
            )
        ],
        byte_reproducible=True,
    )


# ---------------------------------------------------------------------------
# I-K: fragmentation
# ---------------------------------------------------------------------------
def _fixture_i() -> FixtureSpec:
    """One TLS record delivered across several TCP segments."""
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=130)
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    flight = record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der]))
    sizes = [60, 200, len(flight) - 260]
    d.send_server_segmented(flight, sizes)
    d.ack_client()
    return _spec(
        "T_I_record_split_across_packets",
        "t_i_record_split_across_packets.pcap",
        "A single TLS record split across three TCP segments. Segments inside one "
        "reassembled run are contiguous, so the record must be framed normally and all "
        "three packets must appear in its provenance.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_i",
        d,
        [_tls12_expected(certificates=[_expected_leaf(leaf)],
                         validation=_cert_validation(dates="PASSED", chain="NOT_AVAILABLE",
                                                     hostname="NOT_AVAILABLE", identity=None))],
        byte_reproducible=False,
    )


def _fixture_j() -> FixtureSpec:
    """One handshake message split across several TLS records."""
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=131)
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    flight = _tls12_server_flight([leaf.der])
    d.send_server(records_for(CONTENT_HANDSHAKE, flight, chunk=128))
    d.ack_client()
    return _spec(
        "T_J_handshake_split_across_records",
        "t_j_handshake_split_across_records.pcap",
        "The server flight is emitted in 128-byte TLS records, so the Certificate "
        "message spans several of them. Handshake reassembly must recombine the record "
        "bodies and report which records carried each message.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_j",
        d,
        [_tls12_expected(certificates=[_expected_leaf(leaf)],
                         validation=_cert_validation(dates="PASSED", chain="NOT_AVAILABLE",
                                                     hostname="NOT_AVAILABLE", identity=None))],
        byte_reproducible=False,
    )


def _fixture_k() -> FixtureSpec:
    """Several handshake messages inside one TLS record."""
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=132)
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    d.send_server(record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der])))
    d.ack_client()
    return _spec(
        "T_K_multiple_messages_one_record",
        "t_k_multiple_messages_one_record.pcap",
        "ServerHello, Certificate, ServerKeyExchange and ServerHelloDone all travel in a "
        "single TLS record. All four must be reported as separate messages.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_k",
        d,
        [_tls12_expected(certificates=[_expected_leaf(leaf)],
                         validation=_cert_validation(dates="PASSED", chain="NOT_AVAILABLE",
                                                     hostname="NOT_AVAILABLE", identity=None))],
        byte_reproducible=False,
    )


# ---------------------------------------------------------------------------
# L-N: damaged input
# ---------------------------------------------------------------------------
def _fixture_l() -> FixtureSpec:
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    full = record(CONTENT_HANDSHAKE, server_hello(cipher_suite=_ECDHE_ECDSA))
    d.send_server(full[: len(full) - 20])  # the record body is cut short
    d.ack_client()
    return _spec(
        "T_L_truncated_record",
        "t_l_truncated_record.pcap",
        "The server's record declares more bytes than the capture contains. It must be "
        "reported truncated with the declared and available lengths, and framing must "
        "stop rather than continue into whatever follows.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_l",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="CLIENT_HELLO_ONLY",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="TRUNCATED_RECORD",
                selected_version=None,
                key_exchange_method="UNKNOWN",
                forward_secrecy_status="UNKNOWN_INCOMPLETE_EVIDENCE",
                certificate_visibility="NOT_OBSERVED",
                # The ServerHello is reported because its bytes began, but it
                # is incomplete so nothing is derived from it.
                message_types=["client_hello", "server_hello"],
                server_name_indication=SERVER_IDENTITY,
                expected_warning_codes=["TLS_RECORD_TRUNCATED"],
            )
        ],
        byte_reproducible=True,
    )


def _fixture_m() -> FixtureSpec:
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=133)
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    flight = record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der]))
    d.send_server(flight[:120])
    d.drop_server(flight[120:400])  # a segment the capture missed
    d.send_server(flight[400:])
    d.ack_client()
    return _spec(
        "T_M_missing_segment_during_handshake",
        "t_m_missing_segment_during_handshake.pcap",
        "A TCP segment is missing from the middle of the server's handshake. TLS records "
        "are only self-delimiting when every preceding byte was read, so framing must "
        "stop at the hole with ALIGNMENT_LOST_AT_GAP rather than resynchronising on a "
        "guess.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_m",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="INDETERMINATE",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="ALIGNMENT_LOST_AT_GAP",
                # The ServerHello is wholly contained in the bytes that did
                # arrive, so the negotiated parameters it states were genuinely
                # observed and are reported. The enclosing record is truncated
                # and the session is INDETERMINATE, which is what tells a
                # reader not to trust anything after that point.
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="CAPABLE_NEGOTIATED",
                certificate_visibility="NOT_OBSERVED",
                # The Certificate message began inside the bytes that arrived
                # but is cut off by the hole, so it is reported incomplete.
                message_types=["client_hello", "server_hello", "certificate"],
                server_name_indication=SERVER_IDENTITY,
                expected_warning_codes=[
                    "TLS_RECORD_ALIGNMENT_LOST",
                    "TLS_HANDSHAKE_MESSAGE_INCOMPLETE",
                ],
            )
        ],
        byte_reproducible=False,
    )


def _fixture_n() -> FixtureSpec:
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    first = record(CONTENT_HANDSHAKE, server_hello(cipher_suite=_ECDHE_ECDSA))
    second = bytes([0x16, 0x03, 0x03]) + b"\xff" * 40
    d.send_server_conflicting(first, second, overlap=16)
    d.ack_client()
    return _spec(
        "T_N_conflicting_overlapping_bytes",
        "t_n_conflicting_overlapping_bytes.pcap",
        "Two overlapping TCP segments disagree about the bytes carrying the server's "
        "TLS record. Those bytes must be flagged ambiguous and must not be treated as "
        "unambiguous cryptographic evidence.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_n",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="INDETERMINATE",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="AMBIGUOUS_BYTES",
                selected_version=None,
                key_exchange_method="UNKNOWN",
                forward_secrecy_status="UNKNOWN_INCOMPLETE_EVIDENCE",
                certificate_visibility="NOT_OBSERVED",
                server_name_indication=SERVER_IDENTITY,
                expected_warning_codes=["TLS_RECORD_AMBIGUOUS"],
            )
        ],
        byte_reproducible=True,
    )


# ---------------------------------------------------------------------------
# O-U: certificate scenarios
# ---------------------------------------------------------------------------
def _certificate_fixture(
    name: str,
    filename: str,
    description: str,
    builder: str,
    leaf: IssuedCertificate,
    *,
    chain_der: list[bytes] | None = None,
    expected_certs: list[ExpectedCertificate],
    validation: ExpectedValidation,
    warnings: list[str] | None = None,
) -> FixtureSpec:
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    d.send_server(record(CONTENT_HANDSHAKE, _tls12_server_flight(chain_der or [leaf.der])))
    d.ack_client()
    return _spec(
        name,
        filename,
        description,
        builder,
        d,
        [
            _tls12_expected(
                certificates=expected_certs,
                certificate_count=len(expected_certs),
                validation=validation,
                warnings=warnings,
            )
        ],
        byte_reproducible=False,
    )


def _fixture_o() -> FixtureSpec:
    leaf = _ca().issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=140,
        not_before_days=-400, not_after_days=-30,
    )
    return _certificate_fixture(
        "T_O_expired_certificate",
        "t_o_expired_certificate.pcap",
        "The server presents a certificate that had already expired at the capture "
        "timestamp. Validity must be judged against the capture's own clock, not the "
        "analysis clock.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_o",
        leaf,
        expected_certs=[_expected_leaf(leaf)],
        validation=_cert_validation(
            dates="FAILED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
        warnings=["CERTIFICATE_EXPIRED_AT_CAPTURE"],
    )


def _fixture_p() -> FixtureSpec:
    leaf = _ca().issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=141,
        not_before_days=30, not_after_days=400,
    )
    return _certificate_fixture(
        "T_P_not_yet_valid_certificate",
        "t_p_not_yet_valid_certificate.pcap",
        "The server presents a certificate that was not yet valid at the capture "
        "timestamp. This must be distinguished from expiry.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_p",
        leaf,
        expected_certs=[_expected_leaf(leaf)],
        validation=_cert_validation(
            dates="FAILED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
        warnings=["CERTIFICATE_NOT_YET_VALID_AT_CAPTURE"],
    )


def _fixture_q() -> FixtureSpec:
    leaf = _ca().issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=142, self_signed=True
    )
    return _certificate_fixture(
        "T_Q_self_signed_certificate",
        "t_q_self_signed_certificate.pcap",
        "A self-signed end-entity certificate. Subject equals issuer, which is recorded "
        "as a fact; whether it is trusted is the separate chain check.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_q",
        leaf,
        expected_certs=[_expected_leaf(leaf, self_signed=True)],
        validation=_cert_validation(
            dates="PASSED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
    )


def _fixture_r() -> FixtureSpec:
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=143)
    return _certificate_fixture(
        "T_R_valid_trusted_chain",
        "t_r_valid_trusted_chain.pcap",
        "A certificate issued by the synthetic root. With that root configured as a "
        "trust store the chain must verify; without one, chain verification must report "
        "NOT_AVAILABLE rather than falling back to a system store.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_r",
        leaf,
        expected_certs=[_expected_leaf(leaf)],
        validation=_cert_validation(
            dates="PASSED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
    )


def _fixture_s() -> FixtureSpec:
    """A chain whose intermediate the server failed to send."""
    authority = _ca()
    leaf = authority.issue(
        "deep.example.invalid", sans=["deep.example.invalid"], serial=144,
        via_intermediate=True,
    )
    return _certificate_fixture(
        "T_S_incomplete_chain",
        "t_s_incomplete_chain.pcap",
        "The server presents only its end-entity certificate, omitting the intermediate "
        "that links it to the root. With a trust store configured this must FAIL and be "
        "described as an incomplete chain, which is different from a chain that was "
        "built and found invalid.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_s",
        leaf,
        chain_der=[leaf.der],
        expected_certs=[_expected_leaf(leaf)],
        validation=_cert_validation(
            dates="PASSED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
    )


def _fixture_t() -> FixtureSpec:
    leaf = _ca().issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY, "*.alt.example.invalid"], serial=145
    )
    return _certificate_fixture(
        "T_T_hostname_scenarios",
        "t_t_hostname_scenarios.pcap",
        "A certificate naming mail.example.invalid and *.alt.example.invalid. The "
        "hostname tests drive this fixture with a matching identity, a mismatching one "
        "and none at all, and must produce three different outcomes.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_t",
        leaf,
        expected_certs=[_expected_leaf(leaf)],
        validation=_cert_validation(
            dates="PASSED", chain="NOT_AVAILABLE", hostname="NOT_AVAILABLE", identity=None
        ),
    )


def _fixture_u() -> FixtureSpec:
    """SNI is present but must not silently become the expected identity."""
    leaf = _ca().issue(WRONG_IDENTITY, sans=[WRONG_IDENTITY], serial=146)
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch(server_name=SERVER_IDENTITY)))
    d.send_server(record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der])))
    d.ack_client()
    return _spec(
        "T_U_unknown_reference_identity",
        "t_u_unknown_reference_identity.pcap",
        "The ClientHello carries SNI for mail.example.invalid but the certificate names "
        "webmail.other.invalid. With no operator-supplied identity, hostname "
        "verification must be NOT_AVAILABLE: the observed SNI is evidence, not an "
        "authorised expectation, and the destination IP is never used either.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_u",
        d,
        [
            _tls12_expected(
                certificates=[_expected_leaf(leaf)],
                validation=_cert_validation(
                    dates="PASSED", chain="NOT_AVAILABLE",
                    hostname="NOT_AVAILABLE", identity=None,
                ),
            )
        ],
        byte_reproducible=False,
    )


# ---------------------------------------------------------------------------
# V-Z: entry points, malformed input and alerts
# ---------------------------------------------------------------------------
def _fixture_v() -> FixtureSpec:
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=150)
    d = _d(995)
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    d.send_server(record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der])))
    d.ack_client()
    return _spec(
        "T_V_implicit_tls_on_email_port",
        "t_v_implicit_tls_on_email_port.pcap",
        "Implicit TLS on the POP3S port: TLS from the first byte, with no plaintext "
        "phase. The entry point must be IMPLICIT and the email protocol inside must "
        "stay a port hint.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_v",
        d,
        [
            _tls12_expected(
                certificates=[_expected_leaf(leaf)],
                validation=_cert_validation(
                    dates="PASSED", chain="NOT_AVAILABLE",
                    hostname="NOT_AVAILABLE", identity=None,
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_w() -> FixtureSpec:
    """STARTTLS on port 25 followed by a full observable TLS 1.2 handshake."""
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=151)
    d = _d(25)
    d.send_server(SMTP_GREETING)
    d.send_client(SMTP_EHLO)
    d.send_server(SMTP_EHLO_TLS)
    d.send_client(SMTP_STARTTLS)
    d.send_server(SMTP_READY)
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    d.send_server(record(CONTENT_HANDSHAKE, _tls12_server_flight([leaf.der])))
    d.ack_client()
    return _spec(
        "T_W_starttls_then_tls",
        "t_w_starttls_then_tls.pcap",
        "An SMTP STARTTLS upgrade followed by an observable TLS 1.2 handshake. The TLS "
        "layer must start from the M2 transition boundaries rather than from the start "
        "of the stream.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_w",
        d,
        [
            _tls12_expected(
                entry_point="STARTTLS_UPGRADE",
                certificates=[_expected_leaf(leaf)],
                validation=_cert_validation(
                    dates="PASSED", chain="NOT_AVAILABLE",
                    hostname="NOT_AVAILABLE", identity=None,
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_x() -> FixtureSpec:
    """STARTTLS accepted, but the client's ClientHello was never captured."""
    d = _d(587)
    d.send_server(SMTP_GREETING)
    d.send_client(SMTP_EHLO)
    d.send_server(SMTP_EHLO_TLS)
    d.send_client(SMTP_STARTTLS)
    d.send_server(SMTP_READY + record(CONTENT_HANDSHAKE, server_hello(
        cipher_suite=_ECDHE_ECDSA)))
    d.ack_client()
    return _spec(
        "T_X_starttls_without_client_hello",
        "t_x_starttls_without_client_hello.pcap",
        "STARTTLS is accepted and the server's TLS bytes follow, but no ClientHello was "
        "captured. The server side must still be analysed, and the absence of the "
        "client's offers must be visible rather than filled in.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_x",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="STARTTLS_UPGRADE",
                handshake_state="SERVER_HELLO_WITHOUT_CLIENT_HELLO",
                client_record_parse_state="NOT_TLS",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="CAPABLE_NEGOTIATED",
                certificate_visibility="NOT_OBSERVED",
                message_types=["server_hello"],
                server_name_indication=None,
            )
        ],
        byte_reproducible=True,
    )


def _fixture_y() -> FixtureSpec:
    """A Certificate message whose inner lengths are nonsense."""
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    # A certificate_list claiming 0xFFFFF0 bytes inside a small message.
    broken = bytes([11]) + (9).to_bytes(3, "big") + bytes([0xFF, 0xFF, 0xF0]) + bytes(6)
    flight = server_hello(cipher_suite=_ECDHE_ECDSA) + broken
    d.send_server(record(CONTENT_HANDSHAKE, flight))
    d.ack_client()
    return _spec(
        "T_Y_malformed_certificate_lengths",
        "t_y_malformed_certificate_lengths.pcap",
        "The Certificate message declares a certificate_list far larger than the message "
        "containing it. Decoding must fail safely, report PARSE_FAILED, and never "
        "allocate on the declared length.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_y",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="NEGOTIATED",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="CAPABLE_NEGOTIATED",
                certificate_visibility="PARSE_FAILED",
                message_types=["client_hello", "server_hello", "certificate"],
                server_name_indication=SERVER_IDENTITY,
                expected_warning_codes=["CERTIFICATE_PARSE_FAILED"],
            )
        ],
        byte_reproducible=True,
    )


def _fixture_z() -> FixtureSpec:
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch()))
    # handshake_failure (40), fatal (2)
    d.send_server(alert(2, 40))
    d.ack_client()
    return _spec(
        "T_Z_alert_aborted_negotiation",
        "t_z_alert_aborted_negotiation.pcap",
        "The server answers the ClientHello with a fatal handshake_failure alert. The "
        "alert must be decoded and the handshake reported as aborted, not negotiated.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_z",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="ABORTED_BY_ALERT",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version=None,
                key_exchange_method="UNKNOWN",
                forward_secrecy_status="UNKNOWN_INCOMPLETE_EVIDENCE",
                certificate_visibility="NOT_OBSERVED",
                message_types=["client_hello"],
                alert_descriptions=["handshake_failure"],
                server_name_indication=SERVER_IDENTITY,
                expected_warning_codes=["TLS_ALERT_OBSERVED"],
            )
        ],
        byte_reproducible=True,
    )


def _fixture_hrr() -> FixtureSpec:
    """A HelloRetryRequest must not be read as a completed ServerHello."""
    d = _d()
    d.send_client(record(CONTENT_HANDSHAKE, _ch(supported_versions=[TLS13],
                                                key_share_groups=[_X25519],
                                                cipher_suites=[0x1301])))
    d.send_server(record(CONTENT_HANDSHAKE, hello_retry_request(group=_SECP256R1)))
    d.send_server(change_cipher_spec())
    d.ack_client()
    return _spec(
        "T_HRR_hello_retry_request",
        "t_hrr_hello_retry_request.pcap",
        "The server answers with a HelloRetryRequest, which shares a message type with "
        "ServerHello and is distinguished only by its special random value "
        "(RFC 8446 §4.1.3). It must not be reported as a negotiated session, and the "
        "TLS 1.3 compatibility ChangeCipherSpec must not be read as a TLS 1.2 handshake.",
        "securemailscope.testing.tls_fixtures_synthetic._fixture_hrr",
        d,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="HELLO_RETRY_REQUESTED",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version=None,
                key_exchange_method="UNKNOWN",
                forward_secrecy_status="UNKNOWN_INCOMPLETE_EVIDENCE",
                certificate_visibility="NOT_OBSERVED",
                hello_retry_request=True,
                message_types=["client_hello", "server_hello"],
                server_name_indication=SERVER_IDENTITY,
            )
        ],
        byte_reproducible=True,
    )


_BUILDERS = (
    _fixture_g,
    _fixture_h,
    _fixture_i,
    _fixture_j,
    _fixture_k,
    _fixture_l,
    _fixture_m,
    _fixture_n,
    _fixture_o,
    _fixture_p,
    _fixture_q,
    _fixture_r,
    _fixture_s,
    _fixture_t,
    _fixture_u,
    _fixture_v,
    _fixture_w,
    _fixture_x,
    _fixture_y,
    _fixture_z,
    _fixture_hrr,
)


def build_synthetic_tls_fixtures() -> list[FixtureSpec]:
    return [builder() for builder in _BUILDERS]
