"""M3 TLS and certificate fixtures (A-Z).

Two generation methods, kept clearly distinct because they buy different
things and have different reproducibility:

**Locally negotiated** -- real OpenSSL handshakes produced in memory through
``ssl.MemoryBIO`` (see :mod:`securemailscope.testing.live_tls`). These test the
parser against what a real implementation actually emits. TLS randoms and
ephemeral key shares make them non-reproducible, so their manifests set
``byte_reproducible=False`` and assert negotiated parameters instead of a
capture hash.

**Synthetically constructed** -- messages assembled byte by byte from the RFC
structures (see :mod:`securemailscope.testing.tls_messages`). These give exact
control over fragmentation, truncation and malformed input, which OpenSSL
cannot be asked to produce, and they are byte-reproducible.

No fixture uses a real server, a real certificate or real traffic. The
analyzer never opens a socket; only the *generator* performs a handshake, and
it does so entirely in memory with no network involved.
"""

from __future__ import annotations

import ssl
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from ..models.tcp import Direction
from .certs import CAPTURE_EPOCH, IssuedCertificate, SyntheticCA
from .dialogue import Dialogue
from .fixtures import FixtureSpec
from .live_tls import (
    HandshakeCapture,
    negotiate,
    negotiate_resumed,
    tls12_ciphers_available,
)
from .manifest import ExpectedCertificate, ExpectedTLS, ExpectedValidation
from .tls_messages import (
    CONTENT_HANDSHAKE,
    TLS12,
    certificate_message,
    client_hello,
    record,
    server_hello,
    server_hello_done,
)
from .writers import write_pcap

__all__ = ["build_tls_fixtures", "SERVER_IDENTITY", "TRUST_STORE_NAME"]

SERVER_IDENTITY: Final = "mail.example.invalid"
WRONG_IDENTITY: Final = "webmail.other.invalid"
TRUST_STORE_NAME: Final = "synthetic-root.pem"

#: 2026-06-01T12:00:00Z, matching the certificate authority's epoch so
#: "expired at capture time" is a stable fact.
CAPTURE_TIMESTAMP_NS: Final = int(CAPTURE_EPOCH.timestamp()) * 1_000_000_000

SMTP_GREETING: Final = b"220 mail.example ESMTP ready\r\n"
SMTP_EHLO: Final = b"EHLO client.example\r\n"
SMTP_EHLO_TLS: Final = (
    b"250-mail.example Hello\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 HELP\r\n"
)
SMTP_STARTTLS: Final = b"STARTTLS\r\n"
SMTP_READY: Final = b"220 2.0.0 Ready to start TLS\r\n"

_CA: SyntheticCA | None = None


def _ca() -> SyntheticCA:
    """One authority per build, so a fixture set is internally consistent."""
    global _CA
    if _CA is None:
        _CA = SyntheticCA()
    return _CA


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _dialogue(server_port: int = 993, *, handshake: bool = True) -> Dialogue:
    return Dialogue(
        server_port=server_port,
        handshake=handshake,
        start_ns=CAPTURE_TIMESTAMP_NS,
    )


def _write(dialogue: Dialogue) -> bytes:
    return write_pcap(dialogue.packets)


def _emit(dialogue: Dialogue, flights: Sequence[tuple[Direction, bytes]]) -> None:
    """Write handshake flights into the conversation in the order produced."""
    for direction, data in flights:
        if direction is Direction.CLIENT_TO_SERVER:
            dialogue.send_client(data)
        else:
            dialogue.send_server(data)


def _spec(
    name: str,
    filename: str,
    description: str,
    generation: str,
    dialogue: Dialogue,
    tls: list[ExpectedTLS],
    *,
    byte_reproducible: bool,
    protocols: list | None = None,
) -> FixtureSpec:
    packets = dialogue.packets
    return FixtureSpec(
        name=name,
        filename=filename,
        description=description,
        generation=generation,
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(packets),
        timestamps_ns=[timestamp for timestamp, _ in packets],
        expected_packet_count=len(packets),
        expected_tcp_packet_count=len(packets),
        expected_sessions=[],
        expected_warning_codes=[],
        expected_protocols=protocols,
        expected_tls=tls,
        byte_reproducible=byte_reproducible,
    )


def _live(
    *,
    version: ssl.TLSVersion,
    ciphers: str | None = None,
    leaf: IssuedCertificate | None = None,
    via_intermediate: bool = False,
    session: ssl.SSLSession | None = None,
    hostname: str = SERVER_IDENTITY,
) -> tuple[HandshakeCapture, ssl.SSLSession | None]:
    """Run one real handshake in memory against a synthetic certificate."""
    authority = _ca()
    certificate = leaf or authority.issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY, "*.alt.example.invalid"]
    )
    with tempfile.TemporaryDirectory() as directory:
        chain, key = authority.write_chain(
            certificate, Path(directory), via_intermediate=via_intermediate
        )
        return negotiate(
            chain,
            key,
            version=version,
            ciphers=ciphers,
            server_hostname=hostname,
            session=session,
        )


def _expected_leaf(
    certificate: IssuedCertificate, *, position: int = 0, self_signed: bool = False
) -> ExpectedCertificate:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    parsed = certificate.certificate
    key = parsed.public_key()
    algorithm_name: str
    size: int | None
    curve: str | None
    if isinstance(key, rsa.RSAPublicKey):
        algorithm_name, size, curve = "RSA", key.key_size, None
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm_name, size, curve = "EC", key.curve.key_size, key.curve.name
    elif isinstance(key, ed25519.Ed25519PublicKey):
        algorithm_name, size, curve = "Ed25519", None, None
    else:  # pragma: no cover - fixtures use the three above
        algorithm_name, size, curve = "UNKNOWN", None, None
    sans = [
        f"DNS:{entry.value}"
        for entry in parsed.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    ]
    return ExpectedCertificate(
        chain_position=position,
        subject=parsed.subject.rfc4514_string(),
        issuer=parsed.issuer.rfc4514_string(),
        public_key_algorithm=algorithm_name,
        public_key_size_bits=size,
        public_key_curve=curve,
        signature_algorithm=parsed.signature_algorithm_oid._name,
        subject_alternative_names=sans,
        is_self_issued=self_signed,
        basic_constraints_ca=False,
        extended_key_usage=["serverAuth"],
    )


# ---------------------------------------------------------------------------
# A-F: locally negotiated handshakes
# ---------------------------------------------------------------------------
def _fixture_a() -> FixtureSpec:
    capture, _ = _live(
        version=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-ECDSA-AES128-GCM-SHA256"
    )
    dialogue = _dialogue(993)
    _emit(dialogue, capture.flights)
    leaf = _ca().issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY])
    _ = leaf
    return _spec(
        "T_A_tls12_complete_handshake",
        "t_a_tls12_complete_handshake.pcap",
        "A complete TLS 1.2 handshake negotiated locally by OpenSSL, carried on port 993. "
        "Every plaintext handshake message through ServerHelloDone must be reconstructed "
        "and the server's certificate extracted.",
        "securemailscope.testing.tls_fixtures._fixture_a (live OpenSSL, in-memory BIO)",
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="SERVER_FLIGHT_COMPLETE",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_version_source="LEGACY_VERSION",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                cipher_decomposition_applicable=True,
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="EPHEMERAL_OBSERVED",
                certificate_visibility="OBSERVED",
                certificate_count=1,
                message_types=[
                    "client_hello",
                    "server_hello",
                    "certificate",
                    "server_key_exchange",
                    "server_hello_done",
                    "client_key_exchange",
                    # RFC 5077: the TLS 1.2 NewSessionTicket precedes the
                    # server's ChangeCipherSpec, so it is still plaintext.
                    "new_session_ticket",
                ],
                server_name_indication=SERVER_IDENTITY,
                encryption_boundary_reasons={
                    "CLIENT_TO_SERVER": "TLS12_CHANGE_CIPHER_SPEC",
                    "SERVER_TO_CLIENT": "TLS12_CHANGE_CIPHER_SPEC",
                },
                resumption_likely=False,
                validation=ExpectedValidation(
                    certificate_observed="PASSED",
                    validity_dates_checked="PASSED",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_b() -> FixtureSpec:
    capture, _ = _live(
        version=ssl.TLSVersion.TLSv1_2, ciphers="ECDHE-ECDSA-AES256-GCM-SHA384"
    )
    dialogue = _dialogue(465)
    _emit(dialogue, capture.flights)
    return _spec(
        "T_B_tls12_ecdhe",
        "t_b_tls12_ecdhe.pcap",
        "A TLS 1.2 ECDHE negotiation on the SMTPS port. The ephemeral group must come "
        "from the observed ServerKeyExchange, not from the client's offered groups.",
        "securemailscope.testing.tls_fixtures._fixture_b (live OpenSSL)",
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="SERVER_FLIGHT_COMPLETE",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                server_name_indication=SERVER_IDENTITY,
                cipher_key_exchange="ECDHE",
                key_exchange_method="ECDHE",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="EPHEMERAL_OBSERVED",
                certificate_visibility="OBSERVED",
                certificate_count=1,
                validation=ExpectedValidation(
                    certificate_observed="PASSED",
                    validity_dates_checked="PASSED",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_c() -> FixtureSpec:
    """TLS 1.2 static RSA key exchange -- no forward secrecy."""
    authority = _ca()
    leaf = authority.issue(
        SERVER_IDENTITY, sans=[SERVER_IDENTITY], key_kind="rsa2048", serial=110
    )
    available = tls12_ciphers_available("@SECLEVEL=0:kRSA")
    if available:
        capture, _ = _live(
            version=ssl.TLSVersion.TLSv1_2, ciphers="@SECLEVEL=0:AES128-SHA", leaf=leaf
        )
        generation = "securemailscope.testing.tls_fixtures._fixture_c (live OpenSSL, kRSA)"
        flights = capture.flights
    else:  # pragma: no cover - depends on the local OpenSSL build
        # The local library no longer offers static RSA; construct a
        # standards-conformant handshake instead, as the directive allows.
        server_flight = (
            server_hello(cipher_suite=0x009C, legacy_version=TLS12)
            + certificate_message([leaf.der])
            + server_hello_done()
        )
        flights = (
            (Direction.CLIENT_TO_SERVER, record(CONTENT_HANDSHAKE, client_hello(
                cipher_suites=[0x009C], server_name=SERVER_IDENTITY))),
            (Direction.SERVER_TO_CLIENT, record(CONTENT_HANDSHAKE, server_flight)),
        )
        generation = (
            "securemailscope.testing.tls_fixtures._fixture_c (synthetic: the local "
            "OpenSSL no longer offers static RSA key exchange)"
        )
    dialogue = _dialogue(993)
    _emit(dialogue, flights)
    return _spec(
        "T_C_tls12_static_rsa",
        "t_c_tls12_static_rsa.pcap",
        "A TLS 1.2 handshake using static RSA key exchange. The premaster secret is "
        "encrypted to the server's long-term key, so the session has no forward secrecy "
        "and must be classified STATIC_RSA_KEY_EXCHANGE.",
        generation,
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="SERVER_FLIGHT_COMPLETE",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.2",
                selected_cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                server_name_indication=SERVER_IDENTITY,
                # Static RSA sends no ServerKeyExchange: there is no ephemeral
                # parameter to sign.
                message_types=[
                    "client_hello",
                    "server_hello",
                    "certificate",
                    "server_hello_done",
                    "client_key_exchange",
                    "new_session_ticket",
                ],
                cipher_key_exchange="RSA",
                key_exchange_method="RSA",
                key_exchange_source="CIPHER_SUITE",
                forward_secrecy_status="STATIC_RSA_KEY_EXCHANGE",
                certificate_visibility="OBSERVED",
                certificate_count=1,
                certificates=[_expected_leaf(leaf)],
                validation=ExpectedValidation(
                    certificate_observed="PASSED",
                    validity_dates_checked="PASSED",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_d() -> FixtureSpec:
    capture, _ = _live(version=ssl.TLSVersion.TLSv1_3)
    dialogue = _dialogue(993)
    _emit(dialogue, capture.flights)
    # OpenSSL reports TLS 1.3 suites under their IANA names, so this is the
    # peer's own statement of what it chose -- an independent cross-check on
    # our parse of the ServerHello bytes, not a copy of our own output.
    suite = capture.negotiated_cipher
    return _spec(
        "T_D_tls13_negotiation",
        "t_d_tls13_negotiation.pcap",
        "A TLS 1.3 handshake negotiated locally. The version must be read from the "
        "ServerHello supported_versions extension, never from legacy_version (which "
        "reads 0x0303), and key exchange must come from key_share rather than the "
        "cipher suite name.",
        "securemailscope.testing.tls_fixtures._fixture_d (live OpenSSL)",
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="NEGOTIATED_THEN_ENCRYPTED",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.3",
                selected_version_source="SUPPORTED_VERSIONS_EXTENSION",
                selected_cipher_suite=suite,
                server_name_indication=SERVER_IDENTITY,
                cipher_decomposition_applicable=False,
                cipher_key_exchange=None,
                # The local OpenSSL offers X25519MLKEM768 first, a
                # post-quantum hybrid. It is neither ECDHE nor FFDHE, so the
                # method is reported as the generic EPHEMERAL rather than
                # being forced into one of the classical families.
                key_exchange_method="EPHEMERAL",
                key_exchange_source="KEY_SHARE_EXTENSION",
                forward_secrecy_status="EPHEMERAL_OBSERVED",
                certificate_visibility="ENCRYPTED_TLS13",
                certificate_count=0,
                message_types=["client_hello", "server_hello"],
                encryption_boundary_reasons={
                    "CLIENT_TO_SERVER": "TLS13_AFTER_SERVER_HELLO",
                    "SERVER_TO_CLIENT": "TLS13_AFTER_SERVER_HELLO",
                },
                validation=ExpectedValidation(
                    certificate_observed="FAILED",
                    validity_dates_checked="NOT_AVAILABLE",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
                expected_warning_codes=["TLS_HANDSHAKE_ENCRYPTED"],
            )
        ],
        byte_reproducible=False,
    )


def _fixture_e() -> FixtureSpec:
    """Same handshake as D, asserted specifically on the encrypted certificate."""
    capture, _ = _live(version=ssl.TLSVersion.TLSv1_3)
    dialogue = _dialogue(465)
    _emit(dialogue, capture.flights)
    suite = capture.negotiated_cipher
    return _spec(
        "T_E_tls13_encrypted_certificate",
        "t_e_tls13_encrypted_certificate.pcap",
        "A TLS 1.3 session whose Certificate message is encrypted under handshake "
        "traffic keys. Certificate visibility must be ENCRYPTED_TLS13 with an "
        "explanation, and this must NOT be reported as a certificate failure.",
        "securemailscope.testing.tls_fixtures._fixture_e (live OpenSSL)",
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="NEGOTIATED_THEN_ENCRYPTED",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.3",
                selected_version_source="SUPPORTED_VERSIONS_EXTENSION",
                selected_cipher_suite=suite,
                server_name_indication=SERVER_IDENTITY,
                cipher_decomposition_applicable=False,
                key_exchange_method="EPHEMERAL",
                key_exchange_source="KEY_SHARE_EXTENSION",
                forward_secrecy_status="EPHEMERAL_OBSERVED",
                certificate_visibility="ENCRYPTED_TLS13",
                certificate_count=0,
                validation=ExpectedValidation(
                    certificate_observed="FAILED",
                    validity_dates_checked="NOT_AVAILABLE",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=False,
    )


def _fixture_f() -> FixtureSpec:
    """TLS 1.3 resumption: a second handshake reusing the first one's ticket."""
    authority = _ca()
    leaf = authority.issue(SERVER_IDENTITY, sans=[SERVER_IDENTITY], serial=120)
    with tempfile.TemporaryDirectory() as directory:
        chain, key = authority.write_chain(leaf, Path(directory))
        capture = negotiate_resumed(chain, key, version=ssl.TLSVersion.TLSv1_3)
    dialogue = _dialogue(993)
    _emit(dialogue, capture.flights)
    suite = capture.negotiated_cipher
    return _spec(
        "T_F_tls13_resumption",
        "t_f_tls13_resumption.pcap",
        "A TLS 1.3 handshake resuming an earlier session with a pre-shared key. A "
        "resumed session carries no new certificate, which must be reported as a "
        "resumption signal rather than as a missing certificate.",
        "securemailscope.testing.tls_fixtures._fixture_f (live OpenSSL, two handshakes)",
        dialogue,
        [
            ExpectedTLS(
                session_index=0,
                entry_point="IMPLICIT",
                handshake_state="NEGOTIATED_THEN_ENCRYPTED",
                client_record_parse_state="COMPLETE",
                server_record_parse_state="COMPLETE",
                selected_version="TLS 1.3",
                selected_version_source="SUPPORTED_VERSIONS_EXTENSION",
                selected_cipher_suite=suite,
                server_name_indication=SERVER_IDENTITY,
                cipher_decomposition_applicable=False,
                key_exchange_method="PSK_EPHEMERAL",
                key_exchange_source="PSK_EXTENSIONS",
                forward_secrecy_status="EPHEMERAL_OBSERVED",
                certificate_visibility="ENCRYPTED_TLS13",
                resumption_likely=True,
                validation=ExpectedValidation(
                    certificate_observed="FAILED",
                    validity_dates_checked="NOT_AVAILABLE",
                    chain_verified="NOT_AVAILABLE",
                    hostname_verified="NOT_AVAILABLE",
                    revocation_checked="NOT_AVAILABLE",
                ),
            )
        ],
        byte_reproducible=False,
    )


_BUILDERS_LIVE = (
    _fixture_a,
    _fixture_b,
    _fixture_c,
    _fixture_d,
    _fixture_e,
    _fixture_f,
)


def build_tls_fixtures() -> list[FixtureSpec]:
    """Build every M3 fixture."""
    from .tls_fixtures_synthetic import build_synthetic_tls_fixtures

    return [builder() for builder in _BUILDERS_LIVE] + build_synthetic_tls_fixtures()
