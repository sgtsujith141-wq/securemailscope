"""Unit tests for TLS wire parsing, the code-point registry and X.509 decoding."""

from __future__ import annotations

import pytest

from securemailscope.certificates.parse import parse_certificate
from securemailscope.models.tcp import Direction
from securemailscope.testing.tls_messages import (
    TLS12,
    TLS13,
    certificate_message,
    client_hello,
    hello_retry_request,
    server_hello,
    server_key_exchange_ecdhe,
)
from securemailscope.tls.extensions import ExtensionContext, parse_extensions
from securemailscope.tls.handshake import (
    HELLO_RETRY_REQUEST_RANDOM,
    parse_alert,
    parse_certificate_message,
    parse_client_hello,
    parse_server_hello,
    parse_server_key_exchange,
)
from securemailscope.tls.registry import (
    KeyExchangeFamily,
    is_grease,
    lookup_cipher_suite,
    lookup_named_group,
    lookup_signature_scheme,
    lookup_version,
)
from securemailscope.tls.wire import ByteReader, TLSParseError


# -- bounded reader ----------------------------------------------------------
def test_reader_refuses_to_read_past_the_end() -> None:
    reader = ByteReader(b"\x01\x02")
    assert reader.u16() == 0x0102
    with pytest.raises(TLSParseError):
        reader.u8()


def test_reader_rejects_an_oversized_vector() -> None:
    # A two-byte vector claiming 0xFFFF bytes inside a four-byte buffer.
    reader = ByteReader(b"\xff\xff\x00\x00")
    with pytest.raises(TLSParseError):
        reader.vector16()


def test_reader_rejects_odd_code_point_lists() -> None:
    reader = ByteReader(b"")
    with pytest.raises(TLSParseError):
        reader.u16_list(b"\x00\x01\x02")


# -- registry ----------------------------------------------------------------
def test_known_cipher_suites_decompose_correctly() -> None:
    ecdhe = lookup_cipher_suite(0xC02B)
    assert ecdhe is not None
    assert ecdhe.name == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    assert ecdhe.key_exchange is KeyExchangeFamily.ECDHE
    assert ecdhe.aead is True

    static_rsa = lookup_cipher_suite(0x002F)
    assert static_rsa is not None
    assert static_rsa.key_exchange is KeyExchangeFamily.RSA


def test_tls13_suites_do_not_encode_key_exchange() -> None:
    suite = lookup_cipher_suite(0x1301)
    assert suite is not None
    assert suite.tls13_only is True
    assert suite.key_exchange is KeyExchangeFamily.NOT_ENCODED_IN_SUITE
    assert suite.authentication.value == "NOT_ENCODED_IN_SUITE"


def test_unknown_code_points_return_none_rather_than_a_guess() -> None:
    assert lookup_cipher_suite(0x1337) is None
    assert lookup_named_group(0x7777) is None
    assert lookup_signature_scheme(0x7777) is None
    assert lookup_version(0x0399) is None


def test_grease_values_are_recognised() -> None:
    assert is_grease(0x0A0A) is True
    assert is_grease(0xFAFA) is True
    assert is_grease(0xC02B) is False


def test_edwards_groups_have_no_invented_security_level() -> None:
    hybrid = lookup_named_group(0x11EC)
    assert hybrid is not None
    assert hybrid.family == "HYBRID"
    assert hybrid.security_bits is None


def test_a_group_family_maps_to_the_key_exchange_method_without_guessing() -> None:
    """The classification the TLS 1.3 key-exchange method is derived from.

    This used to be covered only by accident: the developer machine's OpenSSL
    offered the post-quantum hybrid X25519MLKEM768, so a generated fixture
    happened to exercise the unclassifiable case -- while a CI runner
    negotiating a classical curve did not, and the committed expectation
    failed there. The generator now pins the group, so this mapping is checked
    here instead, where it does not depend on anyone's OpenSSL build.
    """
    families = {
        0x001D: ("x25519", "ECDHE"),  # classical elliptic curve
        0x0017: ("secp256r1", "ECDHE"),
        0x0100: ("ffdhe2048", "FFDHE"),  # finite-field
        0x11EC: ("X25519MLKEM768", "HYBRID"),  # post-quantum hybrid
    }
    for value, (name, family) in families.items():
        info = lookup_named_group(value)
        assert info is not None, f"{name} (0x{value:04x}) is not in the registry"
        assert info.family == family, (name, info.family)

    # A hybrid is neither ECDHE nor FFDHE. The method must fall back to the
    # generic EPHEMERAL rather than being forced into a classical family,
    # because calling a post-quantum exchange "ECDHE" would be a claim the
    # wire does not support.
    def method_for(value: int) -> str:
        info = lookup_named_group(value)
        family = info.family if info else None
        return "ECDHE" if family == "ECDHE" else "DHE" if family == "FFDHE" else "EPHEMERAL"

    assert method_for(0x001D) == "ECDHE"
    assert method_for(0x0100) == "DHE"
    assert method_for(0x11EC) == "EPHEMERAL"
    assert method_for(0xFFFF) == "EPHEMERAL"  # unknown group, not invented


# -- extensions --------------------------------------------------------------
def test_supported_versions_is_a_list_from_the_client() -> None:
    body = bytes([0, 43, 0, 5, 4, 3, 4, 3, 3])
    parsed = parse_extensions(body, ExtensionContext.CLIENT_HELLO)
    assert parsed.offered_versions == (0x0304, 0x0303)
    assert parsed.selected_version is None


def test_supported_versions_is_one_value_from_the_server() -> None:
    body = bytes([0, 43, 0, 2, 3, 4])
    parsed = parse_extensions(body, ExtensionContext.SERVER_HELLO)
    assert parsed.selected_version == 0x0304
    assert parsed.offered_versions == ()


def test_hello_retry_request_key_share_carries_only_a_group() -> None:
    body = bytes([0, 51, 0, 2, 0, 0x17])
    parsed = parse_extensions(body, ExtensionContext.HELLO_RETRY_REQUEST)
    assert parsed.hello_retry_selected_group == 0x0017
    assert parsed.server_key_share_group is None


def test_malformed_extension_is_recorded_not_raised() -> None:
    body = bytes([0, 43, 0, 99, 1, 2])  # declares 99 bytes, supplies 2
    parsed = parse_extensions(body, ExtensionContext.SERVER_HELLO)
    assert parsed.malformed
    assert parsed.selected_version is None


def test_sni_is_shape_filtered() -> None:
    good = client_hello(server_name="mail.example.invalid")
    assert parse_client_hello(good[4:]).extensions.server_name == "mail.example.invalid"
    # A name containing a space cannot be a DNS name and is dropped.
    raw = bytes([0, 0]) + (26).to_bytes(2, "big") + (24).to_bytes(2, "big")
    raw += bytes([0]) + (21).to_bytes(2, "big") + b"not a hostname at all"
    assert parse_extensions(raw, ExtensionContext.CLIENT_HELLO).server_name is None


# -- handshake messages ------------------------------------------------------
def test_client_hello_round_trips() -> None:
    message = client_hello(
        cipher_suites=[0x1301, 0xC02F],
        supported_versions=[TLS13, TLS12],
        supported_groups=[0x001D],
        key_share_groups=[0x001D],
        alpn=["imap", "http/1.1"],
    )
    info = parse_client_hello(message[4:])
    assert info.cipher_suites == (0x1301, 0xC02F)
    assert info.extensions.offered_versions == (TLS13, TLS12)
    assert info.extensions.client_key_share_groups == (0x001D,)
    assert info.extensions.alpn == ("imap", "http/1.1")


def test_server_hello_round_trips() -> None:
    message = server_hello(
        cipher_suite=0x1301, supported_version=TLS13, key_share_group=0x001D
    )
    info = parse_server_hello(message[4:])
    assert info.legacy_version == TLS12, "TLS 1.3 leaves legacy_version at 0x0303"
    assert info.extensions.selected_version == TLS13
    assert info.extensions.server_key_share_group == 0x001D
    assert info.is_hello_retry_request is False


def test_hello_retry_request_is_distinguished_by_its_random() -> None:
    info = parse_server_hello(hello_retry_request()[4:])
    assert info.is_hello_retry_request is True
    assert len(HELLO_RETRY_REQUEST_RANDOM) == 32


def test_server_key_exchange_named_curve() -> None:
    info = parse_server_key_exchange(server_key_exchange_ecdhe()[4:], "ECDHE")
    assert info.parsed is True
    assert info.named_curve == 0x0017
    assert info.public_key_length == 65


def test_server_key_exchange_is_not_guessed_for_unknown_key_exchange() -> None:
    info = parse_server_key_exchange(server_key_exchange_ecdhe()[4:], "UNKNOWN")
    assert info.parsed is False
    assert "not interpreted" in info.note


def test_certificate_message_parses_both_framings() -> None:
    der = bytes(range(40))
    tls12, notes = parse_certificate_message(
        certificate_message([der])[4:],
        tls13=False,
        max_certificates=8,
        max_certificate_bytes=1024,
    )
    assert tls12 == [der]
    assert notes == []
    tls13, _ = parse_certificate_message(
        certificate_message([der], tls13=True)[4:],
        tls13=True,
        max_certificates=8,
        max_certificate_bytes=1024,
    )
    assert tls13 == [der]


def test_certificate_message_respects_the_size_limit() -> None:
    certificates, notes = parse_certificate_message(
        certificate_message([bytes(200)])[4:],
        tls13=False,
        max_certificates=8,
        max_certificate_bytes=16,
    )
    assert certificates == []
    assert any("exceeds" in note for note in notes)


def test_alert_decoding() -> None:
    assert parse_alert(bytes([2, 40])) == (2, "fatal", 40, "handshake_failure")
    assert parse_alert(bytes([1, 0])) == (1, "warning", 0, "close_notify")
    assert parse_alert(b"") == (None, None, None, None)


# -- certificate decoding ----------------------------------------------------
def test_malformed_der_fails_safely() -> None:
    observation, certificate, error = parse_certificate(
        b"\x30\x82\xff\xff not a certificate",
        chain_position=0,
        direction=Direction.SERVER_TO_CLIENT,
        stream_offset=0,
        packet_refs=(),
    )
    assert observation is None
    assert certificate is None
    assert error


@pytest.mark.parametrize(
    ("key_kind", "algorithm", "has_size"),
    [("ec256", "EC", True), ("rsa2048", "RSA", True), ("ed25519", "Ed25519", False)],
)
def test_public_key_sizes_are_reported_only_where_meaningful(
    key_kind: str, algorithm: str, has_size: bool
) -> None:
    from securemailscope.testing.certs import SyntheticCA

    authority = SyntheticCA()
    leaf = authority.issue(
        "key.example.invalid", key_kind=key_kind, serial=900, sans=["key.example.invalid"]
    )
    observation, _, error = parse_certificate(
        leaf.der,
        chain_position=0,
        direction=Direction.SERVER_TO_CLIENT,
        stream_offset=0,
        packet_refs=(),
    )
    assert error is None
    assert observation is not None
    assert observation.public_key.algorithm == algorithm
    if has_size:
        assert observation.public_key.size_bits is not None
    else:
        # Edwards keys have fixed parameters; a bit length would be invented.
        assert observation.public_key.size_bits is None
        assert any("fixed parameters" in note for note in observation.public_key.notes)
