"""Hand-constructed, standards-conformant TLS messages for fixtures.

Live OpenSSL handshakes give realism but not control: you cannot ask OpenSSL
to split a handshake message across records in a particular way, to truncate a
record, or to emit a cipher suite it no longer supports.  These builders give
exact control over the wire bytes, so the fragmentation, truncation and
malformed-input fixtures test precisely what they claim to.

Everything here is built from the RFC structures byte by byte:
RFC 8446 §4.1 (hellos), §4.2 (extensions), §4.4.2 (certificate),
RFC 5246 §7.4 (TLS 1.2 handshake) and §6.2.1 (record layer).

Captures built only from these builders are byte-reproducible.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "record",
    "records_for",
    "client_hello",
    "server_hello",
    "hello_retry_request",
    "certificate_message",
    "server_key_exchange_ecdhe",
    "server_hello_done",
    "change_cipher_spec",
    "alert",
    "handshake",
    "TLS12",
    "TLS13",
    "TLS10",
]

TLS10: Final = 0x0301
TLS12: Final = 0x0303
TLS13: Final = 0x0304

CONTENT_HANDSHAKE: Final = 22
CONTENT_ALERT: Final = 21
CONTENT_CHANGE_CIPHER_SPEC: Final = 20
CONTENT_APPLICATION_DATA: Final = 23

#: RFC 8446 §4.1.3 -- the random that makes a ServerHello a HelloRetryRequest.
HRR_RANDOM: Final = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

#: Deterministic filler used wherever a message needs a "random". It contains
#: no CR or LF so a binary region can never split into lines by accident.
_FILLER: Final = bytes(range(0x41, 0x61))


def _u8(value: int) -> bytes:
    return bytes([value])


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _vec8(data: bytes) -> bytes:
    return _u8(len(data)) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _vec24(data: bytes) -> bytes:
    return _u24(len(data)) + data


def _extension(number: int, body: bytes) -> bytes:
    return _u16(number) + _vec16(body)


def record(content_type: int, payload: bytes, version: int = TLS12) -> bytes:
    """One TLS record (RFC 8446 §5.1)."""
    return _u8(content_type) + _u16(version) + _vec16(payload)


def records_for(
    content_type: int, payload: bytes, *, chunk: int, version: int = TLS12
) -> bytes:
    """Split ``payload`` across several records of at most ``chunk`` bytes.

    This is how a handshake message that spans multiple TLS records is built.
    """
    if chunk <= 0:
        raise ValueError("chunk must be positive")
    out = bytearray()
    for start in range(0, len(payload), chunk):
        out += record(content_type, payload[start : start + chunk], version)
    return bytes(out)


def handshake(message_type: int, body: bytes) -> bytes:
    """A handshake message header plus body (RFC 5246 §7.4)."""
    return _u8(message_type) + _vec24(body)


def client_hello(
    *,
    legacy_version: int = TLS12,
    cipher_suites: list[int] | None = None,
    session_id: bytes = b"",
    server_name: str | None = None,
    supported_versions: list[int] | None = None,
    supported_groups: list[int] | None = None,
    key_share_groups: list[int] | None = None,
    signature_algorithms: list[int] | None = None,
    alpn: list[str] | None = None,
    psk_identities: int = 0,
    psk_modes: list[int] | None = None,
) -> bytes:
    """A ClientHello (RFC 8446 §4.1.2)."""
    suites = cipher_suites if cipher_suites is not None else [0xC02F, 0x1301]
    extensions = bytearray()
    if server_name is not None:
        host = server_name.encode("ascii")
        extensions += _extension(0, _vec16(_u8(0) + _vec16(host)))
    if supported_groups:
        extensions += _extension(
            10, _vec16(b"".join(_u16(group) for group in supported_groups))
        )
    if signature_algorithms:
        extensions += _extension(
            13, _vec16(b"".join(_u16(scheme) for scheme in signature_algorithms))
        )
    if alpn:
        names = b"".join(_vec8(name.encode("ascii")) for name in alpn)
        extensions += _extension(16, _vec16(names))
    if psk_modes:
        extensions += _extension(45, _vec8(bytes(psk_modes)))
    if supported_versions:
        extensions += _extension(
            43, _vec8(b"".join(_u16(version) for version in supported_versions))
        )
    if key_share_groups:
        shares = b"".join(
            _u16(group) + _vec16(_FILLER) for group in key_share_groups
        )
        extensions += _extension(51, _vec16(shares))
    if psk_identities:
        identities = b"".join(
            _vec16(b"ticket-%d" % index) + (0).to_bytes(4, "big")
            for index in range(psk_identities)
        )
        binders = b"".join(_vec8(bytes(32)) for _ in range(psk_identities))
        # pre_shared_key must be the last extension (RFC 8446 §4.2.11).
        extensions += _extension(41, _vec16(identities) + _vec16(binders))

    body = (
        _u16(legacy_version)
        + _FILLER
        + _vec8(session_id)
        + _vec16(b"".join(_u16(suite) for suite in suites))
        + _vec8(bytes([0]))
        + _vec16(bytes(extensions))
    )
    return handshake(1, body)


def server_hello(
    *,
    legacy_version: int = TLS12,
    cipher_suite: int = 0xC02F,
    session_id: bytes = b"",
    supported_version: int | None = None,
    key_share_group: int | None = None,
    key_share_length: int = 32,
    selected_psk_identity: int | None = None,
    alpn: str | None = None,
    random_bytes: bytes | None = None,
) -> bytes:
    """A ServerHello (RFC 8446 §4.1.3).

    ``supported_version`` populates the extension a TLS 1.3 server uses to
    signal the real version while leaving ``legacy_version`` at 0x0303.
    """
    extensions = bytearray()
    if supported_version is not None:
        extensions += _extension(43, _u16(supported_version))
    if key_share_group is not None:
        extensions += _extension(
            51, _u16(key_share_group) + _vec16(bytes(key_share_length))
        )
    if selected_psk_identity is not None:
        extensions += _extension(41, _u16(selected_psk_identity))
    if alpn is not None:
        extensions += _extension(16, _vec16(_vec8(alpn.encode("ascii"))))

    body = (
        _u16(legacy_version)
        + (random_bytes if random_bytes is not None else _FILLER)
        + _vec8(session_id)
        + _u16(cipher_suite)
        + _u8(0)
        + _vec16(bytes(extensions))
    )
    return handshake(2, body)


def hello_retry_request(*, cipher_suite: int = 0x1301, group: int = 0x0017) -> bytes:
    """A HelloRetryRequest: a ServerHello carrying the special random."""
    extensions = _extension(43, _u16(TLS13)) + _extension(51, _u16(group))
    body = (
        _u16(TLS12)
        + HRR_RANDOM
        + _vec8(b"")
        + _u16(cipher_suite)
        + _u8(0)
        + _vec16(extensions)
    )
    return handshake(2, body)


def certificate_message(certificates: list[bytes], *, tls13: bool = False) -> bytes:
    """A Certificate message (RFC 5246 §7.4.2 / RFC 8446 §4.4.2)."""
    if tls13:
        entries = b"".join(_vec24(der) + _vec16(b"") for der in certificates)
        body = _vec8(b"") + _vec24(entries)
    else:
        body = _vec24(b"".join(_vec24(der) for der in certificates))
    return handshake(11, body)


def server_key_exchange_ecdhe(
    *, named_curve: int = 0x0017, public_key_length: int = 65
) -> bytes:
    """A named-curve ECDHE ServerKeyExchange (RFC 4492 §5.4)."""
    public = bytes([0x04]) + bytes(public_key_length - 1)
    body = (
        _u8(3)  # curve_type = named_curve
        + _u16(named_curve)
        + _vec8(public)
        + _u16(0x0403)  # signature scheme: ecdsa_secp256r1_sha256
        + _vec16(bytes(70))  # opaque signature
    )
    return handshake(12, body)


def server_hello_done() -> bytes:
    return handshake(14, b"")


def change_cipher_spec(version: int = TLS12) -> bytes:
    """A ChangeCipherSpec record (RFC 5246 §7.1).

    In TLS 1.3 this appears only for middlebox compatibility and carries no
    protocol meaning (RFC 8446 §D.4).
    """
    return record(CONTENT_CHANGE_CIPHER_SPEC, b"\x01", version)


def alert(level: int, description: int, version: int = TLS12) -> bytes:
    """An alert record (RFC 5246 §7.2). level 1 = warning, 2 = fatal."""
    return record(CONTENT_ALERT, bytes([level, description]), version)
