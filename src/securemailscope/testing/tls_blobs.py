"""Synthetic TLS record bytes for fixtures.

These are *structurally* valid TLS records built byte by byte: a real record
header, a real handshake header, and a length-consistent body.  They are not
captured from any TLS implementation and carry no cryptographic meaning --
they exist so the record-framing detector has something genuine to validate
and so a fixture can place TLS-looking bytes at an exact stream offset.

The 32-byte "random" field deliberately avoids ``0x0a`` so that a fixture's
binary region cannot accidentally split into lines, which would make the
line-reader tests depend on the contents of a random blob.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "client_hello",
    "server_hello",
    "application_data",
    "truncated_client_hello",
    "not_tls_binary",
]

#: 32 bytes in the printable range, containing no CR or LF.
_RANDOM: Final = bytes(range(0x41, 0x61))
assert len(_RANDOM) == 32
assert b"\n" not in _RANDOM and b"\r" not in _RANDOM


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def _record(content_type: int, version: bytes, payload: bytes) -> bytes:
    return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload


def client_hello() -> bytes:
    """A minimal but length-consistent ClientHello record."""
    body = (
        b"\x03\x03"  # legacy_version TLS 1.2
        + _RANDOM
        + b"\x00"  # empty legacy_session_id
        + b"\x00\x02\x13\x01"  # one cipher suite: TLS_AES_128_GCM_SHA256
        + b"\x01\x00"  # null compression
        + b"\x00\x00"  # no extensions
    )
    return _record(22, b"\x03\x01", _handshake(1, body))


def server_hello() -> bytes:
    """A minimal but length-consistent ServerHello record."""
    body = (
        b"\x03\x03"
        + _RANDOM
        + b"\x00"  # empty legacy_session_id_echo
        + b"\x13\x01"  # selected cipher suite
        + b"\x00"  # null compression
        + b"\x00\x00"  # no extensions
    )
    return _record(22, b"\x03\x03", _handshake(2, body))


def application_data(length: int = 48) -> bytes:
    """An application_data record whose payload is opaque filler."""
    filler = bytes((0x41 + (index % 26)) for index in range(length))
    return _record(23, b"\x03\x03", filler)


def truncated_client_hello(present: int = 40) -> bytes:
    """A ClientHello record header whose body is cut short by the capture."""
    full = client_hello()
    if present >= len(full):
        raise ValueError("present must be shorter than the complete record")
    return full[:present]


def not_tls_binary() -> bytes:
    """Binary payload that must NOT be mistaken for TLS.

    The first byte is outside the content-type range, so a correct detector
    rejects it immediately.
    """
    return bytes([0x99, 0x03, 0x03, 0x00, 0x20]) + bytes(range(0x41, 0x61))
