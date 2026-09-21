"""Lightweight TLS record framing detection.

This is *framing* evidence, not TLS analysis.  It answers one question: do the
bytes at this offset look like a TLS record stream?  It does not decrypt, does
not reconstruct a handshake, and does not extract a version, cipher suite or
certificate.  That is M3.

The bar for saying "yes" is deliberately higher than a single plausible
header.  Plenty of binary payloads begin with a byte in 20-23 followed by
``0x03``.  Strong evidence requires either an identifiable handshake message
whose inner length agrees with the record length, or a chain of records whose
declared lengths line up end to end.
"""

from __future__ import annotations

from typing import Final

from ..models.evidence import EvidenceStatus
from ..models.protocol import (
    TLSContentType,
    TLSFramingEvidence,
    TLSRecordObservation,
)
from ..models.tcp import Direction
from .reader import DirectionalBuffer

__all__ = ["probe_tls_records", "RECORD_HEADER_SIZE", "MAX_RECORD_BYTES"]

RECORD_HEADER_SIZE: Final = 5
#: TLSCiphertext may exceed TLSPlaintext by the AEAD expansion allowance.
MAX_RECORD_BYTES: Final = 16384 + 2048

_CONTENT_TYPES: Final[dict[int, TLSContentType]] = {
    20: TLSContentType.CHANGE_CIPHER_SPEC,
    21: TLSContentType.ALERT,
    22: TLSContentType.HANDSHAKE,
    23: TLSContentType.APPLICATION_DATA,
}

_HANDSHAKE_TYPES: Final[dict[int, str]] = {
    0: "HELLO_REQUEST",
    1: "CLIENT_HELLO",
    2: "SERVER_HELLO",
    4: "NEW_SESSION_TICKET",
    8: "ENCRYPTED_EXTENSIONS",
    11: "CERTIFICATE",
    12: "SERVER_KEY_EXCHANGE",
    13: "CERTIFICATE_REQUEST",
    14: "SERVER_HELLO_DONE",
    15: "CERTIFICATE_VERIFY",
    16: "CLIENT_KEY_EXCHANGE",
    20: "FINISHED",
}

_STRONG: Final = frozenset(
    {
        TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO,
        TLSFramingEvidence.HANDSHAKE_SERVER_HELLO,
        TLSFramingEvidence.RECORD_CHAIN,
    }
)

_LIMITATIONS: Final[tuple[str, ...]] = (
    "TLS record framing only: no handshake was reconstructed and no "
    "cryptographic parameter was extracted.",
    "Valid record framing does not prove a handshake completed or that "
    "the connection was successfully encrypted.",
)


def _classify_header(window: bytes) -> tuple[int, TLSContentType, str, int] | None:
    """Validate a 5-byte record header. Returns ``(type, name, version, length)``."""
    if len(window) < RECORD_HEADER_SIZE:
        return None
    content_type = window[0]
    name = _CONTENT_TYPES.get(content_type)
    if name is None:
        return None
    if window[1] != 0x03 or window[2] > 0x04:
        return None
    length = (window[3] << 8) | window[4]
    if length == 0 or length > MAX_RECORD_BYTES:
        return None
    version = f"0x{window[1]:02x}{window[2]:02x}"
    return content_type, name, version, length


def _handshake_detail(body: bytes, declared_length: int) -> tuple[int, str] | None:
    """Identify a handshake message and cross-check its inner length."""
    if len(body) < 4:
        return None
    handshake_type = body[0]
    name = _HANDSHAKE_TYPES.get(handshake_type)
    if name is None:
        return None
    inner_length = (body[1] << 16) | (body[2] << 8) | body[3]
    # The handshake message must fit inside the record it claims to be in.
    if inner_length > declared_length - 4:
        return None
    return handshake_type, name


def probe_tls_records(
    buffer: DirectionalBuffer,
    start_offset: int,
    *,
    direction: Direction,
    max_records: int,
) -> tuple[TLSRecordObservation, ...]:
    """Walk a record chain from ``start_offset``, bounded by ``max_records``.

    Reading never crosses a run boundary, so a record split by a TCP gap is
    reported truncated rather than silently stitched together.
    """
    observations: list[TLSRecordObservation] = []
    offset = start_offset
    for index in range(max_records):
        window = buffer.read(offset, RECORD_HEADER_SIZE)
        header = _classify_header(window)
        if header is None:
            break
        content_type, name, version, declared_length = header

        body = buffer.read(offset + RECORD_HEADER_SIZE, declared_length)
        complete = len(body) >= declared_length
        handshake_type: int | None = None
        handshake_name: str | None = None
        if name is TLSContentType.HANDSHAKE:
            detail = _handshake_detail(body, declared_length)
            if detail is not None:
                handshake_type, handshake_name = detail

        if handshake_name == "CLIENT_HELLO":
            evidence = TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO
        elif handshake_name == "SERVER_HELLO":
            evidence = TLSFramingEvidence.HANDSHAKE_SERVER_HELLO
        elif handshake_name is not None:
            evidence = TLSFramingEvidence.HANDSHAKE_RECORD
        elif index > 0:
            evidence = TLSFramingEvidence.RECORD_CHAIN
        elif not complete:
            evidence = TLSFramingEvidence.TRUNCATED_RECORD
        else:
            evidence = TLSFramingEvidence.SINGLE_RECORD_HEADER

        end_offset = offset + RECORD_HEADER_SIZE + min(len(body), declared_length)
        limitations = list(_LIMITATIONS)
        if not complete:
            limitations.append(
                f"Only {len(body)} of the {declared_length} declared record bytes are "
                "present in this capture."
            )
        if evidence is TLSFramingEvidence.SINGLE_RECORD_HEADER:
            limitations.append(
                "A single well-formed record header is weak evidence; arbitrary binary "
                "payload can match it by chance."
            )

        observations.append(
            TLSRecordObservation(
                direction=direction,
                stream_offset=offset,
                end_offset=end_offset,
                content_type=content_type,
                content_type_name=name,
                legacy_record_version=version,
                declared_length=declared_length,
                bytes_available=len(body),
                complete=complete,
                handshake_type=handshake_type,
                handshake_type_name=handshake_name,
                evidence=evidence,
                status=EvidenceStatus.OBSERVED
                if evidence in _STRONG
                else EvidenceStatus.INFERRED,
                packet_refs=buffer.refs(offset, max(end_offset, offset + 1)),
                limitations=tuple(limitations),
            )
        )
        if not complete:
            break
        offset = end_offset

    # A lone header stays weak; two chained records upgrade the first.
    if len(observations) >= 2 and observations[0].evidence is (
        TLSFramingEvidence.SINGLE_RECORD_HEADER
    ):
        first = observations[0]
        observations[0] = first.model_copy(
            update={
                "evidence": TLSFramingEvidence.RECORD_CHAIN,
                "status": EvidenceStatus.OBSERVED,
                "limitations": _LIMITATIONS,
            }
        )
    return tuple(observations)
