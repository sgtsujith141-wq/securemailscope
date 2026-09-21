"""Handshake message reassembly and parsing (RFC 5246 §7.4, RFC 8446 §4).

A handshake message and a TLS record are independent framings:

* one message may span several records (a large Certificate message always
  does), and
* one record may carry several messages (ServerHello, Certificate,
  ServerKeyExchange and ServerHelloDone commonly arrive together).

:class:`HandshakeStream` therefore concatenates record *bodies* per direction
and parses messages out of the concatenation, while keeping a map from every
buffer position back to the stream offset, record index and packets that
carried it.  Provenance survives the reassembly.

Only records that are known to be plaintext are ever appended.  Once a
direction crosses its encryption boundary -- ChangeCipherSpec in TLS 1.2, the
ServerHello in TLS 1.3 -- no further bytes enter the buffer, so an encrypted
body can never be parsed as a plaintext message.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.evidence import EvidenceStatus, PacketReference, Severity, WarningCode
from ..models.tcp import Direction
from ..models.tls import TLSMessageObservation
from .extensions import ExtensionContext, ParsedExtensions, parse_extensions
from .records import RecordFragment
from .wire import ByteReader, TLSParseError

__all__ = [
    "HANDSHAKE_TYPE_NAMES",
    "HELLO_RETRY_REQUEST_RANDOM",
    "HandshakeStream",
    "HandshakeMessage",
    "ClientHelloInfo",
    "ServerHelloInfo",
    "ServerKeyExchangeInfo",
    "parse_client_hello",
    "parse_server_hello",
    "parse_certificate_message",
    "parse_server_key_exchange",
    "parse_alert",
]

#: RFC 5246 §7.4 and RFC 8446 §4, merged. The version a message belongs to is
#: tracked separately: several code points exist in only one of the two.
HANDSHAKE_TYPE_NAMES: Final[dict[int, str]] = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    4: "new_session_ticket",
    5: "end_of_early_data",
    8: "encrypted_extensions",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
    24: "key_update",
    254: "message_hash",
}

#: Messages that exist only in TLS 1.2 and earlier.
TLS12_ONLY_TYPES: Final[frozenset[int]] = frozenset({0, 12, 14, 16})
#: Messages that exist only in TLS 1.3.
TLS13_ONLY_TYPES: Final[frozenset[int]] = frozenset({5, 8, 24, 254})

#: RFC 8446 §4.1.3: a ServerHello carrying this random IS a HelloRetryRequest.
HELLO_RETRY_REQUEST_RANDOM: Final = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

#: RFC 5246 §7.2.
_ALERT_LEVELS: Final[dict[int, str]] = {1: "warning", 2: "fatal"}
_ALERT_DESCRIPTIONS: Final[dict[int, str]] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}


@dataclass(frozen=True, slots=True)
class _Fragment:
    buffer_start: int
    stream_offset: int
    length: int
    record_index: int
    packet_refs: tuple[PacketReference, ...]


@dataclass(slots=True)
class HandshakeStream:
    """Concatenated plaintext handshake bytes for one direction."""

    direction: Direction
    buffer: bytearray = field(default_factory=bytearray)
    fragments: list[_Fragment] = field(default_factory=list)
    overflowed: bool = False

    def append(self, fragment: RecordFragment, limit: int) -> bool:
        """Add a handshake record body. Returns False when the limit is hit."""
        if len(self.buffer) + len(fragment.body) > limit:
            self.overflowed = True
            return False
        self.fragments.append(
            _Fragment(
                buffer_start=len(self.buffer),
                stream_offset=fragment.body_offset,
                length=len(fragment.body),
                record_index=fragment.index,
                packet_refs=fragment.observation.packet_refs,
            )
        )
        self.buffer.extend(fragment.body)
        return True

    def locate(
        self, start: int, length: int
    ) -> tuple[int, int, tuple[int, ...], tuple[PacketReference, ...]]:
        """Map a buffer range back to stream offsets, records and packets."""
        end = start + max(length, 1)
        stream_start: int | None = None
        stream_end = 0
        records: list[int] = []
        seen: dict[int, PacketReference] = {}
        for fragment in self.fragments:
            fragment_end = fragment.buffer_start + fragment.length
            if fragment_end <= start or fragment.buffer_start >= end:
                continue
            offset_in = max(0, start - fragment.buffer_start)
            if stream_start is None:
                stream_start = fragment.stream_offset + offset_in
            covered_end = min(end, fragment_end) - fragment.buffer_start
            stream_end = fragment.stream_offset + covered_end
            records.append(fragment.record_index)
            for ref in fragment.packet_refs:
                seen.setdefault(ref.packet_number, ref)
        if stream_start is None:
            stream_start = self.fragments[-1].stream_offset if self.fragments else 0
            stream_end = stream_start
        return (
            stream_start,
            stream_end,
            tuple(records),
            tuple(seen[number] for number in sorted(seen)),
        )


@dataclass(frozen=True, slots=True)
class HandshakeMessage:
    """One parsed handshake message. ``body`` never reaches a model."""

    observation: TLSMessageObservation
    body: bytes


def parse_messages(
    stream: HandshakeStream,
    *,
    config: AnalysisConfig,
    sink: WarningSink,
    session_id: str,
    warn_incomplete: bool = True,
) -> list[HandshakeMessage]:
    """Split a direction's handshake buffer into messages.

    A message whose declared length exceeds the bytes available is reported
    ``complete=False`` and parsing of that direction stops -- the remainder of
    the buffer cannot be aligned without it.

    ``warn_incomplete=False`` suppresses the diagnostic, because the buffer is
    re-parsed as each record arrives and a message that is incomplete now may
    be complete once the next record lands. Only the final pass warns.
    """
    messages: list[HandshakeMessage] = []
    data = bytes(stream.buffer)
    position = 0

    while position + 4 <= len(data):
        if len(messages) >= config.max_tls_handshake_messages:
            sink.add(
                WarningCode.LIMIT_TLS_HANDSHAKE_MESSAGES,
                f"Reached the {config.max_tls_handshake_messages}-message limit while "
                f"parsing the {stream.direction.value} handshake; later messages are not "
                "parsed.",
                severity=Severity.ERROR,
                session_id=session_id,
                limit=config.max_tls_handshake_messages,
            )
            break

        message_type = data[position]
        declared = (data[position + 1] << 16) | (data[position + 2] << 8) | data[position + 3]
        body_start = position + 4
        available = len(data) - body_start
        complete = available >= declared
        body = data[body_start : body_start + min(declared, available)]

        stream_start, stream_end, records, refs = stream.locate(
            position, 4 + min(declared, available)
        )
        name = HANDSHAKE_TYPE_NAMES.get(message_type, f"unknown_{message_type}")
        limitations: list[str] = []
        if not complete:
            limitations.append(
                f"The message declares {declared} bytes but only {available} are present "
                "in this capture, so it is not fully observed."
            )
        if message_type not in HANDSHAKE_TYPE_NAMES:
            limitations.append(
                "This handshake type is not in the registry this build knows; only its "
                "numeric type and length are reported."
            )

        observation = TLSMessageObservation(
            message_type=message_type,
            message_type_name=name,
            direction=stream.direction,
            stream_offset=stream_start,
            end_offset=stream_end,
            declared_length=declared,
            available_length=len(body),
            complete=complete,
            record_indices=records,
            spans_records=len(records) > 1,
            packet_refs=refs,
            first_timestamp=refs[0].timestamp if refs else None,
            status=EvidenceStatus.OBSERVED if complete else EvidenceStatus.INFERRED,
            detail=(
                f"Handshake message {name} ({message_type}) of {declared} byte(s)"
                + (", spanning multiple TLS records" if len(records) > 1 else "")
                + "."
            ),
            limitations=tuple(limitations),
        )
        messages.append(HandshakeMessage(observation=observation, body=body))

        if not complete:
            if not warn_incomplete:
                break
            sink.add(
                WarningCode.TLS_HANDSHAKE_MESSAGE_INCOMPLETE,
                f"The {stream.direction.value} handshake message {name} at stream offset "
                f"{stream_start} declares {declared} bytes but only {available} were "
                "captured; parsing of this direction stops here.",
                session_id=session_id,
                packet_refs=refs,
                stream_offset=stream_start,
                declared_length=declared,
            )
            break
        position = body_start + declared

    return messages


# ---------------------------------------------------------------------------
# Message bodies
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ClientHelloInfo:
    legacy_version: int
    #: Kept internally so TLS 1.2 resumption can be detected by comparing it
    #: with the server's echo. It never reaches a model.
    session_id: bytes
    session_id_length: int
    cipher_suites: tuple[int, ...]
    compression_methods: tuple[int, ...]
    extensions: ParsedExtensions


@dataclass(frozen=True, slots=True)
class ServerHelloInfo:
    legacy_version: int
    session_id: bytes
    session_id_length: int
    cipher_suite: int
    compression_method: int
    is_hello_retry_request: bool
    extensions: ParsedExtensions


@dataclass(frozen=True, slots=True)
class ServerKeyExchangeInfo:
    """Observable parameters of a TLS 1.2 ServerKeyExchange."""

    curve_type: int | None = None
    named_curve: int | None = None
    public_key_length: int | None = None
    dh_prime_length_bits: int | None = None
    dh_generator_length: int | None = None
    parsed: bool = False
    note: str = ""


def parse_client_hello(body: bytes) -> ClientHelloInfo:
    """RFC 8446 §4.1.2. The 32-byte random is read past and never retained."""
    reader = ByteReader(body)
    legacy_version = reader.u16()
    reader.take(32)  # random: discarded, it is not security-relevant evidence
    session_id = reader.vector8()
    cipher_suites = reader.u16_list(reader.vector16())
    compression = tuple(reader.vector8())
    extensions = ParsedExtensions()
    if reader.remaining >= 2:
        extensions = parse_extensions(reader.vector16(), ExtensionContext.CLIENT_HELLO)
    return ClientHelloInfo(
        legacy_version=legacy_version,
        session_id=session_id,
        session_id_length=len(session_id),
        cipher_suites=cipher_suites,
        compression_methods=compression,
        extensions=extensions,
    )


def parse_server_hello(body: bytes) -> ServerHelloInfo:
    """RFC 8446 §4.1.3/§4.1.4.

    A ServerHello whose random equals the HelloRetryRequest constant *is* a
    HelloRetryRequest; the two share a message type, and treating an HRR as a
    completed ServerHello would report a negotiation that never happened.
    """
    reader = ByteReader(body)
    legacy_version = reader.u16()
    random = reader.take(32)
    is_hrr = random == HELLO_RETRY_REQUEST_RANDOM
    session_id = reader.vector8()
    cipher_suite = reader.u16()
    compression = reader.u8()
    context = (
        ExtensionContext.HELLO_RETRY_REQUEST if is_hrr else ExtensionContext.SERVER_HELLO
    )
    extensions = ParsedExtensions()
    if reader.remaining >= 2:
        extensions = parse_extensions(reader.vector16(), context)
    return ServerHelloInfo(
        legacy_version=legacy_version,
        session_id=session_id,
        session_id_length=len(session_id),
        cipher_suite=cipher_suite,
        compression_method=compression,
        is_hello_retry_request=is_hrr,
        extensions=extensions,
    )


def parse_certificate_message(
    body: bytes, *, tls13: bool, max_certificates: int, max_certificate_bytes: int
) -> tuple[list[bytes], list[str]]:
    """Return DER certificates and any structural notes.

    TLS 1.2 (RFC 5246 §7.4.2) and TLS 1.3 (RFC 8446 §4.4.2) use different
    framings: 1.3 prefixes a certificate_request_context and suffixes
    per-certificate extensions. Both are supported, selected by the negotiated
    version rather than guessed from the bytes.
    """
    notes: list[str] = []
    certificates: list[bytes] = []
    reader = ByteReader(body)
    if tls13:
        reader.vector8()  # certificate_request_context
    entries = ByteReader(reader.vector24())
    while entries.remaining >= 3:
        if len(certificates) >= max_certificates:
            notes.append(
                f"Certificate list truncated at the configured limit of {max_certificates}."
            )
            break
        der = entries.vector24()
        if len(der) > max_certificate_bytes:
            notes.append(
                f"A certificate of {len(der)} bytes exceeds the "
                f"{max_certificate_bytes}-byte limit and was not decoded."
            )
            break
        certificates.append(der)
        if tls13 and entries.remaining >= 2:
            entries.vector16()  # per-certificate extensions
    return certificates, notes


def parse_server_key_exchange(body: bytes, key_exchange: str) -> ServerKeyExchangeInfo:
    """RFC 4492 §5.4 (ECDHE) and RFC 5246 §7.4.3 (DHE).

    The structure is only interpretable when the negotiated key exchange is
    known, because the message has no self-describing header. When it is not
    known, nothing is guessed.
    """
    try:
        reader = ByteReader(body)
        if key_exchange == "ECDHE":
            curve_type = reader.u8()
            if curve_type != 3:  # named_curve
                return ServerKeyExchangeInfo(
                    curve_type=curve_type,
                    parsed=False,
                    note="Only the named_curve form of ServerKeyExchange is interpreted.",
                )
            named_curve = reader.u16()
            public = reader.vector8()
            return ServerKeyExchangeInfo(
                curve_type=curve_type,
                named_curve=named_curve,
                public_key_length=len(public),
                parsed=True,
            )
        if key_exchange == "DHE":
            prime = reader.vector16()
            generator = reader.vector16()
            public = reader.vector16()
            return ServerKeyExchangeInfo(
                dh_prime_length_bits=len(prime) * 8,
                dh_generator_length=len(generator),
                public_key_length=len(public),
                parsed=True,
            )
    except TLSParseError as error:
        return ServerKeyExchangeInfo(parsed=False, note=f"Structure truncated: {error}")
    return ServerKeyExchangeInfo(
        parsed=False,
        note=f"ServerKeyExchange is not interpreted for key exchange {key_exchange}.",
    )


def parse_alert(body: bytes) -> tuple[int | None, str | None, int | None, str | None]:
    """RFC 5246 §7.2. Returns ``(level, level_name, description, name)``."""
    if len(body) < 2:
        return None, None, None, None
    level, description = body[0], body[1]
    return (
        level,
        _ALERT_LEVELS.get(level),
        description,
        _ALERT_DESCRIPTIONS.get(description),
    )
