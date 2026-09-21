"""TLS record layer reconstruction over reconstructed TCP payload (RFC 8446 §5.1).

The record layer sits directly on the M1 reassembly output, so it inherits
that layer's gap and ambiguity handling rather than re-implementing it.  One
rule dominates the design:

**After a hole, record alignment is unknowable.**  A TLS record stream is
self-delimiting only if you have read every preceding byte.  If bytes are
missing, the first byte of the next run may be the middle of a record body,
and framing from there would produce confident nonsense.  Parsing therefore
stops at the gap and says so (``ALIGNMENT_LOST_AT_GAP``) instead of
resynchronising on a guess.

Records that merely *span TCP segments* are not affected: segments inside one
reassembled run are contiguous, so a record split across several packets is
read normally, and the packets that carried it are all recorded.

Record bodies are kept in memory for the handshake layer and are never placed
on a model, so serialising a report cannot emit them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.evidence import EvidenceStatus, Severity, WarningCode
from ..models.protocol import TLSContentType, TLSFramingEvidence, TLSRecordObservation
from ..models.tcp import Direction
from ..models.tls import RecordParseState
from ..protocols.framing import (
    RECORD_HEADER_SIZE,
    classify_record_header,
    identify_handshake,
)
from ..protocols.reader import DirectionalBuffer

__all__ = ["RecordFragment", "DirectionRecords", "parse_records"]

_STRONG = frozenset(
    {
        TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO,
        TLSFramingEvidence.HANDSHAKE_SERVER_HELLO,
        TLSFramingEvidence.RECORD_CHAIN,
        TLSFramingEvidence.HANDSHAKE_RECORD,
    }
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    "Record framing only: no record is decrypted and no key material is used.",
)


@dataclass(frozen=True, slots=True)
class RecordFragment:
    """A framed record plus its body, which stays out of every model."""

    index: int
    observation: TLSRecordObservation
    body: bytes
    body_offset: int

    @property
    def content_type(self) -> TLSContentType:
        return self.observation.content_type_name

    @property
    def complete(self) -> bool:
        return self.observation.complete


@dataclass(slots=True)
class DirectionRecords:
    """Every record framed in one direction, and why framing stopped."""

    direction: Direction
    fragments: list[RecordFragment] = field(default_factory=list)
    parse_state: RecordParseState = RecordParseState.NOT_TLS
    start_offset: int = 0
    stopped_at_offset: int = 0
    total_body_bytes: int = 0

    @property
    def observations(self) -> list[TLSRecordObservation]:
        return [fragment.observation for fragment in self.fragments]


def parse_records(
    buffer: DirectionalBuffer,
    start_offset: int,
    *,
    direction: Direction,
    config: AnalysisConfig,
    sink: WarningSink,
    session_id: str,
    index_base: int = 0,
) -> DirectionRecords:
    """Frame TLS records from ``start_offset`` until something stops us."""
    result = DirectionRecords(
        direction=direction, start_offset=start_offset, stopped_at_offset=start_offset
    )
    offset = start_offset
    index = index_base

    while True:
        if len(result.fragments) >= config.max_tls_records_per_direction:
            result.parse_state = RecordParseState.LIMIT_REACHED
            sink.add(
                WarningCode.LIMIT_TLS_RECORDS,
                f"Reached the {config.max_tls_records_per_direction}-record limit while "
                f"framing the {direction.value} TLS stream; later records are not parsed.",
                severity=Severity.ERROR,
                session_id=session_id,
                limit=config.max_tls_records_per_direction,
            )
            break

        header = buffer.read(offset, RECORD_HEADER_SIZE)
        if not header:
            result.parse_state = (
                RecordParseState.ALIGNMENT_LOST_AT_GAP
                if _has_later_run(buffer, offset)
                else (
                    RecordParseState.COMPLETE
                    if result.fragments
                    else RecordParseState.NOT_TLS
                )
            )
            if result.parse_state is RecordParseState.ALIGNMENT_LOST_AT_GAP:
                _warn_alignment(sink, session_id, direction, offset)
            break

        if len(header) < RECORD_HEADER_SIZE:
            # A partial header: either the capture ends here or a hole does.
            if _has_later_run(buffer, offset):
                result.parse_state = RecordParseState.ALIGNMENT_LOST_AT_GAP
                _warn_alignment(sink, session_id, direction, offset)
            else:
                result.parse_state = RecordParseState.TRUNCATED_RECORD
                sink.add(
                    WarningCode.TLS_RECORD_TRUNCATED,
                    f"The {direction.value} TLS stream ends with {len(header)} bytes of a "
                    f"{RECORD_HEADER_SIZE}-byte record header at stream offset {offset}.",
                    session_id=session_id,
                    packet_refs=buffer.refs(offset, offset + max(len(header), 1)),
                    stream_offset=offset,
                )
            break

        classified = classify_record_header(header)
        if classified is None:
            result.parse_state = RecordParseState.MALFORMED_RECORD
            sink.add(
                WarningCode.TLS_RECORD_MALFORMED,
                f"A {direction.value} TLS record header at stream offset {offset} is not "
                "structurally valid (content type, version or length out of range); "
                "record framing stops here rather than guessing.",
                severity=Severity.ERROR,
                session_id=session_id,
                packet_refs=buffer.refs(offset, offset + RECORD_HEADER_SIZE),
                stream_offset=offset,
            )
            break

        content_type, type_name, version, declared_length = classified
        if declared_length > config.max_tls_record_bytes:
            result.parse_state = RecordParseState.LIMIT_REACHED
            sink.add(
                WarningCode.LIMIT_TLS_RECORD_BYTES,
                f"A {direction.value} TLS record at stream offset {offset} declares "
                f"{declared_length} bytes, above the {config.max_tls_record_bytes}-byte "
                "ceiling; framing stops here.",
                severity=Severity.ERROR,
                session_id=session_id,
                stream_offset=offset,
                declared_length=declared_length,
            )
            break

        body = buffer.read(offset + RECORD_HEADER_SIZE, declared_length)
        complete = len(body) >= declared_length
        end_offset = offset + RECORD_HEADER_SIZE + min(len(body), declared_length)
        ambiguous = buffer.is_ambiguous(offset, max(end_offset, offset + 1))

        handshake_type: int | None = None
        handshake_name: str | None = None
        if type_name is TLSContentType.HANDSHAKE:
            detail = identify_handshake(body, declared_length)
            if detail is not None:
                handshake_type, handshake_name = detail

        evidence = _grade(handshake_name, index - index_base, complete)
        limitations = list(_BASE_LIMITATIONS)
        if not complete:
            limitations.append(
                f"Only {len(body)} of the {declared_length} declared record bytes are "
                "present in this capture."
            )
        if ambiguous:
            limitations.append(
                "These bytes overlap a TCP range where segments disagreed, so the record "
                "is not unambiguous evidence."
            )

        observation = TLSRecordObservation(
            direction=direction,
            stream_offset=offset,
            end_offset=end_offset,
            content_type=content_type,
            content_type_name=type_name,
            legacy_record_version=version,
            declared_length=declared_length,
            bytes_available=len(body),
            complete=complete,
            handshake_type=handshake_type,
            handshake_type_name=handshake_name,
            evidence=evidence,
            status=EvidenceStatus.OBSERVED if evidence in _STRONG else EvidenceStatus.INFERRED,
            packet_refs=buffer.refs(offset, max(end_offset, offset + 1)),
            limitations=tuple(limitations),
            record_index=index,
            ambiguous=ambiguous,
        )
        result.fragments.append(
            RecordFragment(
                index=index,
                observation=observation,
                body=body[:declared_length],
                body_offset=offset + RECORD_HEADER_SIZE,
            )
        )
        result.total_body_bytes += len(body)
        index += 1

        if ambiguous:
            result.parse_state = RecordParseState.AMBIGUOUS_BYTES
            sink.add(
                WarningCode.TLS_RECORD_AMBIGUOUS,
                f"A {direction.value} TLS record at stream offset {offset} lies in a range "
                "where overlapping TCP segments disagreed; record parsing stops rather "
                "than treating the bytes as unambiguous evidence.",
                severity=Severity.ERROR,
                session_id=session_id,
                packet_refs=observation.packet_refs,
                stream_offset=offset,
            )
            break

        if not complete:
            if _has_later_run(buffer, offset):
                result.parse_state = RecordParseState.ALIGNMENT_LOST_AT_GAP
                _warn_alignment(sink, session_id, direction, offset)
            else:
                result.parse_state = RecordParseState.TRUNCATED_RECORD
                sink.add(
                    WarningCode.TLS_RECORD_TRUNCATED,
                    f"A {direction.value} TLS record at stream offset {offset} declares "
                    f"{declared_length} bytes but only {len(body)} are present; the record "
                    "is reported truncated and framing stops.",
                    session_id=session_id,
                    packet_refs=observation.packet_refs,
                    stream_offset=offset,
                    declared_length=declared_length,
                )
            break

        offset = end_offset
        result.stopped_at_offset = offset
    else:  # pragma: no cover - the loop only exits via break
        pass

    result.stopped_at_offset = max(result.stopped_at_offset, offset)
    if result.fragments and result.parse_state is RecordParseState.NOT_TLS:
        result.parse_state = RecordParseState.COMPLETE
    return result


def _has_later_run(buffer: DirectionalBuffer, offset: int) -> bool:
    """True when reconstructed data continues after a hole at ``offset``."""
    return any(start > offset for start, _ in buffer.runs)


def _warn_alignment(
    sink: WarningSink, session_id: str, direction: Direction, offset: int
) -> None:
    sink.add(
        WarningCode.TLS_RECORD_ALIGNMENT_LOST,
        f"Missing data interrupts the {direction.value} TLS stream at offset {offset}. "
        "TLS records are only self-delimiting when every preceding byte was read, so "
        "record framing stops here instead of resynchronising on a guess.",
        severity=Severity.ERROR,
        session_id=session_id,
        stream_offset=offset,
    )


def _grade(handshake_name: str | None, position: int, complete: bool) -> TLSFramingEvidence:
    if handshake_name == "CLIENT_HELLO":
        return TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO
    if handshake_name == "SERVER_HELLO":
        return TLSFramingEvidence.HANDSHAKE_SERVER_HELLO
    if handshake_name is not None:
        return TLSFramingEvidence.HANDSHAKE_RECORD
    if position > 0:
        return TLSFramingEvidence.RECORD_CHAIN
    if not complete:
        return TLSFramingEvidence.TRUNCATED_RECORD
    return TLSFramingEvidence.SINGLE_RECORD_HEADER
