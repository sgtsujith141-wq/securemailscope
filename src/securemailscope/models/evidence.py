"""Provenance-aware evidence primitives.

Every fact SecureMailScope reports carries the evidence that supports it.  The
types in this module are the vocabulary used for that: an :class:`Observation`
wraps a value together with *how* it was established, *which packets* support
it and *what the reader must not conclude from it*.

See ``docs/evidence-model.md`` for the normative description.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "EvidenceStatus",
    "Severity",
    "WarningCode",
    "PacketReference",
    "Observation",
    "AnalysisWarning",
    "ns_to_datetime",
]


class EvidenceStatus(StrEnum):
    """How a reported value was established.

    The four statuses are mutually exclusive and are never used
    interchangeably.  In particular an ``INFERRED`` value must never be
    presented to a user as if it were ``OBSERVED``.
    """

    #: Directly read out of captured bytes.  Reproducible from the capture.
    OBSERVED = "OBSERVED"
    #: Derived by documented reasoning from observed data.  Could be wrong if
    #: the capture is incomplete or the traffic was crafted adversarially.
    INFERRED = "INFERRED"
    #: The property is applicable but this capture does not determine it.
    UNKNOWN = "UNKNOWN"
    #: The property cannot be determined from passive capture at all, or the
    #: analysis stage that would determine it is not implemented yet.
    NOT_AVAILABLE = "NOT_AVAILABLE"


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class WarningCode(StrEnum):
    """Stable machine-readable diagnostic codes.

    Codes are part of the output contract: downstream tooling and tests match
    on them, so they are never renamed without a version bump.
    """

    # --- container / file level ---------------------------------------------
    UNSUPPORTED_FILE_FORMAT = "UNSUPPORTED_FILE_FORMAT"
    TRUNCATED_CAPTURE_FILE = "TRUNCATED_CAPTURE_FILE"
    MALFORMED_BLOCK = "MALFORMED_BLOCK"
    UNSUPPORTED_LINK_TYPE = "UNSUPPORTED_LINK_TYPE"
    UNSUPPORTED_BLOCK_TYPE = "UNSUPPORTED_BLOCK_TYPE"
    MISSING_INTERFACE_DESCRIPTION = "MISSING_INTERFACE_DESCRIPTION"

    # --- packet level --------------------------------------------------------
    MALFORMED_PACKET = "MALFORMED_PACKET"
    TRUNCATED_PACKET_DATA = "TRUNCATED_PACKET_DATA"
    NON_IP_PACKET = "NON_IP_PACKET"
    NON_TCP_PACKET = "NON_TCP_PACKET"
    IP_FRAGMENT_NOT_REASSEMBLED = "IP_FRAGMENT_NOT_REASSEMBLED"

    # --- session / reassembly level -----------------------------------------
    MIDSTREAM_SESSION = "MIDSTREAM_SESSION"
    NO_TERMINATION_OBSERVED = "NO_TERMINATION_OBSERVED"
    TUPLE_REUSE = "TUPLE_REUSE"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    OVERLAP_CONFLICT = "OVERLAP_CONFLICT"
    ACKED_DATA_NOT_CAPTURED = "ACKED_DATA_NOT_CAPTURED"
    SEQUENCE_WRAPAROUND = "SEQUENCE_WRAPAROUND"

    # --- application protocol level (M2) -------------------------------------
    PROTOCOL_LINE_TOO_LONG = "PROTOCOL_LINE_TOO_LONG"
    PROTOCOL_GAP_IN_DIALOGUE = "PROTOCOL_GAP_IN_DIALOGUE"
    PROTOCOL_AMBIGUOUS_BYTES = "PROTOCOL_AMBIGUOUS_BYTES"
    PROTOCOL_DESYNCHRONISED = "PROTOCOL_DESYNCHRONISED"
    PROTOCOL_UNSOLICITED_REPLY = "PROTOCOL_UNSOLICITED_REPLY"
    PROTOCOL_MALFORMED_RECORD = "PROTOCOL_MALFORMED_RECORD"
    UPGRADE_REQUEST_WITHOUT_RESPONSE = "UPGRADE_REQUEST_WITHOUT_RESPONSE"
    UPGRADE_ACCEPTED_WITHOUT_TLS_BYTES = "UPGRADE_ACCEPTED_WITHOUT_TLS_BYTES"
    UPGRADE_TAG_MISMATCH = "UPGRADE_TAG_MISMATCH"
    PLAINTEXT_AUTHENTICATION_OBSERVED = "PLAINTEXT_AUTHENTICATION_OBSERVED"
    TLS_RECORD_TRUNCATED = "TLS_RECORD_TRUNCATED"
    TLS_FRAMING_WEAK_EVIDENCE = "TLS_FRAMING_WEAK_EVIDENCE"

    # --- resource limits -----------------------------------------------------
    LIMIT_CAPTURE_BYTES = "LIMIT_CAPTURE_BYTES"
    LIMIT_PACKET_COUNT = "LIMIT_PACKET_COUNT"
    LIMIT_PACKET_BYTES = "LIMIT_PACKET_BYTES"
    LIMIT_TOTAL_PAYLOAD_BYTES = "LIMIT_TOTAL_PAYLOAD_BYTES"
    LIMIT_SESSION_PAYLOAD_BYTES = "LIMIT_SESSION_PAYLOAD_BYTES"
    LIMIT_CONCURRENT_SESSIONS = "LIMIT_CONCURRENT_SESSIONS"
    LIMIT_TOTAL_SESSIONS = "LIMIT_TOTAL_SESSIONS"
    LIMIT_SEGMENTS_PER_DIRECTION = "LIMIT_SEGMENTS_PER_DIRECTION"
    LIMIT_LINE_BYTES = "LIMIT_LINE_BYTES"
    LIMIT_LITERAL_BYTES = "LIMIT_LITERAL_BYTES"
    LIMIT_MESSAGE_BODY_BYTES = "LIMIT_MESSAGE_BODY_BYTES"
    LIMIT_PROTOCOL_EVENTS = "LIMIT_PROTOCOL_EVENTS"
    WARNINGS_SUPPRESSED = "WARNINGS_SUPPRESSED"


def ns_to_datetime(timestamp_ns: int) -> datetime:
    """Convert epoch nanoseconds to a timezone-aware UTC ``datetime``.

    ``datetime`` only stores microseconds, so the nanosecond remainder is lost
    here on purpose.  Full precision is always retained alongside it in
    :attr:`PacketReference.timestamp_ns`.
    """
    return datetime.fromtimestamp(timestamp_ns / 1_000_000_000, tz=UTC)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PacketReference(_Model):
    """A pointer back into the capture that supports some statement.

    ``packet_number`` is 1-based and follows capture file order, so it matches
    the frame number shown by Wireshark for the same file.
    """

    packet_number: int = Field(ge=1, description="1-based index in capture file order.")
    timestamp: datetime = Field(description="Capture timestamp, timezone-aware UTC.")
    timestamp_ns: int = Field(
        ge=0, description="Capture timestamp in epoch nanoseconds (full precision)."
    )

    @classmethod
    def create(cls, packet_number: int, timestamp_ns: int) -> PacketReference:
        return cls(
            packet_number=packet_number,
            timestamp=ns_to_datetime(timestamp_ns),
            timestamp_ns=timestamp_ns,
        )


T = TypeVar("T")


class Observation(_Model, Generic[T]):
    """A value plus the evidence that supports it.

    ``value`` is ``None`` whenever ``status`` is ``UNKNOWN`` or
    ``NOT_AVAILABLE``; consumers must branch on ``status`` rather than on
    truthiness of ``value``.
    """

    value: T | None = None
    status: EvidenceStatus
    capture_id: str
    session_id: str | None = None
    packet_refs: tuple[PacketReference, ...] = ()
    observed_at: datetime | None = Field(
        default=None, description="Timestamp of the earliest supporting packet."
    )
    observed_until: datetime | None = Field(
        default=None, description="Timestamp of the latest supporting packet."
    )
    basis: str | None = Field(
        default=None,
        description="Short machine-readable reason, e.g. 'SERVER_PORT' or 'TCP_SYN'.",
    )
    limitations: tuple[str, ...] = Field(
        default=(),
        description="What this observation does NOT establish. Always populated "
        "for INFERRED values.",
    )

    @classmethod
    def unknown(
        cls, capture_id: str, *, session_id: str | None = None, limitations: tuple[str, ...] = ()
    ) -> Observation[Any]:
        return Observation(
            value=None,
            status=EvidenceStatus.UNKNOWN,
            capture_id=capture_id,
            session_id=session_id,
            limitations=limitations,
        )

    @classmethod
    def not_available(
        cls, capture_id: str, *, session_id: str | None = None, limitations: tuple[str, ...] = ()
    ) -> Observation[Any]:
        return Observation(
            value=None,
            status=EvidenceStatus.NOT_AVAILABLE,
            capture_id=capture_id,
            session_id=session_id,
            limitations=limitations,
        )


class AnalysisWarning(_Model):
    """A structured diagnostic.

    Warnings are first-class output, not log noise: a malformed packet or an
    exceeded limit changes how the rest of the report must be read, so it is
    recorded with the same provenance discipline as any other finding.
    """

    code: WarningCode
    severity: Severity = Severity.WARNING
    message: str
    capture_id: str | None = None
    session_id: str | None = None
    packet_refs: tuple[PacketReference, ...] = ()
    details: dict[str, str | int | bool] = Field(default_factory=dict)

    model_config = ConfigDict(frozen=False, extra="forbid")
