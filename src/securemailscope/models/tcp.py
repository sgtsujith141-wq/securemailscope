"""TCP flow, session and reassembly data contracts.

These models are the boundary between the TCP layer and everything that will
be built on top of it (SMTP/IMAP/POP3 command parsing in M2, TLS record and
handshake reconstruction in M3).  They therefore expose reconstructed data as
*explicitly delimited runs with provenance*, never as a single opaque blob,
so that an upper layer can never accidentally parse across a gap.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import AnalysisWarning, EvidenceStatus, Observation, PacketReference

__all__ = [
    "AddressFamily",
    "Direction",
    "Endpoint",
    "TCPFlow",
    "SegmentDisposition",
    "ReassembledSegment",
    "GapReason",
    "ReassemblyGap",
    "OverlapConflict",
    "ByteRun",
    "DirectionalStream",
    "HandshakeInfo",
    "TerminationReason",
    "TerminationInfo",
    "SessionCompleteness",
    "TCPSession",
]


class AddressFamily(StrEnum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"


class Direction(StrEnum):
    """Direction of a byte stream, named by role rather than by address.

    The roles are assigned from the observed handshake where possible; when
    the capture starts midstream they are inferred from which endpoint was
    seen first, and the session records that inference explicitly.
    """

    CLIENT_TO_SERVER = "CLIENT_TO_SERVER"
    SERVER_TO_CLIENT = "SERVER_TO_CLIENT"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Endpoint(_Frozen):
    ip: str
    port: int = Field(ge=0, le=65535)

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"


class TCPFlow(_Frozen):
    """The addressing identity of a connection.

    ``flow_id`` is derived from the normalized endpoint pair, so every
    connection that reuses the same 5-tuple shares a ``flow_id`` while keeping
    a distinct ``session_id``.  That is what makes tuple reuse visible instead
    of silently merged.
    """

    flow_id: str
    transport: str = "TCP"
    address_family: AddressFamily
    client: Endpoint
    server: Endpoint
    role_status: EvidenceStatus = Field(
        description="OBSERVED when a client SYN fixed the roles, INFERRED otherwise."
    )
    role_basis: str = Field(description="e.g. 'TCP_SYN', 'FIRST_PACKET_SENDER'.")


class SegmentDisposition(StrEnum):
    """What the reassembler did with an incoming TCP segment payload."""

    #: Bytes were new and were accepted into the stream.
    ACCEPTED = "ACCEPTED"
    #: Same (seq, length, payload) as an earlier packet and the link-layer
    #: identity matched -- almost certainly the same frame captured twice.
    DUPLICATE = "DUPLICATE"
    #: Bytes already present and identical; a genuine TCP retransmission.
    RETRANSMISSION = "RETRANSMISSION"
    #: Overlapped stored bytes, agreed where they overlapped, and contributed
    #: some new bytes as well.
    PARTIAL_OVERLAP = "PARTIAL_OVERLAP"
    #: Overlapped stored bytes and disagreed with them.
    OVERLAP_CONFLICT = "OVERLAP_CONFLICT"
    #: Dropped because a configured resource limit was reached.
    DROPPED_LIMIT = "DROPPED_LIMIT"
    #: Sequence number lies before the established stream base (e.g. data from
    #: before a midstream capture point that a retransmission exposed).
    BEFORE_STREAM_BASE = "BEFORE_STREAM_BASE"


class ReassembledSegment(_Frozen):
    """One contiguous accepted byte range and the packet it came from.

    A segment is *never* merged with its neighbours: keeping one record per
    contributing packet is what allows a later TLS or SMTP finding to name the
    exact frame its evidence came from.
    """

    stream_offset: int = Field(ge=0, description="Offset from the start of the reconstructed data.")
    length: int = Field(ge=1)
    sequence_number: int = Field(ge=0, description="Absolute TCP sequence of the first byte.")
    source: PacketReference
    duplicates: tuple[PacketReference, ...] = Field(
        default=(),
        description="Later packets that re-delivered these exact bytes.",
    )
    disposition: SegmentDisposition = SegmentDisposition.ACCEPTED


class GapReason(StrEnum):
    #: Data between two observed ranges was never captured.
    MISSING_SEGMENT = "MISSING_SEGMENT"
    #: A packet declared these bytes but the capture's snapshot length cut
    #: them off, so they are known to have existed and known to be absent.
    NOT_CAPTURED = "NOT_CAPTURED"
    #: A configured limit stopped us from storing further bytes.
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class ReassemblyGap(_Frozen):
    """A hole in the reconstructed stream.

    The gap itself is an observed fact; its *contents* are ``UNKNOWN`` and must
    never be filled in, elided, or concatenated across.
    """

    stream_offset: int = Field(ge=0)
    length: int = Field(ge=1)
    reason: GapReason
    content_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    preceding_packet: PacketReference | None = None
    following_packet: PacketReference | None = None


class OverlapConflict(_Frozen):
    """Two packets claimed the same stream offsets with different bytes.

    This is preserved rather than resolved: overlapping-segment disagreement is
    a classic IDS/endpoint desynchronisation primitive, so silently picking a
    winner would destroy exactly the evidence that matters.  The bytes
    themselves are not stored -- only digests -- so a report can demonstrate
    the disagreement without carrying payload.
    """

    stream_offset: int = Field(ge=0)
    length: int = Field(ge=1)
    accepted_packet: PacketReference
    conflicting_packet: PacketReference
    accepted_sha256: str
    conflicting_sha256: str
    policy: str = Field(
        default="FIRST_OBSERVED_WINS",
        description="Resolution policy applied to the reconstructed stream.",
    )


class ByteRun(_Frozen):
    """A maximal contiguous run of reconstructed bytes.

    Consumers iterate runs; the presence of more than one run means the stream
    has holes and must not be parsed as a continuous byte sequence.
    """

    stream_offset: int = Field(ge=0)
    length: int = Field(ge=1)
    sha256: str = Field(description="SHA-256 of this run's bytes (content is not stored).")
    first_packet: PacketReference
    last_packet: PacketReference


class DirectionalStream(_Frozen):
    """Reconstruction result for one half of a connection."""

    direction: Direction
    source: Endpoint
    destination: Endpoint

    packet_count: int = Field(default=0, ge=0)
    payload_packet_count: int = Field(default=0, ge=0)

    stream_base_sequence: int | None = Field(
        default=None, description="Absolute TCP sequence corresponding to stream offset 0."
    )
    base_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    base_basis: str | None = None

    bytes_reconstructed: int = Field(default=0, ge=0)
    highest_offset_observed: int = Field(
        default=0, ge=0, description="End offset of the furthest byte stored."
    )

    runs: tuple[ByteRun, ...] = ()
    segments: tuple[ReassembledSegment, ...] = ()
    gaps: tuple[ReassemblyGap, ...] = ()
    overlap_conflicts: tuple[OverlapConflict, ...] = ()

    retransmission_count: int = Field(default=0, ge=0)
    duplicate_count: int = Field(default=0, ge=0)
    out_of_order_count: int = Field(default=0, ge=0)
    dropped_by_limit_count: int = Field(default=0, ge=0)

    truncated_by_limit: bool = False
    fin_observed: bool = False
    rst_observed: bool = False
    highest_ack_observed: int | None = None

    @property
    def contiguous(self) -> bool:
        """True when the reconstructed data has no holes."""
        return not self.gaps and len(self.runs) <= 1


class HandshakeInfo(_Frozen):
    syn_observed: bool = False
    syn_ack_observed: bool = False
    ack_observed: bool = False
    client_isn: int | None = None
    server_isn: int | None = None
    syn_packet: PacketReference | None = None
    syn_ack_packet: PacketReference | None = None

    @property
    def complete(self) -> bool:
        return self.syn_observed and self.syn_ack_observed and self.ack_observed


class TerminationReason(StrEnum):
    FIN_BOTH_DIRECTIONS = "FIN_BOTH_DIRECTIONS"
    FIN_ONE_DIRECTION = "FIN_ONE_DIRECTION"
    RESET = "RESET"
    NOT_OBSERVED = "NOT_OBSERVED"


class TerminationInfo(_Frozen):
    reason: TerminationReason = TerminationReason.NOT_OBSERVED
    client_fin: PacketReference | None = None
    server_fin: PacketReference | None = None
    reset_packet: PacketReference | None = None


class SessionCompleteness(StrEnum):
    """How much of the connection this capture actually contains.

    Evaluated in this precedence order, so the label always names the most
    severe deficiency; ``completeness_notes`` lists every contributing reason.
    """

    #: A resource limit stopped reconstruction. Byte counts are lower bounds.
    TRUNCATED = "TRUNCATED"
    #: No client SYN was seen; the capture began after the connection did.
    MIDSTREAM = "MIDSTREAM"
    #: Start was seen, but data is missing and/or no termination was observed.
    PARTIAL = "PARTIAL"
    #: Handshake observed, termination observed, both directions hole-free.
    COMPLETE = "COMPLETE"


class TCPSession(_Frozen):
    """One reconstructed TCP connection.

    ``session_id`` is stable for a given capture: it is derived from the
    capture id, the normalized flow and the ordinal of this connection within
    that flow, so re-running the analysis reproduces the same identifiers.
    """

    session_id: str
    capture_id: str
    flow: TCPFlow
    flow_instance: int = Field(
        ge=1, description="1-based ordinal of this connection among reuses of the same 5-tuple."
    )

    first_packet: PacketReference
    last_packet: PacketReference
    packet_count: int = Field(ge=1)

    handshake: HandshakeInfo
    termination: TerminationInfo
    completeness: SessionCompleteness
    completeness_notes: tuple[str, ...] = ()

    client_to_server: DirectionalStream
    server_to_client: DirectionalStream

    protocol_hint: Observation[str] | None = Field(
        default=None,
        description="Port-derived hint only. Never a confirmed protocol identification.",
    )
    warnings: tuple[AnalysisWarning, ...] = ()

    @property
    def total_bytes_reconstructed(self) -> int:
        return (
            self.client_to_server.bytes_reconstructed + self.server_to_client.bytes_reconstructed
        )

    @property
    def start_time(self) -> datetime:
        return self.first_packet.timestamp

    @property
    def end_time(self) -> datetime:
        return self.last_packet.timestamp
