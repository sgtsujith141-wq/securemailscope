"""Expectation records that make up a fixture manifest.

Manifests are *hand-declared* expectations, not a recording of whatever the
engine happened to produce.  That distinction is what keeps the test suite
from being tautological: the numbers below were worked out from the TCP
semantics of each scenario, and a regression in the engine makes a test fail
rather than quietly rewriting the expectation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = [
    "ExpectedRun",
    "ExpectedGap",
    "ExpectedConflict",
    "ExpectedStream",
    "ExpectedSession",
    "FixtureManifest",
]


@dataclass(frozen=True)
class ExpectedRun:
    stream_offset: int
    length: int
    content_hex: str


@dataclass(frozen=True)
class ExpectedGap:
    stream_offset: int
    length: int
    reason: str
    preceding_packet: int | None = None
    following_packet: int | None = None


@dataclass(frozen=True)
class ExpectedConflict:
    stream_offset: int
    length: int
    accepted_packet: int
    conflicting_packet: int
    accepted_hex: str
    conflicting_hex: str


@dataclass(frozen=True)
class ExpectedStream:
    bytes_reconstructed: int
    stream_base_sequence: int | None
    base_status: str
    runs: list[ExpectedRun] = field(default_factory=list)
    gaps: list[ExpectedGap] = field(default_factory=list)
    conflicts: list[ExpectedConflict] = field(default_factory=list)
    #: Packet numbers of accepted segments, in stream-offset order.
    segment_packets: list[int] = field(default_factory=list)
    #: Packet numbers re-delivering already-stored bytes, keyed by offset.
    duplicate_packets: dict[str, list[int]] = field(default_factory=dict)
    packet_count: int = 0
    retransmission_count: int = 0
    duplicate_count: int = 0
    out_of_order_count: int = 0


@dataclass(frozen=True)
class ExpectedSession:
    client: str
    server: str
    flow_instance: int
    packet_count: int
    completeness: str
    handshake_complete: bool
    termination_reason: str
    role_status: str
    role_basis: str
    protocol_hint: str | None
    first_packet: int
    last_packet: int
    client_to_server: ExpectedStream
    server_to_client: ExpectedStream


@dataclass(frozen=True)
class FixtureManifest:
    name: str
    filename: str
    description: str
    generation: str
    file_format: str
    link_type_code: int
    capture_sha256: str
    file_size_bytes: int
    expected_packet_count: int
    expected_tcp_packet_count: int
    expected_timestamps_ns: list[int]
    expected_sessions: list[ExpectedSession] = field(default_factory=list)
    expected_warning_codes: list[str] = field(default_factory=list)
    expected_capture_truncated: bool = False
    #: Set when analysis is expected to raise instead of producing a result.
    expected_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
