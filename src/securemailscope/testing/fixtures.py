"""Deterministic synthetic capture fixtures.

Each fixture pairs a generated capture with *hand-derived* expectations: the
byte counts, offsets, gap boundaries and packet numbers below were worked out
from the TCP semantics of the scenario, not copied from engine output.  The
generator emits both the capture and a manifest recording those expectations
plus the capture's SHA-256, and the test suite asserts the engine reproduces
them exactly.

Captures are gitignored (``tests/fixtures/generated/``); manifests and this
generator are committed, so anyone can reproduce the captures byte for byte.

No fixture contains a real TLS handshake, a real certificate, or data from any
real system.  TLS negotiation fixtures belong to M3 and inventing them now
would put fabricated cryptographic evidence into the test suite.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import (
    ExpectedConflict,
    ExpectedGap,
    ExpectedProtocol,
    ExpectedRun,
    ExpectedSession,
    ExpectedStream,
    FixtureManifest,
)
from .packets import (
    BASE_TIMESTAMP_NS,
    CLIENT_IP,
    CLIENT_IPV6,
    CLIENT_MAC,
    SERVER_IP,
    SERVER_IPV6,
    SERVER_MAC,
    ethernet_tcp,
)
from .writers import write_pcap, write_pcapng

__all__ = [
    "FixtureSpec",
    "Conversation",
    "build_fixtures",
    "write_fixtures",
    "FIXTURE_DIR_NAME",
]

FIXTURE_DIR_NAME = "generated"

#: 1 ms between packets keeps timestamps readable and unambiguous.
_STEP_NS = 1_000_000

SMTP_GREETING = b"EHLO client.example\r\n"  # 21 bytes
SMTP_REPLY = b"250-mail.example Hello\r\n"  # 24 bytes


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    filename: str
    description: str
    generation: str
    file_format: str
    link_type_code: int
    data: bytes
    timestamps_ns: list[int]
    expected_packet_count: int
    expected_tcp_packet_count: int
    expected_sessions: list[ExpectedSession] = field(default_factory=list)
    expected_warning_codes: list[str] = field(default_factory=list)
    expected_capture_truncated: bool = False
    expected_error: str | None = None
    #: ``None`` means this fixture makes no protocol-layer assertions.
    expected_protocols: list[ExpectedProtocol] | None = None
    #: Dummy credential strings that must never appear in any output.
    forbidden_strings: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def manifest(self) -> FixtureManifest:
        return FixtureManifest(
            name=self.name,
            filename=self.filename,
            description=self.description,
            generation=self.generation,
            file_format=self.file_format,
            link_type_code=self.link_type_code,
            capture_sha256=self.sha256,
            file_size_bytes=len(self.data),
            expected_packet_count=self.expected_packet_count,
            expected_tcp_packet_count=self.expected_tcp_packet_count,
            expected_timestamps_ns=list(self.timestamps_ns),
            expected_sessions=list(self.expected_sessions),
            expected_warning_codes=list(self.expected_warning_codes),
            expected_capture_truncated=self.expected_capture_truncated,
            expected_error=self.expected_error,
            expected_protocols=self.expected_protocols,
            forbidden_strings=list(self.forbidden_strings),
        )


class Conversation:
    """Accumulates frames for one or more connections in capture order."""

    def __init__(
        self,
        *,
        client_ip: str = CLIENT_IP,
        server_ip: str = SERVER_IP,
        client_port: int = 49152,
        server_port: int = 25,
        ipv6: bool = False,
        start_ns: int = BASE_TIMESTAMP_NS,
        step_ns: int = _STEP_NS,
        timestamp_offset_ns: int = 0,
    ) -> None:
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.ipv6 = ipv6
        self._start_ns = start_ns
        self._step_ns = step_ns
        self._timestamp_offset_ns = timestamp_offset_ns
        self.packets: list[tuple[int, bytes]] = []
        self._next_ip_id = 1

    def _timestamp(self) -> int:
        return (
            self._start_ns + len(self.packets) * self._step_ns + self._timestamp_offset_ns
        )

    def _emit(self, frame: bytes) -> int:
        self.packets.append((self._timestamp(), frame))
        return len(self.packets)

    def c2s(
        self,
        seq: int,
        ack: int,
        flags: str,
        payload: bytes = b"",
        ip_id: int | None = None,
    ) -> int:
        return self._emit(self._frame(True, seq, ack, flags, payload, ip_id))

    def s2c(
        self,
        seq: int,
        ack: int,
        flags: str,
        payload: bytes = b"",
        ip_id: int | None = None,
    ) -> int:
        return self._emit(self._frame(False, seq, ack, flags, payload, ip_id))

    def repeat(self, packet_number: int) -> int:
        """Re-emit an earlier frame byte for byte (a frame captured twice)."""
        return self._emit(self.packets[packet_number - 1][1])

    def _frame(
        self,
        from_client: bool,
        seq: int,
        ack: int,
        flags: str,
        payload: bytes,
        ip_id: int | None,
    ) -> bytes:
        if ip_id is None:
            ip_id = self._next_ip_id
            self._next_ip_id += 1
        return ethernet_tcp(
            src_mac=CLIENT_MAC if from_client else SERVER_MAC,
            dst_mac=SERVER_MAC if from_client else CLIENT_MAC,
            src_ip=self.client_ip if from_client else self.server_ip,
            dst_ip=self.server_ip if from_client else self.client_ip,
            src_port=self.client_port if from_client else self.server_port,
            dst_port=self.server_port if from_client else self.client_port,
            seq=seq,
            ack=ack,
            flags=flags,
            payload=payload,
            ip_id=ip_id,
            ipv6=self.ipv6,
        )

    @property
    def client(self) -> str:
        return f"{self.client_ip}:{self.client_port}"

    @property
    def server(self) -> str:
        return f"{self.server_ip}:{self.server_port}"


def _run(offset: int, content: bytes) -> ExpectedRun:
    return ExpectedRun(stream_offset=offset, length=len(content), content_hex=content.hex())


def _merge(conversations: Iterable[Conversation]) -> list[tuple[int, bytes]]:
    """Interleave several conversations into one capture, ordered by timestamp."""
    packets: list[tuple[int, bytes]] = []
    for conversation in conversations:
        packets.extend(conversation.packets)
    packets.sort(key=lambda item: item[0])
    return packets


def _timestamps(packets: list[tuple[int, bytes]]) -> list[int]:
    return [timestamp for timestamp, _ in packets]


# ---------------------------------------------------------------------------
# A. One complete TCP connection with known payload
# ---------------------------------------------------------------------------
def _fixture_a() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING)  # 4
    c.s2c(5001, 1022, "A")  # 5
    c.s2c(5001, 1022, "PA", SMTP_REPLY)  # 6
    c.c2s(1022, 5025, "A")  # 7
    c.c2s(1022, 5025, "FA")  # 8
    c.s2c(5025, 1023, "A")  # 9
    c.s2c(5025, 1023, "FA")  # 10
    c.c2s(1023, 5026, "A")  # 11

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=11,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=11,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[4],
            packet_count=6,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=24,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_REPLY)],
            segment_packets=[6],
            packet_count=5,
        ),
    )
    return FixtureSpec(
        name="A_complete_connection",
        filename="a_complete_connection.pcap",
        description=(
            "One complete SMTP-port TCP connection: full three-way handshake, one "
            "application payload in each direction, graceful FIN/FIN teardown."
        ),
        generation="securemailscope.testing.fixtures._fixture_a (scapy frames, hand-written pcap)",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=11,
        expected_tcp_packet_count=11,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# B. The same payload split across multiple segments
# ---------------------------------------------------------------------------
def _fixture_b() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING[0:5])  # 4  "EHLO "
    c.c2s(1006, 5001, "PA", SMTP_GREETING[5:12])  # 5  "client."
    c.c2s(1013, 5001, "PA", SMTP_GREETING[12:21])  # 6  "example\r\n"
    c.s2c(5001, 1022, "A")  # 7
    c.s2c(5001, 1022, "PA", SMTP_REPLY)  # 8
    c.c2s(1022, 5025, "A")  # 9
    c.c2s(1022, 5025, "FA")  # 10
    c.s2c(5025, 1023, "A")  # 11
    c.s2c(5025, 1023, "FA")  # 12
    c.c2s(1023, 5026, "A")  # 13

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=13,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=13,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[4, 5, 6],
            packet_count=8,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=24,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_REPLY)],
            segment_packets=[8],
            packet_count=5,
        ),
    )
    return FixtureSpec(
        name="B_segmented_payload",
        filename="b_segmented_payload.pcap",
        description=(
            "The fixture A client payload split across three TCP segments delivered in "
            "order. Reconstruction must yield exactly the fixture A byte stream."
        ),
        generation="securemailscope.testing.fixtures._fixture_b",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=13,
        expected_tcp_packet_count=13,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# C. Out-of-order delivery
# ---------------------------------------------------------------------------
def _fixture_c() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING[0:5])  # 4  first segment
    c.c2s(1013, 5001, "PA", SMTP_GREETING[12:21])  # 5  THIRD segment arrives second
    c.c2s(1006, 5001, "PA", SMTP_GREETING[5:12])  # 6  second segment arrives last
    c.s2c(5001, 1022, "A")  # 7
    c.c2s(1022, 5001, "FA")  # 8
    c.s2c(5001, 1023, "A")  # 9
    c.s2c(5001, 1023, "FA")  # 10
    c.c2s(1023, 5002, "A")  # 11

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=11,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=11,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            # Offset order, not arrival order: packet 6 supplies the middle bytes.
            segment_packets=[4, 6, 5],
            packet_count=7,
            out_of_order_count=1,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            runs=[],
            segment_packets=[],
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="C_out_of_order",
        filename="c_out_of_order.pcap",
        description=(
            "Three client segments captured out of order (1, 3, 2). The reconstructed "
            "stream must be contiguous and identical to fixture A's client payload."
        ),
        generation="securemailscope.testing.fixtures._fixture_c",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=11,
        expected_tcp_packet_count=11,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# D. Duplicate segment (the same frame captured twice)
# ---------------------------------------------------------------------------
def _fixture_d() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING)  # 4
    c.repeat(4)  # 5  byte-identical frame
    c.s2c(5001, 1022, "A")  # 6
    c.c2s(1022, 5001, "FA")  # 7
    c.s2c(5001, 1023, "A")  # 8
    c.s2c(5001, 1023, "FA")  # 9
    c.c2s(1023, 5002, "A")  # 10

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=10,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=10,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[4],
            duplicate_packets={"0": [5]},
            packet_count=6,
            duplicate_count=1,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="D_duplicate_segment",
        filename="d_duplicate_segment.pcap",
        description=(
            "The client data frame appears twice, byte for byte, as happens when a "
            "capture point sees the same frame on two interfaces. The payload must be "
            "stored once and the repeat classified as a duplicate."
        ),
        generation="securemailscope.testing.fixtures._fixture_d",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=10,
        expected_tcp_packet_count=10,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# E. Retransmission (same bytes, a genuinely different frame)
# ---------------------------------------------------------------------------
def _fixture_e() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING, ip_id=400)  # 4
    c.c2s(1001, 5001, "PA", SMTP_GREETING, ip_id=401)  # 5 retransmission
    c.s2c(5001, 1022, "A")  # 6
    c.c2s(1022, 5001, "FA")  # 7
    c.s2c(5001, 1023, "A")  # 8
    c.s2c(5001, 1023, "FA")  # 9
    c.c2s(1023, 5002, "A")  # 10

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=10,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=10,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[4],
            duplicate_packets={"0": [5]},
            packet_count=6,
            retransmission_count=1,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="E_retransmission",
        filename="e_retransmission.pcap",
        description=(
            "The client resends the same payload at the same sequence number in a new "
            "frame (different IP ID). The bytes must not be stored twice and the resend "
            "must be classified as a retransmission, not a duplicate capture."
        ),
        generation="securemailscope.testing.fixtures._fixture_e",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=10,
        expected_tcp_packet_count=10,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# F. Missing segment
# ---------------------------------------------------------------------------
def _fixture_f() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING[0:5])  # 4  bytes 0-4
    # bytes 5-11 (sequence 1006-1012) were never captured
    c.c2s(1013, 5001, "PA", SMTP_GREETING[12:21])  # 5  bytes 12-20
    c.s2c(5001, 1022, "A")  # 6
    c.c2s(1022, 5001, "FA")  # 7
    c.s2c(5001, 1023, "A")  # 8
    c.s2c(5001, 1023, "FA")  # 9
    c.c2s(1023, 5002, "A")  # 10

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=10,
        completeness="PARTIAL",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=10,
        client_to_server=ExpectedStream(
            bytes_reconstructed=14,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING[0:5]), _run(12, SMTP_GREETING[12:21])],
            gaps=[
                ExpectedGap(
                    stream_offset=5,
                    length=7,
                    reason="MISSING_SEGMENT",
                    preceding_packet=4,
                    following_packet=5,
                )
            ],
            segment_packets=[4, 5],
            packet_count=6,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="F_missing_segment",
        filename="f_missing_segment.pcap",
        description=(
            "Seven bytes in the middle of the client payload were never captured. The "
            "two surviving ranges must be reported as separate runs with an explicit "
            "gap between them and must never be concatenated."
        ),
        generation="securemailscope.testing.fixtures._fixture_f",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=10,
        expected_tcp_packet_count=10,
        expected_sessions=[session],
        expected_warning_codes=["SEQUENCE_GAP"],
    )


# ---------------------------------------------------------------------------
# G. Two independent connections
# ---------------------------------------------------------------------------
_G_SMTP_PAYLOAD = b"HELO one\r\n"  # 10 bytes
_G_IMAP_PAYLOAD = b"a001 CAPABILITY\r\n"  # 17 bytes


def _fixture_g() -> FixtureSpec:
    smtp = Conversation(client_port=49152, server_port=25, step_ns=2 * _STEP_NS)
    imap = Conversation(
        client_ip="192.0.2.11",
        client_port=49153,
        server_port=143,
        step_ns=2 * _STEP_NS,
        timestamp_offset_ns=_STEP_NS,
    )
    for conversation, payload in ((smtp, _G_SMTP_PAYLOAD), (imap, _G_IMAP_PAYLOAD)):
        conversation.c2s(1000, 0, "S")
        conversation.s2c(5000, 1001, "SA")
        conversation.c2s(1001, 5001, "A")
        conversation.c2s(1001, 5001, "PA", payload)
        conversation.s2c(5001, 1001 + len(payload), "A")
        conversation.c2s(1001 + len(payload), 5001, "FA")
        conversation.s2c(5001, 1002 + len(payload), "A")
        conversation.s2c(5001, 1002 + len(payload), "FA")
        conversation.c2s(1002 + len(payload), 5002, "A")

    packets = _merge([smtp, imap])

    def session_for(
        conversation: Conversation, payload: bytes, numbers: list[int], hint: str
    ) -> ExpectedSession:
        return ExpectedSession(
            client=conversation.client,
            server=conversation.server,
            flow_instance=1,
            packet_count=9,
            completeness="COMPLETE",
            handshake_complete=True,
            termination_reason="FIN_BOTH_DIRECTIONS",
            role_status="OBSERVED",
            role_basis="TCP_SYN",
            protocol_hint=hint,
            first_packet=numbers[0],
            last_packet=numbers[-1],
            client_to_server=ExpectedStream(
                bytes_reconstructed=len(payload),
                stream_base_sequence=1001,
                base_status="OBSERVED",
                runs=[_run(0, payload)],
                segment_packets=[numbers[3]],
                packet_count=5,
            ),
            server_to_client=ExpectedStream(
                bytes_reconstructed=0,
                stream_base_sequence=5001,
                base_status="OBSERVED",
                packet_count=4,
            ),
        )

    # Interleaved 1 ms apart: SMTP takes the odd packet numbers, IMAP the even.
    smtp_numbers = [1, 3, 5, 7, 9, 11, 13, 15, 17]
    imap_numbers = [2, 4, 6, 8, 10, 12, 14, 16, 18]
    return FixtureSpec(
        name="G_two_connections",
        filename="g_two_connections.pcap",
        description=(
            "Two independent connections from different clients to different service "
            "ports, interleaved packet by packet. They must be reported as two separate "
            "sessions with independent reconstruction."
        ),
        generation="securemailscope.testing.fixtures._fixture_g",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(packets),
        timestamps_ns=_timestamps(packets),
        expected_packet_count=18,
        expected_tcp_packet_count=18,
        expected_sessions=[
            session_for(smtp, _G_SMTP_PAYLOAD, smtp_numbers, "HINT:SMTP"),
            session_for(imap, _G_IMAP_PAYLOAD, imap_numbers, "HINT:IMAP"),
        ],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# H. Conflicting overlapping payload
# ---------------------------------------------------------------------------
_H_FIRST = b"A" * 10
_H_SECOND = b"B" * 10


def _fixture_h() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", _H_FIRST)  # 4  offsets 0-9  = "AAAAAAAAAA"
    c.c2s(1006, 5001, "PA", _H_SECOND)  # 5  offsets 5-14 = "BBBBBBBBBB"
    c.s2c(5001, 1016, "A")  # 6
    c.c2s(1016, 5001, "FA")  # 7
    c.s2c(5001, 1017, "A")  # 8
    c.s2c(5001, 1017, "FA")  # 9
    c.c2s(1017, 5002, "A")  # 10

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=10,
        completeness="PARTIAL",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=10,
        client_to_server=ExpectedStream(
            bytes_reconstructed=15,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            # FIRST_OBSERVED_WINS: offsets 5-9 keep packet 4's "AAAAA".
            runs=[_run(0, _H_FIRST + _H_SECOND[5:])],
            conflicts=[
                ExpectedConflict(
                    stream_offset=5,
                    length=5,
                    accepted_packet=4,
                    conflicting_packet=5,
                    accepted_hex=(b"A" * 5).hex(),
                    conflicting_hex=(b"B" * 5).hex(),
                )
            ],
            segment_packets=[4, 5],
            packet_count=6,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="H_overlap_conflict",
        filename="h_overlap_conflict.pcap",
        description=(
            "Two client segments overlap by five bytes and disagree about their "
            "contents. The first observation is kept, the disagreement is reported as "
            "an overlap conflict, and the ambiguity is not hidden."
        ),
        generation="securemailscope.testing.fixtures._fixture_h",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=10,
        expected_tcp_packet_count=10,
        expected_sessions=[session],
        expected_warning_codes=["OVERLAP_CONFLICT"],
    )


# ---------------------------------------------------------------------------
# I. Damaged and unreadable captures
# ---------------------------------------------------------------------------
def _fixture_i_truncated() -> FixtureSpec:
    complete = _fixture_a()
    # Cut the file inside the fourth packet's record: 24-byte file header plus
    # three complete records, then a packet header and four payload bytes.
    keep = 24 + 3 * (16 + 54) + 16 + 4
    data = complete.data[:keep]
    session = ExpectedSession(
        client=f"{CLIENT_IP}:49152",
        server=f"{SERVER_IP}:25",
        flow_instance=1,
        packet_count=3,
        completeness="PARTIAL",
        handshake_complete=True,
        termination_reason="NOT_OBSERVED",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=3,
        client_to_server=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            packet_count=2,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=1,
        ),
    )
    return FixtureSpec(
        name="I1_truncated_capture",
        filename="i1_truncated_capture.pcap",
        description=(
            "Fixture A cut off inside the fourth packet record. The three intact "
            "packets must still be analysed and the damage reported explicitly."
        ),
        generation=(
            "securemailscope.testing.fixtures._fixture_i_truncated "
            "(fixture A, byte-truncated)"
        ),
        file_format="pcap",
        link_type_code=1,
        data=data,
        timestamps_ns=complete.timestamps_ns[:3],
        expected_packet_count=3,
        expected_tcp_packet_count=3,
        expected_sessions=[session],
        expected_warning_codes=["TRUNCATED_CAPTURE_FILE", "NO_TERMINATION_OBSERVED"],
        expected_capture_truncated=True,
    )


def _fixture_i_not_a_capture() -> FixtureSpec:
    data = b"NOT A CAPTURE FILE\n" + bytes(64)
    return FixtureSpec(
        name="I2_not_a_capture",
        filename="i2_not_a_capture.pcap",
        description=(
            "A file with a .pcap extension whose contents are not a capture at all. "
            "Format detection must reject it on contents, not on the extension."
        ),
        generation="securemailscope.testing.fixtures._fixture_i_not_a_capture",
        file_format="raw",
        link_type_code=-1,
        data=data,
        timestamps_ns=[],
        expected_packet_count=0,
        expected_tcp_packet_count=0,
        expected_error="UnsupportedCaptureFormatError",
    )


def _fixture_i_header_only() -> FixtureSpec:
    return FixtureSpec(
        name="I3_header_only",
        filename="i3_header_only.pcap",
        description="A valid pcap file header with no packet records at all.",
        generation="securemailscope.testing.fixtures._fixture_i_header_only",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap([]),
        timestamps_ns=[],
        expected_packet_count=0,
        expected_tcp_packet_count=0,
        expected_sessions=[],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# J. Two distinct connections reusing the same endpoint tuple
# ---------------------------------------------------------------------------
_J_FIRST = b"FIRST\r\n"  # 7 bytes
_J_SECOND = b"SECOND\r\n"  # 8 bytes


def _fixture_j() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", _J_FIRST)  # 4
    c.s2c(5001, 1008, "A")  # 5
    c.c2s(1008, 5001, "FA")  # 6
    c.s2c(5001, 1009, "A")  # 7
    c.s2c(5001, 1009, "FA")  # 8
    c.c2s(1009, 5002, "A")  # 9
    # Same five-tuple, brand new connection with a different ISN.
    c.c2s(9000, 0, "S")  # 10
    c.s2c(7000, 9001, "SA")  # 11
    c.c2s(9001, 7001, "A")  # 12
    c.c2s(9001, 7001, "PA", _J_SECOND)  # 13
    c.s2c(7001, 9009, "A")  # 14
    c.c2s(9009, 7001, "FA")  # 15
    c.s2c(7001, 9010, "A")  # 16
    c.s2c(7001, 9010, "FA")  # 17
    c.c2s(9010, 7002, "A")  # 18

    def session(
        instance: int, payload: bytes, base_c2s: int, base_s2c: int, numbers: list[int]
    ) -> ExpectedSession:
        return ExpectedSession(
            client=c.client,
            server=c.server,
            flow_instance=instance,
            packet_count=9,
            completeness="COMPLETE",
            handshake_complete=True,
            termination_reason="FIN_BOTH_DIRECTIONS",
            role_status="OBSERVED",
            role_basis="TCP_SYN",
            protocol_hint="HINT:SMTP",
            first_packet=numbers[0],
            last_packet=numbers[-1],
            client_to_server=ExpectedStream(
                bytes_reconstructed=len(payload),
                stream_base_sequence=base_c2s,
                base_status="OBSERVED",
                runs=[_run(0, payload)],
                segment_packets=[numbers[3]],
                packet_count=5,
            ),
            server_to_client=ExpectedStream(
                bytes_reconstructed=0,
                stream_base_sequence=base_s2c,
                base_status="OBSERVED",
                packet_count=4,
            ),
        )

    return FixtureSpec(
        name="J_tuple_reuse",
        filename="j_tuple_reuse.pcap",
        description=(
            "Two successive connections reuse the same five-tuple with different "
            "initial sequence numbers. They must be reported as two sessions sharing "
            "one flow id, never merged into one."
        ),
        generation="securemailscope.testing.fixtures._fixture_j",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=18,
        expected_tcp_packet_count=18,
        expected_sessions=[
            session(1, _J_FIRST, 1001, 5001, [1, 2, 3, 4, 5, 6, 7, 8, 9]),
            session(2, _J_SECOND, 9001, 7001, [10, 11, 12, 13, 14, 15, 16, 17, 18]),
        ],
        expected_warning_codes=["TUPLE_REUSE"],
    )


# ---------------------------------------------------------------------------
# K. pcapng container with nanosecond timestamps
# ---------------------------------------------------------------------------
def _fixture_k() -> FixtureSpec:
    complete = _fixture_a()
    # Offset every timestamp by 987 ns so the test can prove sub-microsecond
    # precision survives the pcapng reader.
    packets = [
        (timestamp + 987, data)
        for timestamp, data in zip(
            complete.timestamps_ns, [frame for _, frame in _fixture_a_packets()], strict=True
        )
    ]
    session = complete.expected_sessions[0]
    return FixtureSpec(
        name="K_pcapng_nanosecond",
        filename="k_pcapng_nanosecond.pcapng",
        description=(
            "Fixture A's packets in a pcapng container with if_tsresol=9. Timestamps "
            "carry a 987 ns offset that must survive parsing intact."
        ),
        generation="securemailscope.testing.fixtures._fixture_k",
        file_format="pcapng",
        link_type_code=1,
        data=write_pcapng(packets, tsresol_exponent=9),
        timestamps_ns=[timestamp for timestamp, _ in packets],
        expected_packet_count=11,
        expected_tcp_packet_count=11,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


def _fixture_a_packets() -> list[tuple[int, bytes]]:
    c = Conversation()
    c.c2s(1000, 0, "S")
    c.s2c(5000, 1001, "SA")
    c.c2s(1001, 5001, "A")
    c.c2s(1001, 5001, "PA", SMTP_GREETING)
    c.s2c(5001, 1022, "A")
    c.s2c(5001, 1022, "PA", SMTP_REPLY)
    c.c2s(1022, 5025, "A")
    c.c2s(1022, 5025, "FA")
    c.s2c(5025, 1023, "A")
    c.s2c(5025, 1023, "FA")
    c.c2s(1023, 5026, "A")
    return c.packets


# ---------------------------------------------------------------------------
# L. IPv6 connection
# ---------------------------------------------------------------------------
def _fixture_l() -> FixtureSpec:
    c = Conversation(
        client_ip=CLIENT_IPV6, server_ip=SERVER_IPV6, server_port=587, ipv6=True
    )
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING)  # 4
    c.s2c(5001, 1022, "A")  # 5
    c.c2s(1022, 5001, "FA")  # 6
    c.s2c(5001, 1023, "A")  # 7
    c.s2c(5001, 1023, "FA")  # 8
    c.c2s(1023, 5002, "A")  # 9

    session = ExpectedSession(
        client=f"{CLIENT_IPV6}:49152",
        server=f"{SERVER_IPV6}:587",
        flow_instance=1,
        packet_count=9,
        completeness="COMPLETE",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP submission",
        first_packet=1,
        last_packet=9,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[4],
            packet_count=5,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="L_ipv6_connection",
        filename="l_ipv6_connection.pcap",
        description="A complete IPv6 connection to the SMTP submission port.",
        generation="securemailscope.testing.fixtures._fixture_l",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=9,
        expected_tcp_packet_count=9,
        expected_sessions=[session],
        expected_warning_codes=[],
    )


# ---------------------------------------------------------------------------
# M. Midstream capture (no handshake observed)
# ---------------------------------------------------------------------------
def _fixture_m() -> FixtureSpec:
    c = Conversation()
    c.c2s(1001, 5001, "PA", SMTP_GREETING)  # 1
    c.s2c(5001, 1022, "A")  # 2
    c.s2c(5001, 1022, "PA", SMTP_REPLY)  # 3
    c.c2s(1022, 5025, "A")  # 4

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=4,
        completeness="MIDSTREAM",
        handshake_complete=False,
        termination_reason="NOT_OBSERVED",
        role_status="INFERRED",
        role_basis="WELL_KNOWN_PORT",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=4,
        client_to_server=ExpectedStream(
            bytes_reconstructed=21,
            stream_base_sequence=1001,
            base_status="INFERRED",
            runs=[_run(0, SMTP_GREETING)],
            segment_packets=[1],
            packet_count=2,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=24,
            stream_base_sequence=5001,
            base_status="INFERRED",
            runs=[_run(0, SMTP_REPLY)],
            segment_packets=[3],
            packet_count=2,
        ),
    )
    return FixtureSpec(
        name="M_midstream",
        filename="m_midstream.pcap",
        description=(
            "A capture that starts after the connection was established. Roles must be "
            "INFERRED from the service port and the missing start reported explicitly."
        ),
        generation="securemailscope.testing.fixtures._fixture_m",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(c.packets),
        timestamps_ns=_timestamps(c.packets),
        expected_packet_count=4,
        expected_tcp_packet_count=4,
        expected_sessions=[session],
        expected_warning_codes=["MIDSTREAM_SESSION", "NO_TERMINATION_OBSERVED"],
    )


# ---------------------------------------------------------------------------
# N. Unsupported link type
# ---------------------------------------------------------------------------
def _fixture_n() -> FixtureSpec:
    packets = [(BASE_TIMESTAMP_NS, bytes(range(40)))]
    return FixtureSpec(
        name="N_unsupported_link_type",
        filename="n_unsupported_link_type.pcap",
        description=(
            "A pcap declaring link type 105 (IEEE 802.11), which this engine does not "
            "dissect. It must produce a diagnostic and zero sessions, never a guessed one."
        ),
        generation="securemailscope.testing.fixtures._fixture_n",
        file_format="pcap",
        link_type_code=105,
        data=write_pcap(packets, link_type=105),
        timestamps_ns=_timestamps(packets),
        expected_packet_count=1,
        expected_tcp_packet_count=0,
        expected_sessions=[],
        expected_warning_codes=["UNSUPPORTED_LINK_TYPE"],
    )


# ---------------------------------------------------------------------------
# O. Snapshot-truncated payload
# ---------------------------------------------------------------------------
def _fixture_o() -> FixtureSpec:
    c = Conversation()
    c.c2s(1000, 0, "S")  # 1
    c.s2c(5000, 1001, "SA")  # 2
    c.c2s(1001, 5001, "A")  # 3
    c.c2s(1001, 5001, "PA", SMTP_GREETING)  # 4  full frame, stored short below
    c.s2c(5001, 1022, "A")  # 5
    c.c2s(1022, 5001, "FA")  # 6
    c.s2c(5001, 1023, "A")  # 7
    c.s2c(5001, 1023, "FA")  # 8
    c.c2s(1023, 5002, "A")  # 9

    records: list[tuple[int, bytes, int]] = []
    for index, (timestamp, frame) in enumerate(c.packets, start=1):
        if index == 4:
            # Keep only the first 10 of the 21 payload bytes; declare the true
            # wire length so the shortfall is detectable.
            records.append((timestamp, frame[: len(frame) - 11], len(frame)))
        else:
            records.append((timestamp, frame, len(frame)))

    session = ExpectedSession(
        client=c.client,
        server=c.server,
        flow_instance=1,
        packet_count=9,
        completeness="PARTIAL",
        handshake_complete=True,
        termination_reason="FIN_BOTH_DIRECTIONS",
        role_status="OBSERVED",
        role_basis="TCP_SYN",
        protocol_hint="HINT:SMTP",
        first_packet=1,
        last_packet=9,
        client_to_server=ExpectedStream(
            bytes_reconstructed=10,
            stream_base_sequence=1001,
            base_status="OBSERVED",
            runs=[_run(0, SMTP_GREETING[:10])],
            gaps=[
                ExpectedGap(
                    stream_offset=10,
                    length=11,
                    reason="NOT_CAPTURED",
                    preceding_packet=4,
                    following_packet=None,
                )
            ],
            segment_packets=[4],
            packet_count=5,
        ),
        server_to_client=ExpectedStream(
            bytes_reconstructed=0,
            stream_base_sequence=5001,
            base_status="OBSERVED",
            packet_count=4,
        ),
    )
    return FixtureSpec(
        name="O_snapshot_truncated",
        filename="o_snapshot_truncated.pcap",
        description=(
            "The client data frame was stored with a short snapshot length: 10 of its "
            "21 payload bytes are present. The missing tail must be reported as a "
            "NOT_CAPTURED gap rather than silently shortening the stream."
        ),
        generation="securemailscope.testing.fixtures._fixture_o",
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(records, snaplen=64),
        timestamps_ns=[timestamp for timestamp, _, _ in records],
        expected_packet_count=9,
        expected_tcp_packet_count=9,
        expected_sessions=[session],
        expected_warning_codes=[
            "TRUNCATED_PACKET_DATA",
            "SEQUENCE_GAP",
            # The server acknowledged all 21 bytes, so the 11 missing ones are
            # known to have been sent -- not merely absent.
            "ACKED_DATA_NOT_CAPTURED",
        ],
    )


_BUILDERS = (
    _fixture_a,
    _fixture_b,
    _fixture_c,
    _fixture_d,
    _fixture_e,
    _fixture_f,
    _fixture_g,
    _fixture_h,
    _fixture_i_truncated,
    _fixture_i_not_a_capture,
    _fixture_i_header_only,
    _fixture_j,
    _fixture_k,
    _fixture_l,
    _fixture_m,
    _fixture_n,
    _fixture_o,
)


def build_fixtures() -> list[FixtureSpec]:
    """Build every fixture in memory. Deterministic across runs and machines.

    Combines the M1 TCP-reconstruction fixtures defined here with the M2
    protocol fixtures in :mod:`securemailscope.testing.protocol_fixtures`.
    """
    from .protocol_fixtures import build_protocol_fixtures

    return [builder() for builder in _BUILDERS] + build_protocol_fixtures()


def write_fixtures(capture_dir: Path, manifest_dir: Path) -> list[FixtureSpec]:
    """Write captures and manifests to disk, returning the specs."""
    capture_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)
    specs = build_fixtures()
    for spec in specs:
        (capture_dir / spec.filename).write_bytes(spec.data)
        manifest_path = manifest_dir / f"{spec.name}.json"
        manifest_path.write_text(
            json.dumps(spec.manifest().to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return specs
