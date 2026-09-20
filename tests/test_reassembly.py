"""Manifest-driven verification of TCP session reconstruction.

Each assertion compares engine output against a *hand-derived* expectation
recorded in a committed manifest, including reconstructed bytes and the packet
numbers that produced them.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from securemailscope.models.tcp import Direction
from securemailscope.pipeline import analyze_capture_with_payloads

from .conftest import Fixture

RECONSTRUCTION_FIXTURES = [
    "A_complete_connection",
    "B_segmented_payload",
    "C_out_of_order",
    "D_duplicate_segment",
    "E_retransmission",
    "F_missing_segment",
    "G_two_connections",
    "H_overlap_conflict",
    "I1_truncated_capture",
    "J_tuple_reuse",
    "K_pcapng_nanosecond",
    "L_ipv6_connection",
    "M_midstream",
    "O_snapshot_truncated",
]


def _endpoint(value: str) -> tuple[str, int]:
    ip, _, port = value.rpartition(":")
    return ip.strip("[]"), int(port)


def _check_stream(stream: Any, expected: dict[str, Any], label: str) -> None:
    assert stream.bytes_reconstructed == expected["bytes_reconstructed"], f"{label}: byte count"
    assert stream.stream_base_sequence == expected["stream_base_sequence"], f"{label}: base seq"
    assert stream.base_status.value == expected["base_status"], f"{label}: base status"
    assert stream.packet_count == expected["packet_count"], f"{label}: packet count"
    assert stream.retransmission_count == expected["retransmission_count"], f"{label}: rtx"
    assert stream.duplicate_count == expected["duplicate_count"], f"{label}: dup"
    assert stream.out_of_order_count == expected["out_of_order_count"], f"{label}: ooo"

    # Runs: offsets, lengths and the exact content digest.
    assert len(stream.runs) == len(expected["runs"]), f"{label}: run count"
    for run, expected_run in zip(stream.runs, expected["runs"], strict=True):
        assert run.stream_offset == expected_run["stream_offset"], f"{label}: run offset"
        assert run.length == expected_run["length"], f"{label}: run length"
        content = bytes.fromhex(expected_run["content_hex"])
        assert run.sha256 == hashlib.sha256(content).hexdigest(), f"{label}: run content"

    # Gaps: boundaries, reason and the packets on either side.
    assert len(stream.gaps) == len(expected["gaps"]), f"{label}: gap count"
    for gap, expected_gap in zip(stream.gaps, expected["gaps"], strict=True):
        assert gap.stream_offset == expected_gap["stream_offset"], f"{label}: gap offset"
        assert gap.length == expected_gap["length"], f"{label}: gap length"
        assert gap.reason.value == expected_gap["reason"], f"{label}: gap reason"
        assert gap.content_status.value == "UNKNOWN", f"{label}: gap content status"
        preceding = gap.preceding_packet.packet_number if gap.preceding_packet else None
        following = gap.following_packet.packet_number if gap.following_packet else None
        assert preceding == expected_gap["preceding_packet"], f"{label}: gap predecessor"
        assert following == expected_gap["following_packet"], f"{label}: gap successor"

    # Overlap conflicts: both competing digests and both packet numbers.
    assert len(stream.overlap_conflicts) == len(expected["conflicts"]), f"{label}: conflicts"
    for conflict, expected_conflict in zip(
        stream.overlap_conflicts, expected["conflicts"], strict=True
    ):
        assert conflict.stream_offset == expected_conflict["stream_offset"]
        assert conflict.length == expected_conflict["length"]
        assert conflict.accepted_packet.packet_number == expected_conflict["accepted_packet"]
        assert (
            conflict.conflicting_packet.packet_number == expected_conflict["conflicting_packet"]
        )
        assert (
            conflict.accepted_sha256
            == hashlib.sha256(bytes.fromhex(expected_conflict["accepted_hex"])).hexdigest()
        )
        assert (
            conflict.conflicting_sha256
            == hashlib.sha256(bytes.fromhex(expected_conflict["conflicting_hex"])).hexdigest()
        )
        assert conflict.policy == "FIRST_OBSERVED_WINS"

    # Provenance: exact packet numbers, in stream-offset order.
    assert [segment.source.packet_number for segment in stream.segments] == expected[
        "segment_packets"
    ], f"{label}: segment provenance"

    for offset_key, packet_numbers in expected["duplicate_packets"].items():
        offset = int(offset_key)
        matching = [
            segment for segment in stream.segments if segment.stream_offset == offset
        ]
        assert matching, f"{label}: no segment at offset {offset}"
        assert [
            reference.packet_number for reference in matching[0].duplicates
        ] == packet_numbers, f"{label}: duplicate provenance at offset {offset}"


@pytest.mark.parametrize("fixture", RECONSTRUCTION_FIXTURES, indirect=True)
def test_sessions_match_manifest(fixture: Fixture) -> None:
    artifacts = analyze_capture_with_payloads(fixture.path)
    result = artifacts.result
    expected_sessions = fixture.expected_sessions

    assert len(result.sessions) == len(expected_sessions), "session count"

    for session, expected in zip(result.sessions, expected_sessions, strict=True):
        label = f"{fixture.name}/{session.session_id}"
        assert (session.flow.client.ip, session.flow.client.port) == _endpoint(
            expected["client"]
        ), f"{label}: client"
        assert (session.flow.server.ip, session.flow.server.port) == _endpoint(
            expected["server"]
        ), f"{label}: server"
        assert session.flow_instance == expected["flow_instance"], f"{label}: flow instance"
        assert session.packet_count == expected["packet_count"], f"{label}: packet count"
        assert session.completeness.value == expected["completeness"], f"{label}: completeness"
        assert session.handshake.complete == expected["handshake_complete"], f"{label}: hs"
        assert (
            session.termination.reason.value == expected["termination_reason"]
        ), f"{label}: termination"
        assert session.flow.role_status.value == expected["role_status"], f"{label}: roles"
        assert session.flow.role_basis == expected["role_basis"], f"{label}: role basis"
        assert session.first_packet.packet_number == expected["first_packet"]
        assert session.last_packet.packet_number == expected["last_packet"]

        if expected["protocol_hint"] is None:
            assert session.protocol_hint is None
        else:
            assert session.protocol_hint is not None
            assert session.protocol_hint.value == expected["protocol_hint"]
            assert session.protocol_hint.status.value == "INFERRED"

        _check_stream(session.client_to_server, expected["client_to_server"], f"{label}/c2s")
        _check_stream(session.server_to_client, expected["server_to_client"], f"{label}/s2c")


@pytest.mark.parametrize("fixture", RECONSTRUCTION_FIXTURES, indirect=True)
def test_reconstructed_bytes_equal_expected_bytes(fixture: Fixture) -> None:
    """Literal byte comparison against the manifest's expected content."""
    artifacts = analyze_capture_with_payloads(fixture.path)

    for session, expected in zip(
        artifacts.result.sessions, fixture.expected_sessions, strict=True
    ):
        for direction, key in (
            (Direction.CLIENT_TO_SERVER, "client_to_server"),
            (Direction.SERVER_TO_CLIENT, "server_to_client"),
        ):
            runs = artifacts.payload_runs[session.session_id, direction]
            expected_runs = expected[key]["runs"]
            assert len(runs) == len(expected_runs)
            for (offset, data), expected_run in zip(runs, expected_runs, strict=True):
                assert offset == expected_run["stream_offset"]
                assert data == bytes.fromhex(expected_run["content_hex"])


@pytest.mark.parametrize(
    "fixture", [*RECONSTRUCTION_FIXTURES, "N_unsupported_link_type"], indirect=True
)
def test_warning_codes_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture_with_payloads(fixture.path).result
    observed = {warning.code.value for warning in result.warnings}
    observed |= {
        warning.code.value for session in result.sessions for warning in session.warnings
    }
    assert observed == fixture.expected_warning_codes


def test_segmented_and_whole_payload_reconstruct_identically(
    fixtures: dict[str, Fixture],
) -> None:
    """Fixtures A, B and C carry the same bytes in different segmentations."""
    digests = set()
    for name in ("A_complete_connection", "B_segmented_payload", "C_out_of_order"):
        result = analyze_capture_with_payloads(fixtures[name].path).result
        digests.add(result.sessions[0].client_to_server.runs[0].sha256)
    assert len(digests) == 1, "segmentation and ordering must not change the byte stream"


def test_gaps_are_not_concatenated(fixtures: dict[str, Fixture]) -> None:
    """A stream with a hole must expose two runs, never one joined blob."""
    artifacts = analyze_capture_with_payloads(fixtures["F_missing_segment"].path)
    session = artifacts.result.sessions[0]
    runs = artifacts.payload_runs[session.session_id, Direction.CLIENT_TO_SERVER]
    assert len(runs) == 2
    assert runs[0][0] == 0
    assert runs[1][0] == 12
    assert session.client_to_server.contiguous is False
    joined = b"".join(data for _, data in runs)
    assert joined != b"EHLO client.example\r\n", "the gap must not be silently closed"


def test_overlap_conflict_keeps_the_first_observation(fixtures: dict[str, Fixture]) -> None:
    artifacts = analyze_capture_with_payloads(fixtures["H_overlap_conflict"].path)
    session = artifacts.result.sessions[0]
    runs = artifacts.payload_runs[session.session_id, Direction.CLIENT_TO_SERVER]
    assert len(runs) == 1
    assert runs[0][1] == b"A" * 10 + b"B" * 5
    conflict = session.client_to_server.overlap_conflicts[0]
    assert conflict.accepted_sha256 != conflict.conflicting_sha256


def test_retransmission_and_duplicate_are_distinguished(
    fixtures: dict[str, Fixture],
) -> None:
    duplicate = analyze_capture_with_payloads(
        fixtures["D_duplicate_segment"].path
    ).result.sessions[0]
    retransmission = analyze_capture_with_payloads(
        fixtures["E_retransmission"].path
    ).result.sessions[0]

    assert duplicate.client_to_server.duplicate_count == 1
    assert duplicate.client_to_server.retransmission_count == 0
    assert retransmission.client_to_server.duplicate_count == 0
    assert retransmission.client_to_server.retransmission_count == 1
    # Neither may inflate the reconstructed stream.
    assert duplicate.client_to_server.bytes_reconstructed == 21
    assert retransmission.client_to_server.bytes_reconstructed == 21
