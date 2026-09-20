"""Capture ingestion: validation, packet numbering, timestamps and limits."""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope import analyze_capture
from securemailscope.config import AnalysisConfig
from securemailscope.diagnostics import WarningSink
from securemailscope.errors import (
    CaptureNotFoundError,
    CaptureTooLargeError,
    MalformedCaptureError,
    UnsupportedCaptureFormatError,
)
from securemailscope.ingestion.reader import open_capture
from securemailscope.models.evidence import WarningCode
from securemailscope.testing.writers import write_pcap

from .conftest import Fixture

ALL_READABLE = [
    "A_complete_connection",
    "B_segmented_payload",
    "C_out_of_order",
    "D_duplicate_segment",
    "E_retransmission",
    "F_missing_segment",
    "G_two_connections",
    "H_overlap_conflict",
    "I1_truncated_capture",
    "I3_header_only",
    "J_tuple_reuse",
    "K_pcapng_nanosecond",
    "L_ipv6_connection",
    "M_midstream",
    "N_unsupported_link_type",
    "O_snapshot_truncated",
]


@pytest.mark.parametrize("fixture", ALL_READABLE, indirect=True)
def test_packet_counts_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    assert result.capture.packet_count == fixture.manifest["expected_packet_count"]
    assert result.capture.tcp_packet_count == fixture.manifest["expected_tcp_packet_count"]


@pytest.mark.parametrize("fixture", ALL_READABLE, indirect=True)
def test_capture_id_is_the_sha256_of_the_file(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    assert result.capture.capture_id == "sha256:" + fixture.manifest["capture_sha256"]
    assert result.capture.file_size_bytes == fixture.manifest["file_size_bytes"]


@pytest.mark.parametrize("fixture", ALL_READABLE, indirect=True)
def test_packet_numbering_and_timestamps_are_exact(fixture: Fixture) -> None:
    """Every packet must keep its capture-order number and its exact timestamp."""
    expected = fixture.manifest["expected_timestamps_ns"]
    sink = WarningSink()
    source = open_capture(fixture.path, config=AnalysisConfig(), sink=sink)
    observed = [(frame.packet_number, frame.timestamp_ns) for frame in source.frames()]

    assert [number for number, _ in observed] == list(range(1, len(expected) + 1))
    assert [timestamp for _, timestamp in observed] == expected


def test_pcapng_preserves_nanosecond_precision(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["K_pcapng_nanosecond"]
    result = analyze_capture(fixture.path)
    assert result.capture.file_format.value == "PCAPNG"
    # The generator offsets every timestamp by 987 ns; a microsecond-truncating
    # reader would lose exactly this.
    assert result.capture.first_packet_timestamp_ns is not None
    assert result.capture.first_packet_timestamp_ns % 1000 == 987
    assert result.sessions[0].first_packet.timestamp_ns % 1000 == 987


def test_pcap_and_pcapng_of_the_same_traffic_agree(fixtures: dict[str, Fixture]) -> None:
    pcap = analyze_capture(fixtures["A_complete_connection"].path)
    pcapng = analyze_capture(fixtures["K_pcapng_nanosecond"].path)
    assert pcap.capture.packet_count == pcapng.capture.packet_count
    assert len(pcap.sessions) == len(pcapng.sessions)
    for left, right in zip(pcap.sessions, pcapng.sessions, strict=True):
        assert left.client_to_server.bytes_reconstructed == (
            right.client_to_server.bytes_reconstructed
        )
        assert left.client_to_server.runs[0].sha256 == right.client_to_server.runs[0].sha256
        assert left.completeness is right.completeness


def test_timestamps_are_timezone_aware(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["A_complete_connection"].path)
    assert result.capture.first_packet_timestamp is not None
    assert result.capture.first_packet_timestamp.tzinfo is not None
    assert result.sessions[0].first_packet.timestamp.tzinfo is not None


# -- rejection paths ---------------------------------------------------------
def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CaptureNotFoundError):
        analyze_capture(tmp_path / "nope.pcap")


def test_directory_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(CaptureNotFoundError):
        analyze_capture(tmp_path)


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(MalformedCaptureError):
        analyze_capture(path)


def test_non_capture_contents_are_rejected(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["I2_not_a_capture"]
    assert fixture.manifest["expected_error"] == "UnsupportedCaptureFormatError"
    with pytest.raises(UnsupportedCaptureFormatError):
        analyze_capture(fixture.path)


def test_oversized_capture_is_rejected_before_parsing(
    fixtures: dict[str, Fixture],
) -> None:
    fixture = fixtures["A_complete_connection"]
    config = AnalysisConfig(max_capture_bytes=10)
    with pytest.raises(CaptureTooLargeError):
        analyze_capture(fixture.path, config=config)


def test_truncated_capture_yields_partial_results_not_an_exception(
    fixtures: dict[str, Fixture],
) -> None:
    fixture = fixtures["I1_truncated_capture"]
    result = analyze_capture(fixture.path)
    assert result.capture.truncated is True
    assert result.capture.packet_count == 3
    assert len(result.sessions) == 1
    codes = {warning.code for warning in result.capture.warnings}
    assert WarningCode.TRUNCATED_CAPTURE_FILE in codes


def test_header_only_capture_produces_no_sessions(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["I3_header_only"].path)
    assert result.capture.packet_count == 0
    assert result.sessions == ()
    assert result.inventory.session_count == 0


def test_unsupported_link_type_produces_a_diagnostic_not_a_session(
    fixtures: dict[str, Fixture],
) -> None:
    result = analyze_capture(fixtures["N_unsupported_link_type"].path)
    assert result.capture.packet_count == 1
    assert result.capture.tcp_packet_count == 0
    assert result.sessions == ()
    codes = {warning.code for warning in result.warnings}
    assert WarningCode.UNSUPPORTED_LINK_TYPE in codes
    assert result.capture.interfaces[0].link_type.value == "UNSUPPORTED"


# -- bounded resource behaviour ---------------------------------------------
def test_packet_count_limit_stops_parsing(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["A_complete_connection"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_packets=4))
    assert result.capture.packet_count == 4
    assert result.capture.truncated is True
    assert WarningCode.LIMIT_PACKET_COUNT in {w.code for w in result.capture.warnings}


def test_packet_size_limit_stops_parsing(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["A_complete_connection"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_packet_bytes=20))
    assert result.capture.packet_count == 0
    assert result.capture.truncated is True
    assert WarningCode.LIMIT_PACKET_BYTES in {w.code for w in result.capture.warnings}


def test_session_payload_limit_truncates_rather_than_dropping(
    fixtures: dict[str, Fixture],
) -> None:
    fixture = fixtures["A_complete_connection"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_session_payload_bytes=10))
    session = result.sessions[0]
    assert session.completeness.value == "TRUNCATED"
    assert session.client_to_server.bytes_reconstructed == 10
    assert session.client_to_server.truncated_by_limit is True
    # The prefix that was reconstructed is still genuine.
    assert session.client_to_server.runs[0].length == 10
    codes = {warning.code for warning in session.warnings}
    assert WarningCode.LIMIT_SESSION_PAYLOAD_BYTES in codes


def test_total_payload_limit_is_enforced_across_sessions(
    fixtures: dict[str, Fixture],
) -> None:
    fixture = fixtures["G_two_connections"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_total_payload_bytes=12))
    total = sum(
        session.client_to_server.bytes_reconstructed
        + session.server_to_client.bytes_reconstructed
        for session in result.sessions
    )
    assert total == 12


def test_concurrent_session_limit_refuses_new_connections(
    fixtures: dict[str, Fixture],
) -> None:
    fixture = fixtures["G_two_connections"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_concurrent_sessions=1))
    assert len(result.sessions) == 1
    assert WarningCode.LIMIT_CONCURRENT_SESSIONS in {w.code for w in result.warnings}


def test_segment_limit_is_enforced(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["B_segmented_payload"]
    result = analyze_capture(fixture.path, config=AnalysisConfig(max_segments_per_direction=2))
    session = result.sessions[0]
    assert session.completeness.value == "TRUNCATED"
    assert session.client_to_server.truncated_by_limit is True
    assert WarningCode.LIMIT_SEGMENTS_PER_DIRECTION in {w.code for w in session.warnings}


def test_absurd_declared_packet_length_does_not_allocate(tmp_path: Path) -> None:
    """A corrupt incl_len must be refused on the header, before any read."""
    data = bytearray(write_pcap([(1_700_000_000_000_000_000, bytes(60))]))
    # Overwrite incl_len of the first record with 4 GiB - 1.
    data[24 + 8 : 24 + 12] = (0xFFFFFFFF).to_bytes(4, "little")
    path = tmp_path / "corrupt.pcap"
    path.write_bytes(bytes(data))
    result = analyze_capture(path)
    assert result.capture.packet_count == 0
    assert result.capture.truncated is True
