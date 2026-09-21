"""JSON report contract: serialisable, provenanced, and free of payload bytes."""

from __future__ import annotations

import json
from pathlib import Path

from securemailscope import analyze_capture
from securemailscope.reporting.json_report import (
    result_to_dict,
    result_to_json,
    write_json_report,
)

from .conftest import Fixture

#: Byte sequences that appear in fixture payloads and must never reach a report.
PAYLOAD_MARKERS = (
    "EHLO client.example",
    "250-mail.example",
    "a001 CAPABILITY",
    "HELO one",
    "FIRST",
    "SECOND",
)


def test_report_is_valid_json_and_round_trips(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["A_complete_connection"].path)
    text = result_to_json(result)
    parsed = json.loads(text)
    assert parsed["capture"]["capture_id"].startswith("sha256:")
    assert parsed["tool"]["passive_only"] is True
    assert parsed["inventory"]["session_count"] == 1


def test_report_never_contains_payload_bytes(fixtures: dict[str, Fixture]) -> None:
    for name in ("A_complete_connection", "G_two_connections", "J_tuple_reuse"):
        text = result_to_json(analyze_capture(fixtures[name].path))
        for marker in PAYLOAD_MARKERS:
            assert marker not in text, f"{name}: payload text {marker!r} leaked into the report"
        # Nor the hex or base64 of a payload.
        assert b"EHLO".hex() not in text


def test_report_carries_packet_provenance(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["B_segmented_payload"].path)
    data = result_to_dict(result)
    segments = data["sessions"][0]["client_to_server"]["segments"]
    assert [segment["source"]["packet_number"] for segment in segments] == [4, 5, 6]
    for segment in segments:
        assert segment["source"]["timestamp"].endswith("Z") or "+00:00" in (
            segment["source"]["timestamp"]
        )
        assert isinstance(segment["source"]["timestamp_ns"], int)


def test_report_declares_stage_status_honestly(fixtures: dict[str, Fixture]) -> None:
    """Stage status must track what is actually built.

    Updated in M2: ``EMAIL_PROTOCOL_PARSING`` and ``STARTTLS_DETECTION`` are
    now implemented, so the assertion changed deliberately. ``TLS_ANALYSIS``
    and ``CERTIFICATE_ASSESSMENT`` must stay NOT_IMPLEMENTED until M3.
    """
    data = result_to_dict(analyze_capture(fixtures["A_complete_connection"].path))
    status = data["stage_status"]
    assert status["CAPTURE_INGESTION"] == "IMPLEMENTED"
    assert status["TCP_REASSEMBLY"] == "IMPLEMENTED"
    assert status["EMAIL_PROTOCOL_PARSING"] == "IMPLEMENTED"
    assert status["STARTTLS_DETECTION"] == "IMPLEMENTED"
    # Framing only: enough to bound TLS bytes, not to parse them.
    assert status["TLS_RECORD_FRAMING"] == "IMPLEMENTED"
    # M3 analyses only what a passive capture can show; nothing is decrypted.
    assert status["TLS_ANALYSIS"] == "PARTIAL"
    assert status["CERTIFICATE_REVOCATION"] == "NOT_IMPLEMENTED"
    assert status["CERTIFICATE_ASSESSMENT"] == "NOT_IMPLEMENTED"
    assert data["tool"]["report_schema_version"] == "1.2.0"
    # No fabricated cryptographic findings anywhere in the document. This is
    # now a structural check rather than a substring one: the prose legitimately
    # mentions certificates in order to say they are NOT analysed, so what must
    # be absent is a *field claiming a value*, not the word.
    assert _keys_matching(data, {"cipher_suite", "certificate", "tls_version",
                                 "negotiated_cipher", "certificate_chain",
                                 "subject", "issuer", "not_after"}) == []
    assert data["protocol_inventory"]["tls_handshakes_analysed"] == 0
    # This capture carries no TLS at all, so no cryptographic claim may appear.
    assert data["tls"] == []
    assert data["tls_inventory"]["handshakes_cryptographically_verified"] == 0
    assert data["tls_inventory"]["revocation_checks_performed"] == 0
    for analysis in data["protocols"]:
        upgrade = analysis.get("upgrade")
        if upgrade is not None:
            assert upgrade["handshake_analyzed"] is False
            assert upgrade["negotiated_parameters_available"] is False
            assert upgrade["handshake_analysis_status"] == "NOT_IMPLEMENTED"


def _keys_matching(node: object, forbidden: set[str], path: str = "") -> list[str]:
    """Every path in a nested structure whose key is in ``forbidden``."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            where = f"{path}.{key}"
            if key in forbidden:
                found.append(where)
            found.extend(_keys_matching(value, forbidden, where))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_keys_matching(value, forbidden, f"{path}[{index}]"))
    return found


def test_report_echoes_the_limits_in_force(fixtures: dict[str, Fixture]) -> None:
    data = result_to_dict(analyze_capture(fixtures["A_complete_connection"].path))
    assert data["limits"]["max_packets"] > 0
    assert data["limits"]["max_session_payload_bytes"] > 0


def test_no_segments_option_drops_only_segments(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["F_missing_segment"].path)
    data = result_to_dict(result, include_segments=False)
    stream = data["sessions"][0]["client_to_server"]
    assert "segments" not in stream
    assert len(stream["runs"]) == 2
    assert len(stream["gaps"]) == 1


def test_write_json_report_creates_the_file(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    result = analyze_capture(fixtures["A_complete_connection"].path)
    destination = tmp_path / "nested" / "report.json"
    written = write_json_report(result, destination)
    assert written.is_file()
    assert json.loads(written.read_text())["capture"]["source_name"] == (
        "a_complete_connection.pcap"
    )


def test_report_records_only_the_file_name_not_the_path(
    fixtures: dict[str, Fixture],
) -> None:
    """A report must not leak where the analyst keeps their captures."""
    result = analyze_capture(fixtures["A_complete_connection"].path)
    text = result_to_json(result)
    assert str(fixtures["A_complete_connection"].path.parent) not in text
    assert result.capture.source_name == "a_complete_connection.pcap"
