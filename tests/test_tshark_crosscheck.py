"""Optional cross-validation against TShark.

An independent implementation reading the same fixture is the strongest check
that our parsing matches reality rather than matching our own assumptions.
TShark is *not* required to run the test suite: these tests are skipped unless
both of the following hold.

* ``tshark`` is on ``PATH``
* ``SECUREMAILSCOPE_TSHARK=1`` is set

The opt-in switch exists because invoking an external binary during an ordinary
test run is exactly the kind of implicit dependency this project avoids. TShark
runs strictly offline here (``-r`` on a local file, ``-n`` to disable name
resolution), so no network access is involved either way.

Deviations found by these tests must be recorded in
``docs/milestones/M2-REPORT.md`` rather than worked around.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from securemailscope import analyze_capture

from .conftest import Fixture

TSHARK = shutil.which("tshark")
ENABLED = os.environ.get("SECUREMAILSCOPE_TSHARK") == "1"

pytestmark = pytest.mark.skipif(
    not (TSHARK and ENABLED),
    reason=(
        "TShark cross-check is opt-in: install tshark and set "
        "SECUREMAILSCOPE_TSHARK=1 to enable it"
    ),
)


def _tshark(*args: str) -> str:
    assert TSHARK is not None
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, local file only
        [TSHARK, "-n", *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return completed.stdout


def test_packet_count_agrees(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["P_A_smtp_starttls_accepted"]
    output = _tshark("-r", str(fixture.path), "-T", "fields", "-e", "frame.number")
    tshark_count = len([line for line in output.splitlines() if line.strip()])
    assert analyze_capture(fixture.path).capture.packet_count == tshark_count


def test_tcp_stream_count_agrees(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["P_A_smtp_starttls_accepted"]
    output = _tshark(
        "-r", str(fixture.path), "-T", "fields", "-e", "tcp.stream", "-Y", "tcp"
    )
    streams = {line.strip() for line in output.splitlines() if line.strip()}
    assert len(analyze_capture(fixture.path).sessions) == len(streams)


def test_smtp_starttls_command_is_seen_by_both(fixtures: dict[str, Fixture]) -> None:
    """TShark's SMTP dissector must agree that STARTTLS was requested."""
    fixture = fixtures["P_A_smtp_starttls_accepted"]
    output = _tshark(
        "-r",
        str(fixture.path),
        "-Y",
        "smtp.req.command == \"STARTTLS\"",
        "-T",
        "fields",
        "-e",
        "frame.number",
    )
    tshark_frames = {int(line) for line in output.splitlines() if line.strip()}
    assert tshark_frames, "TShark did not identify a STARTTLS command"

    analysis = analyze_capture(fixture.path).protocols[0]
    assert analysis.upgrade is not None
    assert analysis.upgrade.requested is not None
    ours = {ref.packet_number for ref in analysis.upgrade.requested.packet_refs}
    assert ours & tshark_frames, (
        f"STARTTLS request frames disagree: ours {sorted(ours)}, "
        f"TShark {sorted(tshark_frames)}"
    )


def test_pop3_and_imap_detection_agree(fixtures: dict[str, Fixture]) -> None:
    for name, display_filter in (
        ("P_F_pop3_stls_accepted", "pop"),
        ("P_D_imap_starttls_accepted", "imap"),
    ):
        fixture = fixtures[name]
        output = _tshark(
            "-r", str(fixture.path), "-Y", display_filter, "-T", "fields", "-e", "frame.number"
        )
        assert [line for line in output.splitlines() if line.strip()], (
            f"TShark did not dissect {name} as {display_filter}"
        )
        analysis = analyze_capture(fixture.path).protocols[0]
        assert analysis.detection.protocol.value == display_filter.upper().replace(
            "POP", "POP3"
        )


def test_json_export_matches_our_session_endpoints(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["P_D_imap_starttls_accepted"]
    output = _tshark("-r", str(fixture.path), "-T", "json", "-c", "1")
    first = json.loads(output)[0]["_source"]["layers"]
    session = analyze_capture(fixture.path).sessions[0]
    assert first["ip"]["ip.src"] == session.flow.client.ip
    assert first["ip"]["ip.dst"] == session.flow.server.ip
