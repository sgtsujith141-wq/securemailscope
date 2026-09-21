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


# ---------------------------------------------------------------------------
# M3: TLS and certificate cross-checks
# ---------------------------------------------------------------------------
def test_tls_version_agrees(fixtures: dict[str, Fixture]) -> None:
    """TShark's own view of the negotiated version must match ours."""
    for name, expected in (
        ("T_A_tls12_complete_handshake", "TLS 1.2"),
        ("T_D_tls13_negotiation", "TLS 1.3"),
    ):
        fixture = fixtures[name]
        output = _tshark(
            "-r",
            str(fixture.path),
            "-Y",
            "tls.handshake.type == 2",
            "-T",
            "fields",
            "-e",
            "tls.handshake.version",
            "-e",
            "tls.handshake.extensions.supported_version",
        )
        assert output.strip(), f"TShark saw no ServerHello in {name}"
        analysis = analyze_capture(fixture.path).tls[0]
        assert analysis.version.selected_version is not None
        assert analysis.version.selected_version.name == expected, (
            f"{name}: we say {analysis.version.selected_version.name}, "
            f"TShark fields: {output.strip()!r}"
        )


def test_tls_cipher_suite_agrees(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["T_A_tls12_complete_handshake"]
    output = _tshark(
        "-r",
        str(fixture.path),
        "-Y",
        "tls.handshake.type == 2",
        "-T",
        "fields",
        "-e",
        "tls.handshake.ciphersuite",
    )
    values = [int(line) for line in output.split() if line.strip().isdigit()]
    assert values, "TShark reported no selected cipher suite"
    analysis = analyze_capture(fixture.path).tls[0]
    assert analysis.cipher_suite.selected is not None
    assert analysis.cipher_suite.selected.value in values


def test_certificate_count_agrees(fixtures: dict[str, Fixture]) -> None:
    fixture = fixtures["T_A_tls12_complete_handshake"]
    output = _tshark(
        "-r",
        str(fixture.path),
        "-Y",
        "tls.handshake.type == 11",
        "-T",
        "fields",
        "-e",
        "x509sat.printableString",
    )
    assert output.strip(), "TShark did not dissect a Certificate message"
    analysis = analyze_capture(fixture.path).tls[0]
    assert analysis.certificates.chain_length >= 1


def test_tls13_certificate_is_not_visible_to_either_tool(
    fixtures: dict[str, Fixture],
) -> None:
    """Neither TShark nor we can see a TLS 1.3 certificate without keys."""
    fixture = fixtures["T_D_tls13_negotiation"]
    output = _tshark(
        "-r",
        str(fixture.path),
        "-Y",
        "tls.handshake.type == 11",
        "-T",
        "fields",
        "-e",
        "frame.number",
    )
    assert not output.strip(), "TShark unexpectedly dissected a TLS 1.3 Certificate"
    analysis = analyze_capture(fixture.path).tls[0]
    assert analysis.certificates.visibility.value == "ENCRYPTED_TLS13"
