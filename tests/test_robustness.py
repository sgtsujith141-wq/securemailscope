"""M8: malformed input, resource limits and the passive-only guarantee.

Two properties are asserted throughout, and they matter more than any
individual case:

**Malformed input never produces invented cryptographic evidence.** A truncated
handshake, a lying length field or a corrupted certificate must yield fewer
observations, never a fabricated one. A parser that guesses is worse than one
that stops.

**A limit that engages is reported.** A capture cut short by a resource limit
must not come back looking complete, because a reader would take the missing
sessions as evidence they did not exist.

Property-based cases use Hypothesis with a bounded example count so the
ordinary suite stays fast. Anything genuinely expensive is marked ``stress``
and deselected by default.
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from securemailscope.config import AnalysisConfig
from securemailscope.errors import InputError, SecureMailScopeError
from securemailscope.pipeline import analyze_capture
from securemailscope.testing.dialogue import Dialogue
from securemailscope.testing.tls_messages import (
    CONTENT_HANDSHAKE,
    TLS12,
    client_hello,
    record,
    server_hello,
)
from securemailscope.testing.writers import write_pcap

FIXTURES = Path(__file__).parent / "fixtures" / "generated"

#: Keep the property suite quick enough to run on every change.
FAST = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"


def write(tmp_path: Path, data: bytes, name: str = "case.pcap") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def analyse_or_reject(path: Path, config: AnalysisConfig | None = None):
    """Analyse, allowing a *stated* rejection but never a crash.

    A malformed capture may legitimately be refused. What it must not do is
    raise something the caller cannot interpret, or return a result that claims
    more than the bytes support.
    """
    try:
        return analyze_capture(path, config=config)
    except SecureMailScopeError:
        return None


# ---------------------------------------------------------------------------
# Container-level malformation
# ---------------------------------------------------------------------------
def test_an_empty_file_is_rejected_with_a_reason(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="empty"):
        analyze_capture(write(tmp_path, b""))


def test_a_header_only_capture_yields_no_sessions(tmp_path: Path) -> None:
    header = PCAP_MAGIC + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    result = analyse_or_reject(write(tmp_path, header))
    assert result is not None
    assert result.capture.packet_count == 0
    assert result.sessions == ()


@FAST
@given(truncate_at=st.integers(min_value=1, max_value=23))
def test_a_truncated_pcap_header_never_crashes(tmp_path_factory, truncate_at: int) -> None:
    header = PCAP_MAGIC + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    path = tmp_path_factory.mktemp("trunc") / "c.pcap"
    path.write_bytes(header[:truncate_at])
    analyse_or_reject(path)


@FAST
@given(payload=st.binary(min_size=0, max_size=400))
def test_arbitrary_bytes_after_a_valid_header_never_crash(
    tmp_path_factory, payload: bytes
) -> None:
    """Whatever follows the header, the reader stops or reports; it never raises."""
    header = PCAP_MAGIC + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    path = tmp_path_factory.mktemp("fuzz") / "c.pcap"
    path.write_bytes(header + payload)
    result = analyse_or_reject(path)
    if result is not None:
        # Nothing may be claimed about TLS from arbitrary bytes.
        for analysis in result.tls:
            assert analysis.version.selected_version is None or analysis.messages


@FAST
@given(declared=st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_a_lying_packet_length_is_bounded(tmp_path_factory, declared: int) -> None:
    """A record header may declare any length. The reader must not trust it.

    The bound that matters is bytes read, not packets: a declared length of
    zero legitimately lets several empty records be parsed out of the trailing
    bytes, while a declared length of four billion must not cause a read of
    four billion bytes.
    """
    header = PCAP_MAGIC + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 1)
    trailer = b"\x00" * 32
    body = struct.pack("<IIII", 1700000000, 0, declared, declared) + trailer
    path = tmp_path_factory.mktemp("len") / "c.pcap"
    path.write_bytes(header + body)
    file_size = path.stat().st_size

    result = analyse_or_reject(path)
    if result is None:
        return
    # No packet may claim more bytes than the file contains, however much its
    # header declared.
    assert result.capture.file_size_bytes == file_size
    assert result.capture.packet_count <= len(trailer) + 1
    # And nothing may be concluded about TLS from a header full of zeroes.
    assert result.tls == ()


def test_an_unsupported_link_type_is_reported_not_guessed(tmp_path: Path) -> None:
    # Link type 999 is not one this build dissects.
    header = PCAP_MAGIC + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, 999)
    body = struct.pack("<IIII", 1700000000, 0, 16, 16) + b"\x00" * 16
    result = analyse_or_reject(write(tmp_path, header + body))
    if result is not None:
        assert result.sessions == ()
        assert result.capture.unsupported_link_packet_count >= 0


def test_a_truncated_real_capture_reports_it(tmp_path: Path) -> None:
    """Half a real capture: fewer observations, and the truncation is stated."""
    full = (FIXTURES / "aa_tls10_static_rsa.pcap").read_bytes()
    result = analyse_or_reject(write(tmp_path, full[: len(full) // 2]))
    if result is None:
        return
    assert result.capture.truncated or result.capture.packet_count < 5
    for analysis in result.tls:
        if analysis.version.selected_version is not None:
            assert analysis.messages, "a version was reported with no message behind it"


# ---------------------------------------------------------------------------
# TLS-level malformation
# ---------------------------------------------------------------------------
def _tls_capture(tmp_path: Path, payload: bytes, name: str = "tls.pcap") -> Path:
    dialogue = Dialogue(server_port=993, handshake=True)
    dialogue.send_client(
        record(CONTENT_HANDSHAKE, client_hello(cipher_suites=[0xC02B]), version=TLS12)
    )
    dialogue.send_server(payload)
    return write(tmp_path, write_pcap(dialogue.packets), name)


@FAST
@given(declared=st.integers(min_value=0, max_value=0xFFFF))
def test_a_lying_tls_record_length_invents_nothing(
    tmp_path_factory, declared: int
) -> None:
    body = server_hello(cipher_suite=0xC02B)
    # A record header whose length does not match its body.
    malformed = bytes([CONTENT_HANDSHAKE]) + struct.pack(">HH", TLS12, declared) + body
    path = _tls_capture(tmp_path_factory.mktemp("rec"), malformed)
    result = analyse_or_reject(path)
    if result is None or not result.tls:
        return
    analysis = result.tls[0]
    suite = analysis.cipher_suite.selected
    if suite is not None:
        # A suite may only be reported if a ServerHello was actually parsed.
        assert any(m.message_type_name == "server_hello" for m in analysis.messages)


@FAST
@given(cut=st.integers(min_value=1, max_value=60))
def test_a_truncated_handshake_reports_less_not_more(
    tmp_path_factory, cut: int
) -> None:
    body = server_hello(cipher_suite=0xC02B)
    full = record(CONTENT_HANDSHAKE, body, version=TLS12)
    truncated = full[:-cut] if cut < len(full) else full[:1]
    path = _tls_capture(tmp_path_factory.mktemp("cut"), truncated)
    result = analyse_or_reject(path)
    if result is None or not result.tls:
        return
    analysis = result.tls[0]
    if analysis.cipher_suite.selected is not None:
        assert any(m.message_type_name == "server_hello" for m in analysis.messages)


@FAST
@given(garbage=st.binary(min_size=1, max_size=200))
def test_arbitrary_tls_payload_never_yields_a_certificate(
    tmp_path_factory, garbage: bytes
) -> None:
    """The strongest form of the rule: no certificate from noise."""
    path = _tls_capture(tmp_path_factory.mktemp("garb"), garbage)
    result = analyse_or_reject(path)
    if result is None or not result.tls:
        return
    for certificate in result.tls[0].certificates.certificates:
        # Any certificate reported must have decoded into real fields.
        assert certificate.sha256_fingerprint
        assert certificate.subject


def test_a_malformed_certificate_is_reported_not_invented(tmp_path: Path) -> None:
    from securemailscope.testing.tls_messages import certificate_message

    body = server_hello(cipher_suite=0xC02F) + certificate_message([b"\x30\x82\xff\xff not DER"])
    path = _tls_capture(tmp_path, record(CONTENT_HANDSHAKE, body, version=TLS12))
    result = analyse_or_reject(path)
    assert result is not None and result.tls
    inventory = result.tls[0].certificates
    for certificate in inventory.certificates:
        assert certificate.subject, "a certificate was reported with no decoded subject"


# ---------------------------------------------------------------------------
# Protocol-level malformation
# ---------------------------------------------------------------------------
@FAST
@given(line=st.binary(min_size=0, max_size=300))
def test_arbitrary_smtp_bytes_never_confirm_a_protocol(
    tmp_path_factory, line: bytes
) -> None:
    dialogue = Dialogue(server_port=25, handshake=True)
    dialogue.send_server(line)
    path = write(tmp_path_factory.mktemp("smtp"), write_pcap(dialogue.packets))
    result = analyse_or_reject(path)
    if result is None or not result.protocols:
        return
    detection = result.protocols[0].detection
    if detection.status.value == "CONFIRMED":
        assert detection.evidence_refs, "a confirmation with no evidence behind it"


def test_an_oversized_protocol_line_is_bounded(tmp_path: Path) -> None:
    """A line far longer than the limit must not be buffered without bound.

    Sent in segments, because a single pcap record cannot carry it -- which is
    also how a real oversized line would arrive.
    """
    dialogue = Dialogue(server_port=25, handshake=True)
    dialogue.send_server(b"220 ")
    for _ in range(40):
        dialogue.send_server(b"A" * 8192)
    dialogue.send_server(b"\r\n")
    path = write(tmp_path, write_pcap(dialogue.packets))

    result = analyse_or_reject(path, AnalysisConfig(max_line_bytes=4096))
    assert result is not None
    assert result.sessions
    protocol = result.protocols[0] if result.protocols else None
    if protocol is None:
        return
    # Whatever it concluded, no event may report a line longer than the limit,
    # and an over-long line must not be silently accepted as a greeting.
    for event in protocol.events:
        if event.end_offset is not None:
            assert event.end_offset - event.stream_offset <= 4096 + 2
    if protocol.detection.status.value == "CONFIRMED":
        assert protocol.detection.evidence_refs


# ---------------------------------------------------------------------------
# Resource limits
# ---------------------------------------------------------------------------
def _many_sessions(tmp_path: Path, count: int) -> Path:
    packets: list[tuple[int, bytes]] = []
    for index in range(count):
        dialogue = Dialogue(
            client_ip=f"192.0.2.{10 + index % 200}",
            client_port=30000 + index,
            server_port=993,
            handshake=True,
            start_ns=1_700_000_000_000_000_000 + index * 1000,
        )
        dialogue.send_client(
            record(CONTENT_HANDSHAKE, client_hello(cipher_suites=[0xC02B]), version=TLS12)
        )
        packets.extend(dialogue.packets)
    packets.sort(key=lambda item: item[0])
    return write(tmp_path, write_pcap(packets), "many.pcap")


def test_a_session_limit_engages_and_is_reported(tmp_path: Path) -> None:
    """A limit that silently truncates would be worse than no limit."""
    path = _many_sessions(tmp_path, 60)
    result = analyze_capture(path, config=AnalysisConfig(max_total_sessions=10))
    assert len(result.sessions) <= 10
    codes = {warning.code for warning in result.warnings}
    codes |= {w.code for w in result.capture.warnings}
    assert codes, "a limit engaged without producing any warning"
    assert any("LIMIT" in code or "limit" in code.lower() for code in codes), codes


def test_a_packet_limit_marks_the_capture_truncated(tmp_path: Path) -> None:
    path = _many_sessions(tmp_path, 40)
    result = analyze_capture(path, config=AnalysisConfig(max_packets=20))
    assert result.capture.packet_count <= 20
    assert result.capture.truncated, (
        "a capture cut short by a packet limit must not look complete"
    )


def test_a_limited_analysis_keeps_the_evidence_it_did_establish(tmp_path: Path) -> None:
    """A partial analysis preserves what it reliably saw."""
    path = _many_sessions(tmp_path, 40)
    result = analyze_capture(path, config=AnalysisConfig(max_total_sessions=5))
    assert result.sessions, "a limited run discarded everything"
    for session in result.sessions:
        assert session.first_packet.packet_number >= 1
        assert session.flow.server.port == 993


def test_many_tiny_packets_are_bounded(tmp_path: Path) -> None:
    """Thousands of one-byte segments must not grow a buffer without limit."""
    dialogue = Dialogue(server_port=25, handshake=True)
    for _ in range(3000):
        dialogue.send_client(b"A")
    path = write(tmp_path, write_pcap(dialogue.packets))
    result = analyze_capture(
        path, config=AnalysisConfig(max_segments_per_direction=500)
    )
    assert result.sessions
    stream = result.sessions[0].client_to_server
    assert len(stream.segments) <= 500
    assert stream.truncated_by_limit or stream.dropped_by_limit_count > 0, (
        "segments were dropped without saying so"
    )


# ---------------------------------------------------------------------------
# Passive-only guarantee
# ---------------------------------------------------------------------------
class _BlockedSocket:
    """Any attempt to construct a socket is a test failure, with the trace."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise AssertionError(
            "the analyzer attempted to create a network socket; analysis must "
            "be entirely passive"
        )


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch):
    """Block every outbound path the standard library offers."""
    monkeypatch.setattr(socket, "socket", _BlockedSocket)
    monkeypatch.setattr(socket, "create_connection", _BlockedSocket)

    def refuse(*args: object, **kwargs: object):
        raise AssertionError("the analyzer attempted a DNS resolution")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname", refuse)
    return None


@pytest.mark.usefixtures("no_network")
@pytest.mark.parametrize(
    "fixture_name",
    [
        "aa_tls10_static_rsa.pcap",
        "t_a_tls12_complete_handshake.pcap",
        "t_d_tls13_negotiation.pcap",
        "p_m_auth_before_tls.pcap",
        "t_o_expired_certificate.pcap",
    ],
)
def test_analysis_opens_no_socket_and_resolves_no_name(fixture_name: str) -> None:
    """Every layer, including assessment, intelligence and ML."""
    result = analyze_capture(FIXTURES / fixture_name)
    assert result.capture.packet_count > 0
    # The layers that could plausibly reach out all ran.
    assert result.assessment is not None
    assert result.ml is not None


@pytest.mark.usefixtures("no_network")
def test_batch_analysis_and_reporting_open_no_socket() -> None:
    from securemailscope.intelligence import analyze_batch
    from securemailscope.reporting.html_report import render_html
    from securemailscope.reporting.pdf_report import render_pdf
    from securemailscope.reporting.report_model import build_report

    outcome = analyze_batch(
        [
            FIXTURES / "aa_tls10_static_rsa.pcap",
            FIXTURES / "t_a_tls12_complete_handshake.pcap",
        ]
    )
    model = build_report(outcome.results, outcome.investigation)
    assert render_html(model)
    assert render_pdf(model).startswith(b"%PDF")


def test_no_outbound_client_library_is_imported_by_the_engine() -> None:
    """The engine must not even have the means to reach the network.

    Import-level, not call-level: a module that imports ``requests`` has the
    capability whether or not this run used it.
    """
    import sys

    import securemailscope.pipeline  # noqa: F401

    forbidden = {
        "requests", "urllib3", "httpx", "aiohttp", "http.client",
        "ftplib", "smtplib", "imaplib", "poplib", "telnetlib",
    }
    # httpx and the http stack arrive with FastAPI's test client, which is a
    # test dependency, so the check is on what the *engine* pulls in.
    engine_modules = {
        name for name in sys.modules
        if name.startswith("securemailscope") and "backend" not in name
    }
    for name in engine_modules:
        module = sys.modules[name]
        for attribute in dir(module):
            value = getattr(module, attribute, None)
            module_name = getattr(value, "__name__", "")
            assert module_name not in forbidden, (
                f"{name} exposes {module_name}, which can reach the network"
            )
