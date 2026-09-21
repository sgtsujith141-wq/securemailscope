"""Targeted behavioural tests for the protocol state machines.

These build small dialogues inline rather than going through the fixture
manifests, so each one isolates a single rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope import AnalysisConfig, analyze_capture
from securemailscope.models.analysis import AnalysisResult
from securemailscope.reporting.json_report import result_to_json
from securemailscope.testing.dialogue import Dialogue
from securemailscope.testing.tls_blobs import client_hello, server_hello
from securemailscope.testing.writers import write_pcap

GREETING = b"220 mail.example ESMTP ready\r\n"
EHLO_TLS = b"250-mail.example Hello\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 HELP\r\n"
READY = b"220 2.0.0 Ready to start TLS\r\n"


def _analyze(
    dialogue: Dialogue, tmp_path: Path, *, config: AnalysisConfig | None = None
) -> AnalysisResult:
    path = tmp_path / "inline.pcap"
    path.write_bytes(write_pcap(dialogue.packets))
    return analyze_capture(path, config=config)


# -- command/response matching ----------------------------------------------
def test_pipelined_commands_are_matched_to_the_right_replies(tmp_path: Path) -> None:
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\nSTARTTLS\r\n")  # both in one segment
    d.send_server(b"250 Hello\r\n")  # answers EHLO
    d.send_server(READY)  # answers STARTTLS
    d.send_client(client_hello())

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.upgrade is not None
    assert analysis.upgrade.state.value == "TLS_BYTES_OBSERVED"
    assert analysis.upgrade.response_code == "220"


def test_a_220_answering_an_earlier_command_does_not_accept_starttls(
    tmp_path: Path,
) -> None:
    """The core anti-confusion rule: replies belong to the command they answer."""
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\nSTARTTLS\r\n")
    # Only ONE reply arrives. It answers EHLO, which is at the head of the
    # queue -- it must not be read as accepting the later STARTTLS, even
    # though its code happens to be 220.
    d.send_server(b"220 Hello, this answers EHLO\r\n")
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.upgrade is not None
    assert analysis.upgrade.state.value == "UPGRADE_REQUESTED"
    assert analysis.upgrade.response_code is None
    assert analysis.upgrade.server_boundary is None
    types = {event.event_type.value for event in analysis.events}
    assert "UPGRADE_ACCEPTED" not in types


def test_imap_untagged_ok_does_not_complete_a_command(tmp_path: Path) -> None:
    d = Dialogue(server_port=143)
    d.send_server(b"* OK IMAP4rev1 Service Ready\r\n")
    d.send_client(b"a001 STARTTLS\r\n")
    d.send_server(b"* OK Begin TLS negotiation now\r\n")  # untagged: not a completion
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.upgrade is not None
    assert analysis.upgrade.state.value == "UPGRADE_REQUESTED"


def test_smtp_354_does_not_complete_the_data_command(tmp_path: Path) -> None:
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(b"250 Hello\r\n")
    d.send_client(b"DATA\r\n")
    d.send_server(b"354 Go ahead\r\n")
    d.send_client(b"Subject: x\r\n\r\nbody\r\n.\r\n")
    d.send_server(b"250 2.0.0 Queued\r\n")  # this completes DATA
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.parse_state.value == "COMPLETE"
    body_events = [
        event for event in analysis.events if event.event_type.value == "MESSAGE_BODY_SKIPPED"
    ]
    assert len(body_events) == 1
    assert body_events[0].byte_count == len(b"Subject: x\r\n\r\nbody\r\n.\r\n")


# -- malformed input ---------------------------------------------------------
def test_malformed_server_reply_is_reported_not_crashed(tmp_path: Path) -> None:
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(b"this is not an smtp reply at all\r\n")
    d.send_server(b"25O Hello\r\n")  # letter O, not a digit
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    types = [event.event_type.value for event in analysis.events]
    assert types.count("PARSE_DESYNCHRONISED") >= 2
    assert analysis.detection.protocol.value == "SMTP"


def test_reply_code_followed_by_neither_space_nor_hyphen_is_rejected(
    tmp_path: Path,
) -> None:
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(b"250xHello\r\n")
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert any(
        event.event_type.value == "PARSE_DESYNCHRONISED" for event in analysis.events
    )


def test_unrecognised_command_token_is_not_echoed(tmp_path: Path) -> None:
    """An unknown token in command position may be a credential; never report it."""
    secret = b"Zm9vOmJhcnNlY3JldA=="
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(secret + b"\r\n")
    d.close()

    result = _analyze(d, tmp_path)
    assert secret.decode() not in result_to_json(result)
    analysis = result.protocols[0]
    for event in analysis.events:
        assert event.command_verb != secret.decode()


# -- bounds ------------------------------------------------------------------
def test_oversized_imap_literal_stops_parsing(tmp_path: Path) -> None:
    d = Dialogue(server_port=143)
    d.send_server(b"* OK IMAP4rev1 Service Ready\r\n")
    d.send_client(b"a001 APPEND INBOX {99999999+}\r\n")
    d.send_client(b"a002 STARTTLS\r\n")
    d.close()

    config = AnalysisConfig(max_literal_bytes=1024)
    analysis = _analyze(d, tmp_path, config=config).protocols[0]
    assert analysis.parse_state.value == "INDETERMINATE"
    assert "LIMIT_LITERAL_BYTES" in {warning.code.value for warning in analysis.warnings}
    # Nothing after the oversized literal is interpreted.
    assert analysis.upgrade is None


def test_oversized_data_body_stops_parsing(tmp_path: Path) -> None:
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(b"250 Hello\r\n")
    d.send_client(b"DATA\r\n")
    d.send_server(b"354 Go ahead\r\n")
    d.send_client(b"A" * 400 + b"\r\n")
    d.send_client(b"B" * 400 + b"\r\n")

    config = AnalysisConfig(max_message_body_bytes=256)
    analysis = _analyze(d, tmp_path, config=config).protocols[0]
    assert analysis.parse_state.value == "INDETERMINATE"
    assert "LIMIT_MESSAGE_BODY_BYTES" in {w.code.value for w in analysis.warnings}


# -- the upgrade boundary ----------------------------------------------------
def test_no_plaintext_parsing_resumes_after_acceptance(tmp_path: Path) -> None:
    """Binary that fails to decode must not cause a fall back to plaintext."""
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(EHLO_TLS)
    request = d.send_client(b"STARTTLS\r\n")
    response = d.send_server(READY)
    # Not valid TLS at all -- and it spells a plaintext command.
    d.send_client(b"QUIT\r\nAUTH PLAIN c2VjcmV0\r\n")
    d.send_server(b"221 Bye\r\n")

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.parse_state.value == "HANDED_OFF_TO_TLS"
    assert analysis.client_plaintext_end_offset == request.end_offset
    assert analysis.server_plaintext_end_offset == response.end_offset
    types = {event.event_type.value for event in analysis.events}
    assert "AUTHENTICATION_COMMAND" not in types
    assert "SESSION_TERMINATION" not in types
    assert analysis.authentication == ()
    # The upgrade was accepted but nothing TLS-shaped followed: say so.
    assert analysis.upgrade is not None
    assert analysis.upgrade.state.value == "UPGRADE_ACCEPTED"
    assert "UPGRADE_ACCEPTED_WITHOUT_TLS_BYTES" in {
        warning.code.value for warning in analysis.warnings
    }


def test_client_boundary_is_not_assumed_to_be_the_command_end(tmp_path: Path) -> None:
    """With no client TLS bytes, the client boundary is NOT_OBSERVED."""
    d = Dialogue(server_port=25)
    d.send_server(GREETING)
    d.send_client(b"EHLO client.example\r\n")
    d.send_server(EHLO_TLS)
    d.send_client(b"STARTTLS\r\n")
    d.send_server(READY + server_hello())
    d.ack_client()  # the client sends nothing further

    analysis = _analyze(d, tmp_path).protocols[0]
    upgrade = analysis.upgrade
    assert upgrade is not None
    assert upgrade.server_boundary is not None
    assert upgrade.server_boundary.basis == "SERVER_SUCCESS_REPLY_END"
    assert upgrade.client_boundary is not None
    assert upgrade.client_boundary.basis == "NOT_OBSERVED"
    assert upgrade.client_boundary.status.value == "UNKNOWN"
    assert any("not assumed" in note for note in upgrade.notes)


# -- detection ---------------------------------------------------------------
def test_implicit_tls_on_993_is_a_port_hint_not_confirmed_imap(tmp_path: Path) -> None:
    d = Dialogue(server_port=993)
    d.send_client(client_hello())
    d.send_server(server_hello())
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.detection.status.value == "PORT_HINT"
    assert analysis.detection.protocol.value == "IMAP"
    assert analysis.detection.confidence_basis == "SERVER_PORT_ONLY"
    assert analysis.implicit_tls is not None
    assert analysis.implicit_tls.observed is True
    assert analysis.implicit_tls.service_identity_status.value == "PORT_HINT"
    assert any("cannot be identified" in text for text in analysis.implicit_tls.limitations)


def test_unknown_traffic_on_an_unknown_port_is_unknown(tmp_path: Path) -> None:
    d = Dialogue(server_port=9999)
    d.send_client(b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
    d.send_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.detection.status.value == "UNKNOWN"
    assert analysis.detection.protocol.value == "UNKNOWN"
    assert analysis.upgrade is None


@pytest.mark.parametrize("port", [25, 143, 110])
def test_a_conventional_port_alone_never_confirms(port: int, tmp_path: Path) -> None:
    """Bytes that are not an email dialogue must not be confirmed by the port."""
    d = Dialogue(server_port=port)
    d.send_client(bytes(range(0x30, 0x40)) * 3)
    d.send_server(bytes(range(0x60, 0x70)) * 3)
    d.close()

    analysis = _analyze(d, tmp_path).protocols[0]
    assert analysis.detection.status.value != "CONFIRMED"
    assert analysis.detection.confidence_basis in {
        "SERVER_PORT_ONLY",
        "NO_APPLICATION_EVIDENCE",
    }
