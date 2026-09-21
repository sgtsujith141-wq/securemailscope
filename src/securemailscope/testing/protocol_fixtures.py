"""M2 protocol fixtures: SMTP, IMAP and POP3 dialogues with known ground truth.

Every expectation in this module is derived from the dialogue being built --
"I put the STARTTLS command at client offset 21, so the client transition
boundary must be 31" -- and not from engine output. The engine has to
reconstruct the stream, parse the dialogue and arrive at the same numbers on
its own.

Credential material in these fixtures is deliberately recognisable
(``dummy-user@example.invalid``, ``NotARealPassword123``) and every fixture
that contains any lists it in ``forbidden_strings``, so a test can assert it
never reaches a report, a warning or a log line.

All addresses are RFC 5737 documentation ranges, all hostnames use
``.example``/``.invalid``, and the TLS records are synthetic byte structures
(see :mod:`securemailscope.testing.tls_blobs`). Nothing here came from a real
mail server.
"""

from __future__ import annotations

import base64
from typing import Final

from .dialogue import Dialogue, Sent
from .fixtures import FixtureSpec
from .manifest import (
    ExpectedAuthentication,
    ExpectedProtocol,
    ExpectedProtocolEvent,
    ExpectedUpgrade,
)
from .tls_blobs import (
    application_data,
    client_hello,
    server_hello,
    truncated_client_hello,
)
from .writers import write_pcap

__all__ = ["build_protocol_fixtures"]

# --- recognisable dummy credentials ----------------------------------------
DUMMY_USER: Final = b"dummy-user@example.invalid"
DUMMY_PASSWORD: Final = b"NotARealPassword123"
DUMMY_SENDER: Final = b"sender@example.invalid"
DUMMY_RECIPIENT: Final = b"recipient@example.invalid"
AUTH_PLAIN_B64: Final = base64.b64encode(b"\x00" + DUMMY_USER + b"\x00" + DUMMY_PASSWORD)
AUTH_USER_B64: Final = base64.b64encode(DUMMY_USER)
AUTH_PASSWORD_B64: Final = base64.b64encode(DUMMY_PASSWORD)

CREDENTIAL_STRINGS: Final[list[str]] = [
    DUMMY_USER.decode(),
    DUMMY_PASSWORD.decode(),
    AUTH_PLAIN_B64.decode(),
    AUTH_USER_B64.decode(),
    AUTH_PASSWORD_B64.decode(),
]

SMTP_GREETING: Final = b"220 mail.example ESMTP Postfix ready\r\n"
SMTP_EHLO: Final = b"EHLO client.example\r\n"
SMTP_EHLO_TLS: Final = (
    b"250-mail.example Hello client.example\r\n"
    b"250-PIPELINING\r\n"
    b"250-SIZE 10485760\r\n"
    b"250-STARTTLS\r\n"
    b"250 HELP\r\n"
)
SMTP_EHLO_NO_TLS: Final = (
    b"250-mail.example Hello client.example\r\n"
    b"250-PIPELINING\r\n"
    b"250-AUTH PLAIN LOGIN\r\n"
    b"250 HELP\r\n"
)
SMTP_STARTTLS: Final = b"STARTTLS\r\n"
SMTP_READY: Final = b"220 2.0.0 Ready to start TLS\r\n"


def _spec(
    name: str,
    filename: str,
    description: str,
    generation: str,
    dialogue: Dialogue,
    protocols: list[ExpectedProtocol],
    *,
    forbidden: list[str] | None = None,
) -> FixtureSpec:
    packets = dialogue.packets
    return FixtureSpec(
        name=name,
        filename=filename,
        description=description,
        generation=generation,
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(packets),
        timestamps_ns=[timestamp for timestamp, _ in packets],
        expected_packet_count=len(packets),
        expected_tcp_packet_count=len(packets),
        expected_sessions=[],
        expected_warning_codes=[],
        expected_protocols=protocols,
        forbidden_strings=list(forbidden or []),
    )


def _smtp_preamble(dialogue: Dialogue, *, advertise_tls: bool = True) -> tuple[Sent, Sent]:
    dialogue.send_server(SMTP_GREETING)
    dialogue.send_client(SMTP_EHLO)
    capabilities = dialogue.send_server(
        SMTP_EHLO_TLS if advertise_tls else SMTP_EHLO_NO_TLS
    )
    return capabilities, capabilities


# ---------------------------------------------------------------------------
# A. SMTP STARTTLS accepted (with a retransmitted command segment)
# ---------------------------------------------------------------------------
def _fixture_a() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    d.retransmit_last_client()  # the same segment arrives twice
    response = d.send_server(SMTP_READY)
    hello = d.send_client(client_hello())
    d.send_server(server_hello())
    d.ack_client()

    return _spec(
        "P_A_smtp_starttls_accepted",
        "p_a_smtp_starttls_accepted.pcap",
        "A complete SMTP STARTTLS negotiation that the server accepts, including a "
        "retransmission of the STARTTLS segment. Plaintext parsing must stop at the end "
        "of the 220 reply and the retransmission must not produce a second request.",
        "securemailscope.testing.protocol_fixtures._fixture_a",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="SERVER_GREETING",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=0,
                        reply_code="220",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        end_offset=request.end_offset,
                        command_verb="STARTTLS",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_ACCEPTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        end_offset=response.end_offset,
                        reply_code="220",
                    ),
                ],
                forbidden_event_types=["AUTHENTICATION_COMMAND"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# B. SMTP STARTTLS rejected (454 temporary failure)
# ---------------------------------------------------------------------------
def _fixture_b() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    response = d.send_server(b"454 4.7.0 TLS not available due to temporary reason\r\n")
    d.send_client(b"QUIT\r\n")
    d.send_server(b"221 2.0.0 Bye\r\n")
    d.close()

    return _spec(
        "P_B_smtp_starttls_rejected",
        "p_b_smtp_starttls_rejected.pcap",
        "The server refuses STARTTLS with 454, a temporary failure. The session must "
        "continue to be parsed as plaintext and the refusal must be distinguished from a "
        "permanent 5xx rejection.",
        "securemailscope.testing.protocol_fixtures._fixture_b",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="UPGRADE_REJECTED",
                    advertised=True,
                    requested=True,
                    response_code="454",
                    tls_record_count=0,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_TEMPORARY_FAILURE",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        end_offset=response.end_offset,
                        reply_code="454",
                    ),
                    ExpectedProtocolEvent(
                        event_type="SESSION_TERMINATION",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.end_offset,
                        command_verb="QUIT",
                    ),
                ],
                forbidden_event_types=["UPGRADE_ACCEPTED"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# C. SMTP multiline 220 acceptance
# ---------------------------------------------------------------------------
def _fixture_c() -> FixtureSpec:
    d = Dialogue(server_port=587)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    response = d.send_server(
        b"220-Beginning TLS negotiation now\r\n"
        b"220-This reply continues\r\n"
        b"220 2.0.0 Ready to start TLS\r\n"
    )
    hello = d.send_client(client_hello())
    d.send_server(server_hello())

    return _spec(
        "P_C_smtp_multiline_220",
        "p_c_smtp_multiline_220.pcap",
        "The STARTTLS acceptance is a three-line 220 reply. The reply is not complete "
        "until its final line, so the server transition boundary must be the end of the "
        "LAST line, not the first.",
        "securemailscope.testing.protocol_fixtures._fixture_c",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    # The whole multiline reply is one record: it starts at the
                    # first 220- line and ends after the final 220 line.
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_ACCEPTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        end_offset=response.end_offset,
                        reply_code="220",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                    ),
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# D. IMAP tagged STARTTLS accepted (with out-of-order server segments)
# ---------------------------------------------------------------------------
def _fixture_d() -> FixtureSpec:
    d = Dialogue(server_port=143)
    d.send_server(b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] Server ready\r\n")
    d.send_client(b"a001 CAPABILITY\r\n")
    capability = b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK completed\r\n"
    d.send_server_out_of_order(capability, [46, len(capability) - 46])
    request = d.send_client(b"a002 STARTTLS\r\n")
    response = d.send_server(b"a002 OK Begin TLS negotiation now\r\n")
    hello = d.send_client(client_hello())
    d.send_server(server_hello())

    return _spec(
        "P_D_imap_starttls_accepted",
        "p_d_imap_starttls_accepted.pcap",
        "IMAP STARTTLS accepted by a correctly tagged OK, with the CAPABILITY response "
        "delivered out of order at the TCP layer. Reassembly must restore the order "
        "before the protocol layer sees it.",
        "securemailscope.testing.protocol_fixtures._fixture_d",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="IMAP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="IMAP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="OK",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="SERVER_GREETING",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=0,
                        reply_code="OK",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                        tag="a002",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_ACCEPTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        reply_code="OK",
                        tag="a002",
                    ),
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# E. IMAP wrong-tag OK response
# ---------------------------------------------------------------------------
def _fixture_e() -> FixtureSpec:
    d = Dialogue(server_port=143)
    d.send_server(b"* OK IMAP4rev1 Service Ready\r\n")
    d.send_client(b"a001 CAPABILITY\r\n")
    d.send_server(b"* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK completed\r\n")
    request = d.send_client(b"a002 STARTTLS\r\n")
    # A tagged OK for a tag that was never issued: it must not accept STARTTLS.
    d.send_server(b"a003 OK Begin TLS negotiation now\r\n")
    d.send_client(b"a004 LOGOUT\r\n")
    d.close()

    return _spec(
        "P_E_imap_wrong_tag_ok",
        "p_e_imap_wrong_tag_ok.pcap",
        "The server answers with a tagged OK carrying the WRONG tag. It must not be "
        "treated as accepting STARTTLS; the upgrade stays merely requested.",
        "securemailscope.testing.protocol_fixtures._fixture_e",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="IMAP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="INCOMPLETE",
                port_hint="IMAP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="UPGRADE_REQUESTED",
                    advertised=True,
                    requested=True,
                    response_code=None,
                    tls_record_count=0,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                        tag="a002",
                    )
                ],
                forbidden_event_types=["UPGRADE_ACCEPTED"],
                expected_warning_codes=[
                    "PROTOCOL_UNSOLICITED_REPLY",
                    "UPGRADE_REQUEST_WITHOUT_RESPONSE",
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# F. POP3 STLS accepted
# ---------------------------------------------------------------------------
def _fixture_f() -> FixtureSpec:
    d = Dialogue(server_port=110)
    d.send_server(b"+OK POP3 server ready\r\n")
    d.send_client(b"CAPA\r\n")
    d.send_server(b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n")
    request = d.send_client(b"STLS\r\n")
    response = d.send_server(b"+OK Begin TLS negotiation\r\n")
    hello = d.send_client(client_hello())
    d.send_server(server_hello())

    return _spec(
        "P_F_pop3_stls_accepted",
        "p_f_pop3_stls_accepted.pcap",
        "POP3 STLS advertised in a multiline CAPA response and accepted with +OK. "
        "Plaintext parsing must stop at the end of the +OK line.",
        "securemailscope.testing.protocol_fixtures._fixture_f",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="POP3",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="POP3",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="+OK",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="SERVER_GREETING",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=0,
                        reply_code="+OK",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STLS",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_ACCEPTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        reply_code="+OK",
                    ),
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# G. POP3 STLS rejected
# ---------------------------------------------------------------------------
def _fixture_g() -> FixtureSpec:
    d = Dialogue(server_port=110)
    d.send_server(b"+OK POP3 server ready\r\n")
    d.send_client(b"CAPA\r\n")
    d.send_server(b"+OK Capability list follows\r\nTOP\r\nUSER\r\n.\r\n")
    d.send_client(b"STLS\r\n")
    response = d.send_server(b"-ERR TLS is not supported on this server\r\n")
    d.send_client(b"QUIT\r\n")
    d.send_server(b"+OK Bye\r\n")
    d.close()

    return _spec(
        "P_G_pop3_stls_rejected",
        "p_g_pop3_stls_rejected.pcap",
        "STLS is not advertised and the server refuses it with -ERR. The session must "
        "continue to be parsed as plaintext; the absence of TLS is recorded as an "
        "observation, not judged.",
        "securemailscope.testing.protocol_fixtures._fixture_g",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="POP3",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="POP3",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STLS",
                    state="UPGRADE_REJECTED",
                    advertised=False,
                    requested=True,
                    response_code="-ERR",
                    tls_record_count=0,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REJECTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=response.start_offset,
                        reply_code="-ERR",
                    )
                ],
                forbidden_event_types=["UPGRADE_ACCEPTED", "UPGRADE_ADVERTISED"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# H. SMTP on a non-standard port
# ---------------------------------------------------------------------------
def _fixture_h() -> FixtureSpec:
    d = Dialogue(server_port=8025)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    response = d.send_server(SMTP_READY)
    d.send_client(client_hello())

    return _spec(
        "P_H_smtp_nonstandard_port",
        "p_h_smtp_nonstandard_port.pcap",
        "A full SMTP dialogue on TCP port 8025, which carries no port hint at all. "
        "Detection must be CONFIRMED from payload alone.",
        "securemailscope.testing.protocol_fixtures._fixture_h",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint=None,
                port_hint_agrees=None,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=request.end_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=1,
                ),
            )
        ],
    )


# ---------------------------------------------------------------------------
# I. POP3 dialogue on the IMAP port
# ---------------------------------------------------------------------------
def _fixture_i() -> FixtureSpec:
    d = Dialogue(server_port=143)
    d.send_server(b"+OK POP3 server ready\r\n")
    d.send_client(b"CAPA\r\n")
    d.send_server(b"+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n")
    d.send_client(b"STLS\r\n")
    d.send_server(b"+OK Begin TLS negotiation\r\n")
    d.send_client(client_hello())

    return _spec(
        "P_I_pop3_on_imap_port",
        "p_i_pop3_on_imap_port.pcap",
        "A POP3 dialogue running on TCP port 143, which conventionally carries IMAP. The "
        "payload evidence must win and the disagreement with the port must be reported.",
        "securemailscope.testing.protocol_fixtures._fixture_i",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="POP3",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="IMAP",
                port_hint_agrees=False,
                upgrade=ExpectedUpgrade(
                    mechanism="STLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="+OK",
                    tls_record_count=1,
                ),
            )
        ],
    )


# ---------------------------------------------------------------------------
# J. STARTTLS command with no server response
# ---------------------------------------------------------------------------
def _fixture_j() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    d.ack_server()  # the capture ends before the server answers

    return _spec(
        "P_J_starttls_no_response",
        "p_j_starttls_no_response.pcap",
        "The client issues STARTTLS and the capture ends before any server response. "
        "The outcome must be reported as unknown, never as success.",
        "securemailscope.testing.protocol_fixtures._fixture_j",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="INCOMPLETE",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="UPGRADE_REQUESTED",
                    advertised=True,
                    requested=True,
                    response_code=None,
                    tls_record_count=0,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                    )
                ],
                forbidden_event_types=["UPGRADE_ACCEPTED", "UPGRADE_REJECTED"],
                expected_warning_codes=["UPGRADE_REQUEST_WITHOUT_RESPONSE"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# K. TCP gap during the upgrade negotiation
# ---------------------------------------------------------------------------
def _fixture_k() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    d.drop_server(SMTP_READY)  # the acceptance is missing from the capture
    d.send_server(server_hello())
    d.send_client(client_hello())

    return _spec(
        "P_K_gap_during_upgrade",
        "p_k_gap_during_upgrade.pcap",
        "The server's STARTTLS response is missing from the capture and TLS-looking bytes "
        "follow. Even though TLS bytes appear, success must NOT be claimed: the "
        "negotiation was interrupted by a hole.",
        "securemailscope.testing.protocol_fixtures._fixture_k",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="INCOMPLETE",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="INCOMPLETE",
                    advertised=True,
                    requested=True,
                    response_code=None,
                    tls_record_count=0,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                    )
                ],
                forbidden_event_types=["UPGRADE_ACCEPTED"],
                # Only PROTOCOL_DESYNCHRONISED: the line before the hole was
                # complete, so nothing was "cut short" (no
                # PROTOCOL_GAP_IN_DIALOGUE), and the state is INCOMPLETE rather
                # than UPGRADE_REQUESTED, which is what would have produced
                # UPGRADE_REQUEST_WITHOUT_RESPONSE. INCOMPLETE already says the
                # outcome cannot be concluded.
                expected_warning_codes=["PROTOCOL_DESYNCHRONISED"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# L. STARTTLS acceptance and TLS bytes in the same TCP payload
# ---------------------------------------------------------------------------
def _fixture_l() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d)
    request = d.send_client(SMTP_STARTTLS)
    combined_start = d.server_offset
    d.send_server(SMTP_READY + server_hello())
    hello = d.send_client(client_hello())

    return _spec(
        "P_L_tls_bytes_in_accept_packet",
        "p_l_tls_bytes_in_accept_packet.pcap",
        "The server's 220 acceptance and its first TLS record travel in ONE TCP payload. "
        "The boundary must fall immediately after the reply's CRLF and the trailing TLS "
        "bytes must be preserved, not discarded.",
        "securemailscope.testing.protocol_fixtures._fixture_l",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    # Immediately after the CRLF of the 220 line, mid-payload.
                    server_boundary_offset=combined_start + len(SMTP_READY),
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_ACCEPTED",
                        direction="SERVER_TO_CLIENT",
                        stream_offset=combined_start,
                        end_offset=combined_start + len(SMTP_READY),
                        reply_code="220",
                    ),
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        command_verb="STARTTLS",
                    ),
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# M. Authentication before TLS, with a multi-round SASL continuation
# ---------------------------------------------------------------------------
def _fixture_m() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d, advertise_tls=False)
    auth = d.send_client(b"AUTH LOGIN\r\n")
    d.send_server(b"334 VXNlcm5hbWU6\r\n")
    d.send_client(AUTH_USER_B64 + b"\r\n")
    d.send_server(b"334 UGFzc3dvcmQ6\r\n")
    d.send_client(AUTH_PASSWORD_B64 + b"\r\n")
    d.send_server(b"235 2.7.0 Authentication successful\r\n")
    d.send_client(b"QUIT\r\n")
    d.send_server(b"221 2.0.0 Bye\r\n")
    d.close()

    return _spec(
        "P_M_auth_before_tls",
        "p_m_auth_before_tls.pcap",
        "AUTH LOGIN with a two-round base64 challenge/response exchange, entirely in "
        "plaintext with no STARTTLS offered. The attempt must be recorded; the username "
        "and password must not appear anywhere in the output.",
        "securemailscope.testing.protocol_fixtures._fixture_m",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=None,
                authentication=[
                    ExpectedAuthentication(
                        command_verb="AUTH",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=auth.start_offset,
                        before_upgrade=True,
                        mechanism="LOGIN",
                        continuation_exchanges=2,
                    )
                ],
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="AUTHENTICATION_COMMAND",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=auth.start_offset,
                        command_verb="AUTH",
                    )
                ],
                expected_warning_codes=["PLAINTEXT_AUTHENTICATION_OBSERVED"],
            )
        ],
        forbidden=CREDENTIAL_STRINGS,
    )


# ---------------------------------------------------------------------------
# N. Bytes after an accepted upgrade are never parsed as plaintext
# ---------------------------------------------------------------------------
def _fixture_n() -> FixtureSpec:
    d = Dialogue(server_port=587)
    _smtp_preamble(d)
    d.send_client(SMTP_STARTTLS)
    response = d.send_server(SMTP_READY)
    # After the boundary the client sends a TLS record and then bytes that
    # would look exactly like a plaintext AUTH command if anything resumed
    # parsing them. Nothing must.
    hello = d.send_client(
        client_hello() + b"AUTH PLAIN " + AUTH_PLAIN_B64 + b"\r\n" + application_data(32)
    )
    d.send_server(server_hello())

    return _spec(
        "P_N_no_plaintext_after_upgrade",
        "p_n_no_plaintext_after_upgrade.pcap",
        "After the upgrade is accepted, the client's encrypted region deliberately "
        "contains bytes that spell a plaintext AUTH command. Parsing must not resume, so "
        "no authentication observation may be produced and the credential must not leak.",
        "securemailscope.testing.protocol_fixtures._fixture_n",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=2,
                ),
                authentication=[],
                forbidden_event_types=[
                    "AUTHENTICATION_COMMAND",
                    "AUTHENTICATION_CONTINUATION",
                ],
            )
        ],
        forbidden=CREDENTIAL_STRINGS,
    )


# ---------------------------------------------------------------------------
# O. Implicit TLS with a truncated record
# ---------------------------------------------------------------------------
def _fixture_o() -> FixtureSpec:
    d = Dialogue(server_port=993)
    d.send_client(truncated_client_hello(40))
    d.ack_server()

    return _spec(
        "P_O_implicit_tls_incomplete",
        "p_o_implicit_tls_incomplete.pcap",
        "A session on port 993 that is TLS-framed from its first byte, whose ClientHello "
        "record is truncated by the end of the capture. The framing may be observed; the "
        "email protocol inside must remain a port hint only.",
        "securemailscope.testing.protocol_fixtures._fixture_o",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="IMAP",
                detection_status="PORT_HINT",
                confidence_basis="SERVER_PORT_ONLY",
                parse_state="NOT_APPLICABLE",
                port_hint="IMAP",
                port_hint_agrees=None,
                implicit_tls_observed=True,
                upgrade=None,
                forbidden_event_types=["UPGRADE_ACCEPTED", "SERVER_GREETING"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# P. SMTP DATA body containing text that looks like STARTTLS
# ---------------------------------------------------------------------------
def _fixture_p() -> FixtureSpec:
    d = Dialogue(server_port=25)
    _smtp_preamble(d, advertise_tls=False)
    d.send_client(b"MAIL FROM:<" + DUMMY_SENDER + b">\r\n")
    d.send_server(b"250 2.1.0 Ok\r\n")
    d.send_client(b"RCPT TO:<" + DUMMY_RECIPIENT + b">\r\n")
    d.send_server(b"250 2.1.5 Ok\r\n")
    d.send_client(b"DATA\r\n")
    d.send_server(b"354 End data with <CR><LF>.<CR><LF>\r\n")
    body = (
        b"Subject: not a command\r\n"
        b"\r\n"
        b"STARTTLS\r\n"
        b"220 2.0.0 Ready to start TLS\r\n"
        b"..a dot-stuffed line that is not a terminator\r\n"
        b".\r\n"
    )
    body_sent = d.send_client(body)
    d.send_server(b"250 2.0.0 Ok: queued\r\n")
    d.send_client(b"QUIT\r\n")
    d.send_server(b"221 2.0.0 Bye\r\n")
    d.close()

    return _spec(
        "P_P_data_body_fake_starttls",
        "p_p_data_body_fake_starttls.pcap",
        "The DATA body contains the literal text 'STARTTLS' and a fake '220 Ready to "
        "start TLS' line, plus a dot-stuffed line. None of it may be parsed as protocol: "
        "no upgrade may be reported at all.",
        "securemailscope.testing.protocol_fixtures._fixture_p",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=None,
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="MESSAGE_BODY_SKIPPED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=body_sent.end_offset - 3,
                        end_offset=body_sent.end_offset,
                    )
                ],
                forbidden_event_types=[
                    "UPGRADE_REQUESTED",
                    "UPGRADE_ACCEPTED",
                    "UPGRADE_ADVERTISED",
                ],
            )
        ],
        forbidden=[DUMMY_SENDER.decode(), DUMMY_RECIPIENT.decode()],
    )


# ---------------------------------------------------------------------------
# Q. IMAP literal containing text that looks like a STARTTLS exchange
# ---------------------------------------------------------------------------
_Q_LITERAL: Final = b"a002 STARTTLS\r\na002 OK Begin TLS negotiation now\r\n"


def _fixture_q() -> FixtureSpec:
    d = Dialogue(server_port=143)
    d.send_server(b"* OK IMAP4rev1 Service Ready\r\n")
    login = d.send_client(b"a001 LOGIN " + DUMMY_USER + b" " + DUMMY_PASSWORD + b"\r\n")
    d.send_server(b"a001 OK LOGIN completed\r\n")
    literal_command = (
        b"a003 APPEND INBOX {" + str(len(_Q_LITERAL)).encode() + b"+}\r\n"
    )
    literal_start = d.client_offset + len(literal_command)
    d.send_client(literal_command + _Q_LITERAL + b"\r\n")
    d.send_server(b"a003 OK APPEND completed\r\n")
    d.send_client(b"a004 LOGOUT\r\n")
    d.send_server(b"* BYE Logging out\r\na004 OK LOGOUT completed\r\n")
    d.close()

    return _spec(
        "P_Q_imap_literal_fake_commands",
        "p_q_imap_literal_fake_commands.pcap",
        "An IMAP APPEND literal contains a complete fake STARTTLS exchange. The literal "
        "must be skipped by its declared length, so no upgrade may be reported. LOGIN "
        "credentials in the same dialogue must not appear in the output.",
        "securemailscope.testing.protocol_fixtures._fixture_q",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="IMAP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="IMAP",
                port_hint_agrees=True,
                upgrade=None,
                authentication=[
                    ExpectedAuthentication(
                        command_verb="LOGIN",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=login.start_offset,
                        before_upgrade=True,
                    )
                ],
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="LITERAL_SKIPPED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=literal_start - len(literal_command),
                        end_offset=literal_start + len(_Q_LITERAL),
                    )
                ],
                forbidden_event_types=["UPGRADE_REQUESTED", "UPGRADE_ACCEPTED"],
                expected_warning_codes=["PLAINTEXT_AUTHENTICATION_OBSERVED"],
            )
        ],
        forbidden=[DUMMY_USER.decode(), DUMMY_PASSWORD.decode()],
    )


# ---------------------------------------------------------------------------
# R. POP3 retrieved message containing text that looks like STLS
# ---------------------------------------------------------------------------
def _fixture_r() -> FixtureSpec:
    d = Dialogue(server_port=110)
    d.send_server(b"+OK POP3 server ready\r\n")
    d.send_client(b"CAPA\r\n")
    d.send_server(b"+OK Capability list follows\r\nTOP\r\nUSER\r\n.\r\n")
    user = d.send_client(b"USER " + DUMMY_USER + b"\r\n")
    d.send_server(b"+OK User accepted\r\n")
    password = d.send_client(b"PASS " + DUMMY_PASSWORD + b"\r\n")
    d.send_server(b"+OK Mailbox ready\r\n")
    d.send_client(b"RETR 1\r\n")
    d.send_server(
        b"+OK 140 octets\r\n"
        b"Subject: nothing to see\r\n"
        b"\r\n"
        b"STLS\r\n"
        b"+OK Begin TLS negotiation\r\n"
        b"..dot stuffed\r\n"
        b".\r\n"
    )
    d.send_client(b"QUIT\r\n")
    d.send_server(b"+OK Bye\r\n")
    d.close()

    return _spec(
        "P_R_pop3_message_fake_stls",
        "p_r_pop3_message_fake_stls.pcap",
        "A retrieved POP3 message body contains 'STLS' and a fake '+OK Begin TLS "
        "negotiation' line. The dot-terminated body must be skipped without "
        "interpretation, so no upgrade may be reported. USER and PASS arguments must "
        "not appear in the output.",
        "securemailscope.testing.protocol_fixtures._fixture_r",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="POP3",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="COMPLETE",
                port_hint="POP3",
                port_hint_agrees=True,
                upgrade=None,
                authentication=[
                    ExpectedAuthentication(
                        command_verb="USER",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=user.start_offset,
                        before_upgrade=True,
                    ),
                    ExpectedAuthentication(
                        command_verb="PASS",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=password.start_offset,
                        before_upgrade=True,
                    ),
                ],
                forbidden_event_types=["UPGRADE_REQUESTED", "UPGRADE_ACCEPTED"],
                expected_warning_codes=["PLAINTEXT_AUTHENTICATION_OBSERVED"],
            )
        ],
        forbidden=[DUMMY_USER.decode(), DUMMY_PASSWORD.decode()],
    )


# ---------------------------------------------------------------------------
# S. Commands split across TCP segments, including a split CRLF
# ---------------------------------------------------------------------------
def _fixture_s() -> FixtureSpec:
    d = Dialogue(server_port=25)
    d.send_server(SMTP_GREETING)
    d.send_client_segmented(SMTP_EHLO, [5, 16])
    d.send_server_segmented(SMTP_EHLO_TLS, [40, len(SMTP_EHLO_TLS) - 40])
    # "STARTTLS\r" and "\n": the terminator itself spans two segments.
    request = d.send_client_segmented(SMTP_STARTTLS, [9, 1])
    response = d.send_server(SMTP_READY)
    hello = d.send_client(client_hello())

    return _spec(
        "P_S_commands_split_across_segments",
        "p_s_commands_split_across_segments.pcap",
        "EHLO, the EHLO reply and STARTTLS are each split across TCP segments, with the "
        "STARTTLS CRLF itself spanning two segments. Reassembly must restore them before "
        "the line reader sees them.",
        "securemailscope.testing.protocol_fixtures._fixture_s",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="CONFIRMED",
                confidence_basis="GREETING_AND_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=True,
                    requested=True,
                    response_code="220",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=hello.start_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=1,
                ),
                key_events=[
                    ExpectedProtocolEvent(
                        event_type="UPGRADE_REQUESTED",
                        direction="CLIENT_TO_SERVER",
                        stream_offset=request.start_offset,
                        end_offset=request.end_offset,
                        command_verb="STARTTLS",
                    )
                ],
            )
        ],
    )


# ---------------------------------------------------------------------------
# T. Capture starting midstream
# ---------------------------------------------------------------------------
def _fixture_t() -> FixtureSpec:
    d = Dialogue(server_port=25, handshake=False)
    d.send_server(SMTP_EHLO_TLS)  # the EHLO that prompted this was not captured
    request = d.send_client(SMTP_STARTTLS)
    response = d.send_server(SMTP_READY)
    d.send_client(client_hello())

    return _spec(
        "P_T_midstream_smtp",
        "p_t_midstream_smtp.pcap",
        "The capture begins mid-session: there is no TCP handshake and no SMTP greeting. "
        "Detection must fall to PROBABLE, and the 250 multiline reply must NOT be treated "
        "as a capability advertisement because the command it answers was not observed.",
        "securemailscope.testing.protocol_fixtures._fixture_t",
        d,
        [
            ExpectedProtocol(
                session_index=0,
                protocol="SMTP",
                detection_status="PROBABLE",
                confidence_basis="SINGLE_MATCHED_EXCHANGE",
                parse_state="HANDED_OFF_TO_TLS",
                port_hint="SMTP",
                port_hint_agrees=True,
                upgrade=ExpectedUpgrade(
                    mechanism="STARTTLS",
                    state="TLS_BYTES_OBSERVED",
                    advertised=False,
                    requested=True,
                    response_code="220",
                    server_boundary_offset=response.end_offset,
                    server_boundary_basis="SERVER_SUCCESS_REPLY_END",
                    client_boundary_offset=request.end_offset,
                    client_boundary_basis="FIRST_TLS_RECORD",
                    tls_record_count=1,
                ),
                forbidden_event_types=["SERVER_GREETING", "UPGRADE_ADVERTISED"],
            )
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
    _fixture_i,
    _fixture_j,
    _fixture_k,
    _fixture_l,
    _fixture_m,
    _fixture_n,
    _fixture_o,
    _fixture_p,
    _fixture_q,
    _fixture_r,
    _fixture_s,
    _fixture_t,
)


def build_protocol_fixtures() -> list[FixtureSpec]:
    """Build every M2 protocol fixture. Deterministic across runs."""
    return [builder() for builder in _BUILDERS]

