"""POP3 dialogue parser (RFC 1939, RFC 2449, RFC 2595).

The parts that are easy to get wrong:

* **Multiline responses.**  ``CAPA``, ``LIST``, ``UIDL``, ``RETR`` and ``TOP``
  answer with a status line followed by lines terminated by a single ``.``.
  Those body lines are not protocol records: a message retrieved with ``RETR``
  can contain the text ``STLS`` and must never be read as one.  Dot-stuffing
  means only a line that is exactly ``.`` terminates the body.
* **Command/response correspondence.**  POP3 has no tags, so a ``+OK`` is
  matched to the single command that was outstanding when it arrived.  A
  ``+OK`` that answers ``CAPA`` cannot accept a later ``STLS``.
* **State.**  ``STLS`` is only meaningful in the AUTHORIZATION state, before
  the session is authenticated; a ``STLS`` after ``PASS`` is recorded but not
  treated as a normal upgrade.
* **Credentials.**  ``USER``, ``PASS`` and ``APOP`` carry credential material
  as arguments. Only the verb is ever recorded.
"""

from __future__ import annotations

from ..models.evidence import EvidenceStatus, WarningCode
from ..models.protocol import (
    EmailProtocol,
    ParseState,
    ProtocolEventType,
    UpgradeMechanism,
)
from ..models.tcp import Direction
from .base import ParseContext, ParseOutcome, PendingCommand, ProtocolParser
from .reader import DialogueDriver, StreamCursor, StreamLine, merge_span
from .redaction import POP3_VERBS, safe_capability, safe_mechanism, safe_verb

__all__ = ["POP3Parser"]

#: Commands whose successful response is a dot-terminated multiline body.
_MULTILINE_COMMANDS = frozenset({"CAPA", "LIST", "UIDL", "RETR", "TOP"})
#: Commands that carry credential material in their arguments.
_AUTH_COMMANDS = frozenset({"USER", "PASS", "APOP", "AUTH"})


class POP3Parser(ProtocolParser):
    protocol = EmailProtocol.POP3
    mechanism = UpgradeMechanism.STLS

    def __init__(self, context: ParseContext) -> None:
        super().__init__(context)
        self._in_multiline = False
        self._multiline_command: str | None = None
        self._multiline_lines: list[StreamLine] = []
        self._multiline_bytes = 0
        self._authenticated = False
        self._awaiting_auth_continuation = False
        self._auth_continuations = 0
        self._halt = False

    def run(self) -> ParseOutcome:
        driver = DialogueDriver(
            StreamCursor(self.ctx.client, self.ctx.config, self.ctx.sink, self.ctx.session_id),
            StreamCursor(self.ctx.server, self.ctx.config, self.ctx.sink, self.ctx.session_id),
        )
        state = ParseState.NOT_APPLICABLE
        while not self._halt:
            item = driver.next()
            if item is None:
                break
            line = item.line
            if line.preceded_by_gap:
                self.note_gap(line)
                if self._in_multiline:
                    self._abandon_multiline(line)
            if item.direction is Direction.CLIENT_TO_SERVER:
                self._client_line(line)
            else:
                self._server_line(line)
            if self.state is ParseState.INDETERMINATE:
                state = ParseState.INDETERMINATE
                break

        if self._halt:
            state = ParseState.HANDED_OFF_TO_TLS
            self.halt_plaintext(
                driver,
                client_end=self.requested_event.end_offset if self.requested_event else None,
                server_end=self.response_event.end_offset if self.response_event else None,
            )
        elif state is not ParseState.INDETERMINATE:
            state = self._resting_state()
        return self.finish(state)

    def _resting_state(self) -> ParseState:
        if not self.greeting_observed and not self.recognised_commands:
            return ParseState.NOT_APPLICABLE
        if self.gap_seen:
            return ParseState.INCOMPLETE
        if self.pending or self._in_multiline:
            return ParseState.INCOMPLETE
        return ParseState.COMPLETE

    # -- client ------------------------------------------------------------
    def _client_line(self, line: StreamLine) -> None:
        if self._awaiting_auth_continuation:
            self._auth_continuations += 1
            self._awaiting_auth_continuation = False
            self.add_event(
                ProtocolEventType.AUTHENTICATION_CONTINUATION,
                line,
                "A client SASL continuation response was observed and discarded. Its "
                "contents are credential material and are not recorded.",
                byte_count=line.end_offset - line.start_offset,
            )
            return
        if not line.usable:
            self._unusable(line, "client command")
            return

        token, remainder = _split_token(line.content)
        verb = safe_verb(token, POP3_VERBS)
        if verb is None:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A client line did not begin with a recognised POP3 command keyword. The "
                "token is not reported because an unrecognised token in command position "
                "may be credential material.",
            )
            return

        self.recognised_commands += 1
        is_upgrade = verb == "STLS"
        is_auth = verb in _AUTH_COMMANDS
        mechanism = None
        if verb == "AUTH":
            mechanism_token, _ = _split_token(remainder)
            mechanism = safe_mechanism(mechanism_token)

        self.pending.append(
            PendingCommand(
                verb=verb,
                tag=None,
                line=line,
                is_upgrade=is_upgrade,
                is_auth=is_auth,
                mechanism=mechanism,
            )
        )

        if is_upgrade:
            self.upgrade_seen = True
            limitations: tuple[str, ...] = ()
            detail = (
                "The client issued STLS. The command alone does not establish TLS; the "
                "server's +OK or -ERR decides the outcome."
            )
            if self._authenticated:
                limitations = (
                    "RFC 2595 permits STLS only in the AUTHORIZATION state. This command "
                    "followed an accepted authentication, so the exchange does not conform.",
                )
                detail += " It was issued after authentication, which RFC 2595 does not allow."
            self.requested_event = self.add_event(
                ProtocolEventType.UPGRADE_REQUESTED,
                line,
                detail,
                command_verb=verb,
                limitations=limitations,
            )
        elif is_auth:
            self.add_event(
                ProtocolEventType.AUTHENTICATION_COMMAND,
                line,
                f"A POP3 {verb} command was observed. Its arguments carry credential "
                "material and are not recorded."
                + (f" Mechanism: {mechanism}." if mechanism else ""),
                command_verb=verb,
            )
            self.record_auth(line, verb, mechanism)
        elif verb == "QUIT":
            self.add_event(
                ProtocolEventType.SESSION_TERMINATION,
                line,
                "The client issued QUIT.",
                command_verb=verb,
            )
        else:
            self.add_event(
                ProtocolEventType.CLIENT_COMMAND,
                line,
                f"Client command {verb} observed.",
                command_verb=verb,
            )

    # -- server ------------------------------------------------------------
    def _server_line(self, line: StreamLine) -> None:
        if self._in_multiline:
            self._multiline_line(line)
            return
        if not line.usable:
            self._unusable(line, "server response")
            return

        status_token, remainder = _split_token(line.content)
        status = status_token.decode("ascii", errors="replace").upper()
        if status not in {"+OK", "-ERR"}:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A server line did not begin with the POP3 status indicator +OK or -ERR.",
            )
            return

        if not self.pending:
            if not self.greeting_observed and not self.recognised_commands:
                self.greeting_observed = status == "+OK"
                self.add_event(
                    ProtocolEventType.SERVER_GREETING,
                    line,
                    f"POP3 server greeting '{status}'. The banner, including any APOP "
                    "timestamp, is not recorded.",
                    reply_code=status,
                )
                return
            self.ctx.sink.add(
                WarningCode.PROTOCOL_UNSOLICITED_REPLY,
                f"A POP3 {status} response arrived with no command outstanding at server "
                f"stream offset {line.start_offset}.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
            )
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                line,
                f"Unsolicited POP3 {status}; no command was outstanding.",
                reply_code=status,
            )
            return

        command = self.pending[0]
        if command.is_auth and status == "+OK" and command.verb in {"AUTH"}:
            # A SASL AUTH may continue with '+ <challenge>' rather than finish.
            pass
        self.pending.pop(0)
        self.matched_exchanges += 1

        if command.is_upgrade:
            self._resolve_upgrade(line, status)
            return
        if command.is_auth:
            self._finish_auth(line, command.verb or "AUTH", status)
            if status == "+OK" and command.verb in {"PASS", "APOP", "AUTH"}:
                self._authenticated = True
            return

        if status == "+OK" and command.verb in _MULTILINE_COMMANDS:
            self._in_multiline = True
            self._multiline_command = command.verb
            self._multiline_lines = [line]
            self._multiline_bytes = 0
            return

        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            line,
            f"Server response {status} to {command.verb}.",
            reply_code=status,
            command_verb=command.verb,
        )

    def _multiline_line(self, line: StreamLine) -> None:
        """Consume a dot-terminated body without interpreting it."""
        self._multiline_bytes += line.end_offset - line.start_offset
        if line.complete and line.content == b".":
            command = self._multiline_command or "multiline"
            lines = [*self._multiline_lines, line]
            self._in_multiline = False
            self._multiline_command = None
            self._multiline_lines = []
            if command == "CAPA":
                self._record_capa(lines)
            else:
                self.add_event(
                    ProtocolEventType.MULTILINE_RESPONSE_SKIPPED,
                    merge_span(lines),
                    f"A POP3 {command} multiline response of {self._multiline_bytes} "
                    "byte(s) was skipped without interpretation and ended at its dot "
                    "terminator. Message content is never parsed as protocol records and "
                    "is not recorded.",
                    byte_count=self._multiline_bytes,
                    reply_code="+OK",
                    command_verb=command,
                )
            self._multiline_bytes = 0
            return

        if self._multiline_command == "CAPA":
            self._multiline_lines.append(line)
            return
        if self._multiline_bytes > self.ctx.config.max_message_body_bytes:
            self.ctx.sink.add(
                WarningCode.LIMIT_MESSAGE_BODY_BYTES,
                f"A POP3 multiline response exceeded the "
                f"{self.ctx.config.max_message_body_bytes}-byte limit without reaching its "
                "dot terminator; parsing stops rather than resuming inside message content.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
            )
            self.state = ParseState.INDETERMINATE
            self.extra_limitations.append(
                "An oversized POP3 multiline response prevented the parser from finding its "
                "terminator; nothing after that point is interpreted."
            )

    def _abandon_multiline(self, line: StreamLine) -> None:
        self._in_multiline = False
        command = self._multiline_command or "multiline"
        self._multiline_command = None
        self._multiline_lines = []
        self.add_event(
            ProtocolEventType.INCOMPLETE_RECORD,
            line,
            f"A POP3 {command} multiline response was interrupted by missing data, so its "
            "dot terminator was never seen. The body is not reconstructed across the gap.",
            status=EvidenceStatus.UNKNOWN,
        )

    def _record_capa(self, lines: list[StreamLine]) -> None:
        capabilities: list[str] = []
        for line in lines[1:]:
            token, _ = _split_token(line.content)
            keyword = safe_capability(token)
            if keyword:
                capabilities.append(keyword)
            if len(capabilities) >= 64:
                break
        self.add_event(
            ProtocolEventType.CAPABILITY_ADVERTISEMENT,
            merge_span([*lines]),
            f"The server advertised {len(capabilities)} POP3 capability keyword(s) in its "
            "CAPA response.",
            capabilities=tuple(capabilities),
            reply_code="+OK",
            command_verb="CAPA",
        )
        if "STLS" not in capabilities:
            return
        self.upgrade_seen = True
        for line in lines[1:]:
            token, _ = _split_token(line.content)
            if safe_capability(token) == "STLS":
                self.advertised_event = self.add_event(
                    ProtocolEventType.UPGRADE_ADVERTISED,
                    line,
                    "The server advertised the STLS capability (RFC 2595). Advertisement "
                    "alone does not mean the upgrade was used.",
                    capabilities=("STLS",),
                )
                break

    def _resolve_upgrade(self, line: StreamLine, status: str) -> None:
        self.response_code = status
        if status == "+OK":
            self.upgrade_outcome = "ACCEPTED"
            self.response_event = self.add_event(
                ProtocolEventType.UPGRADE_ACCEPTED,
                line,
                "The server returned +OK to STLS, so it agreed to begin TLS. Plaintext POP3 "
                "parsing stops at the end of this response. This is not evidence that a TLS "
                "handshake completed.",
                reply_code=status,
                command_verb="STLS",
            )
            self._halt = True
            return
        self.upgrade_outcome = "REJECTED"
        self.response_event = self.add_event(
            ProtocolEventType.UPGRADE_REJECTED,
            line,
            "The server returned -ERR to STLS. TLS was not started and the session "
            "continues in plaintext.",
            reply_code=status,
            command_verb="STLS",
        )

    def _finish_auth(self, line: StreamLine, verb: str, status: str) -> None:
        self._awaiting_auth_continuation = False
        if self.auth and self._auth_continuations:
            last = self.auth[-1]
            self.auth[-1] = last.model_copy(
                update={"continuation_exchanges": self._auth_continuations}
            )
        self._auth_continuations = 0
        outcome = "was accepted" if status == "+OK" else "was refused"
        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            line,
            f"Server response {status} to {verb}; the attempt {outcome}. No credential "
            "material is recorded.",
            reply_code=status,
            command_verb=verb,
        )

    def _unusable(self, line: StreamLine, what: str) -> None:
        if any(command.is_upgrade for command in self.pending) or self.requested_event:
            self.mark_negotiation_unsafe()
        reason = (
            "overlapping TCP segments disagreed about these bytes"
            if line.ambiguous
            else "the record was cut short by missing data or the line limit"
        )
        self.add_event(
            ProtocolEventType.INCOMPLETE_RECORD,
            line,
            f"A POP3 {what} at stream offset {line.start_offset} is not usable as "
            f"evidence: {reason}.",
            status=EvidenceStatus.UNKNOWN,
        )


def _split_token(data: bytes) -> tuple[bytes, bytes]:
    stripped = data.lstrip(b" \t")
    index = 0
    while index < len(stripped) and stripped[index : index + 1] not in (b" ", b"\t"):
        index += 1
    return stripped[:index], stripped[index:].lstrip(b" \t")
