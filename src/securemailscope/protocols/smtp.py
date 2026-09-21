"""SMTP dialogue parser (RFC 5321, RFC 3207, RFC 4954).

The parts that are easy to get wrong, and what this parser does about them:

* **Multiline replies.**  A reply is not complete until a line whose code is
  followed by a space rather than a hyphen.  A multiline ``220`` acceptance
  therefore ends at its *final* line, and that is where the TLS transition
  boundary is measured from -- not at the first line.
* **Reply-to-command matching.**  Replies are matched against a FIFO of
  outstanding commands, so with pipelined ``EHLO``/``STARTTLS`` the ``250``
  answers ``EHLO`` and only the following ``220`` can accept ``STARTTLS``.
* **Intermediate replies.**  ``354`` (DATA) and ``334`` (AUTH challenge) do not
  complete their command; the command stays outstanding until its final reply.
* **DATA bodies.**  Once ``354`` is seen the client's bytes are message
  content, not commands.  Only a line consisting of exactly ``.`` terminates
  it -- a dot-stuffed line such as ``..signature`` does not.  Nothing from the
  body is recorded beyond a byte count.
* **AUTH continuations.**  After a ``334`` the client's next line is credential
  material.  It is counted and discarded; it is never parsed as a command and
  never reaches a report.
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
from .redaction import SMTP_VERBS, safe_capability, safe_mechanism, safe_reply_code, safe_verb

__all__ = ["SMTPParser"]

#: Reply codes that can legitimately open an SMTP session.
_GREETING_CODES = frozenset({"220", "554"})
#: RFC 3207: 220 means "ready to start TLS". Nothing else accepts.
_STARTTLS_ACCEPT = "220"
#: RFC 3207: 454 is "TLS not available due to temporary reason".
_STARTTLS_TEMPORARY = "454"


class SMTPParser(ProtocolParser):
    protocol = EmailProtocol.SMTP
    mechanism = UpgradeMechanism.STARTTLS

    def __init__(self, context: ParseContext) -> None:
        super().__init__(context)
        self._reply_lines: list[StreamLine] = []
        self._in_data_body = False
        self._data_bytes = 0
        self._awaiting_auth_continuation = False
        self._auth_continuations = 0
        self._halt = False

    # -- entry point -------------------------------------------------------
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
        if self.pending or self._in_data_body or self._reply_lines:
            return ParseState.INCOMPLETE
        return ParseState.COMPLETE

    # -- client ------------------------------------------------------------
    def _client_line(self, line: StreamLine) -> None:
        if self._in_data_body:
            self._data_body_line(line)
            return
        if self._awaiting_auth_continuation:
            self._auth_continuations += 1
            self._awaiting_auth_continuation = False
            self.add_event(
                ProtocolEventType.AUTHENTICATION_CONTINUATION,
                line,
                "A client SASL continuation response was observed and discarded. Its "
                "contents are credential material and are not recorded.",
                byte_count=line.end_offset - line.start_offset,
                limitations=(
                    "Only the presence and size of the exchange are recorded; the payload "
                    "is never decoded, stored or reported.",
                ),
            )
            return

        if not line.usable:
            self._unusable(line, "client command")
            return

        token, remainder = _split_token(line.content)
        verb = safe_verb(token, SMTP_VERBS)
        if verb is None:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A client line did not begin with a recognised SMTP command keyword. The "
                "token is not reported because an unrecognised token in command position "
                "may be credential material.",
                status=EvidenceStatus.OBSERVED,
            )
            return

        self.recognised_commands += 1
        mechanism = None
        is_upgrade = verb == "STARTTLS"
        is_auth = verb == "AUTH"
        if is_auth:
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
            self.requested_event = self.add_event(
                ProtocolEventType.UPGRADE_REQUESTED,
                line,
                "The client issued STARTTLS. The command alone does not establish TLS; "
                "the server's reply decides the outcome.",
                command_verb=verb,
            )
        elif is_auth:
            self.add_event(
                ProtocolEventType.AUTHENTICATION_COMMAND,
                line,
                "An SMTP AUTH command was observed."
                + (f" Mechanism: {mechanism}." if mechanism else " Mechanism not recognised."),
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

    def _data_body_line(self, line: StreamLine) -> None:
        """Consume message content without interpreting it.

        Only a line that is exactly ``.`` ends the body. ``..anything`` is a
        dot-stuffed content line and is *not* a terminator -- which is also why
        a body containing the text ``STARTTLS`` can never be mistaken for a
        command.
        """
        span = line.end_offset - line.start_offset
        self._data_bytes += span
        if line.complete and line.content == b".":
            self._in_data_body = False
            self.add_event(
                ProtocolEventType.MESSAGE_BODY_SKIPPED,
                line,
                f"An SMTP DATA body of {self._data_bytes} byte(s) was skipped without "
                "interpretation and ended at its dot terminator. Message content is never "
                "parsed as commands and never recorded.",
                byte_count=self._data_bytes,
                end_offset=line.end_offset,
            )
            self._data_bytes = 0
            return
        if self._data_bytes > self.ctx.config.max_message_body_bytes:
            self.ctx.sink.add(
                WarningCode.LIMIT_MESSAGE_BODY_BYTES,
                f"An SMTP DATA body exceeded the "
                f"{self.ctx.config.max_message_body_bytes}-byte limit without reaching its "
                "terminator; parsing stops here rather than resuming in the middle of "
                "message content.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
            )
            self.state = ParseState.INDETERMINATE
            self.extra_limitations.append(
                "An oversized DATA body prevented the parser from finding the end of the "
                "message; nothing after that point is interpreted."
            )

    # -- server ------------------------------------------------------------
    def _server_line(self, line: StreamLine) -> None:
        if not line.usable:
            self._unusable(line, "server reply")
            self._reply_lines.clear()
            return

        code = safe_reply_code(line.content[:3])
        if code is None:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A server line did not begin with a three-digit SMTP reply code.",
            )
            self._reply_lines.clear()
            return

        separator = line.content[3:4]
        self._reply_lines.append(line)
        if separator == b"-":
            return  # continuation; the reply is not complete yet
        if separator not in (b" ", b""):
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A server reply code was not followed by a space or hyphen, so the reply "
                "does not conform to RFC 5321 syntax.",
                reply_code=code,
            )
            self._reply_lines.clear()
            return
        self._complete_reply(code)

    def _complete_reply(self, code: str) -> None:
        lines = list(self._reply_lines)
        self._reply_lines.clear()
        span = merge_span(lines)

        if not self.pending:
            first_reply = not self.greeting_observed and not self.recognised_commands
            if first_reply and code in _GREETING_CODES:
                self.greeting_observed = True
                self.add_event(
                    ProtocolEventType.SERVER_GREETING,
                    span,
                    f"SMTP server greeting with reply code {code}. The banner text is not "
                    "recorded.",
                    reply_code=code,
                )
                return
            if first_reply:
                # A first reply that is not a greeting code means the capture
                # began mid-dialogue; it is not labelled a greeting.
                self.add_event(
                    ProtocolEventType.SERVER_REPLY,
                    span,
                    f"The first observed server reply is {code}, which is not a session "
                    "greeting; the capture began after this session started.",
                    reply_code=code,
                    status=EvidenceStatus.OBSERVED,
                )
                return
            self.ctx.sink.add(
                WarningCode.PROTOCOL_UNSOLICITED_REPLY,
                f"An SMTP reply {code} arrived with no command outstanding at server "
                f"stream offset {span.start_offset}; it is not matched to any command.",
                session_id=self.ctx.session_id,
                packet_refs=span.packet_refs,
                stream_offset=span.start_offset,
            )
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                span,
                f"Unsolicited SMTP reply {code}; no command was outstanding.",
                reply_code=code,
                status=EvidenceStatus.OBSERVED,
            )
            return

        command = self.pending[0]

        # Intermediate replies keep their command outstanding.
        if command.verb == "DATA" and code == "354":
            self._in_data_body = True
            self._data_bytes = 0
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                span,
                "Server replied 354; the client's following bytes are message content and "
                "are not parsed as commands.",
                reply_code=code,
            )
            return
        if command.is_auth and code == "334":
            self._awaiting_auth_continuation = True
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                span,
                "Server issued a 334 SASL challenge. The challenge payload is not recorded.",
                reply_code=code,
            )
            return

        self.pending.pop(0)
        self.matched_exchanges += 1

        if command.is_upgrade:
            self._resolve_upgrade(span, code)
            return
        if command.is_auth:
            self._finish_auth(span, code)
            return

        capabilities: tuple[str, ...] = ()
        if command.verb in {"EHLO", "HELO"}:
            capabilities = self._extract_capabilities(lines)
        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            span,
            f"Server reply {code} to {command.verb}.",
            reply_code=code,
            command_verb=command.verb,
            capabilities=capabilities,
        )
        if capabilities:
            self._record_capabilities(lines, capabilities)

    def _extract_capabilities(self, lines: list[StreamLine]) -> tuple[str, ...]:
        """Extension keywords from an EHLO reply.

        RFC 5321 puts the server domain on the first line of the reply, so it
        is skipped: it is identity, not a capability, and it is not recorded.
        """
        capabilities: list[str] = []
        for line in lines[1:]:
            token, _ = _split_token(line.content[4:])
            keyword = safe_capability(token)
            if keyword:
                capabilities.append(keyword)
            if len(capabilities) >= 64:
                break
        return tuple(capabilities)

    def _record_capabilities(self, lines: list[StreamLine], capabilities: tuple[str, ...]) -> None:
        self.add_event(
            ProtocolEventType.CAPABILITY_ADVERTISEMENT,
            merge_span(lines),
            f"The server advertised {len(capabilities)} SMTP extension(s).",
            capabilities=capabilities,
        )
        if "STARTTLS" not in capabilities:
            return
        self.upgrade_seen = True
        for line in lines[1:]:
            token, _ = _split_token(line.content[4:])
            if safe_capability(token) == "STARTTLS":
                self.advertised_event = self.add_event(
                    ProtocolEventType.UPGRADE_ADVERTISED,
                    line,
                    "The server advertised the STARTTLS extension (RFC 3207). Advertisement "
                    "alone does not mean the upgrade was used.",
                    capabilities=("STARTTLS",),
                )
                break

    def _resolve_upgrade(self, span: StreamLine, code: str) -> None:
        self.response_code = code
        if code == _STARTTLS_ACCEPT:
            self.upgrade_outcome = "ACCEPTED"
            self.response_event = self.add_event(
                ProtocolEventType.UPGRADE_ACCEPTED,
                span,
                "The server returned 220 to STARTTLS, so it agreed to begin TLS. Plaintext "
                "SMTP parsing stops at the end of this reply. This is not evidence that a "
                "TLS handshake completed.",
                reply_code=code,
                command_verb="STARTTLS",
            )
            self._halt = True
            return
        if code == _STARTTLS_TEMPORARY or code.startswith("4"):
            self.upgrade_outcome = "TEMPORARY"
            self.response_event = self.add_event(
                ProtocolEventType.UPGRADE_TEMPORARY_FAILURE,
                span,
                f"The server returned {code} to STARTTLS, a temporary failure. TLS was not "
                "started and the session continues in plaintext.",
                reply_code=code,
                command_verb="STARTTLS",
            )
            return
        if code.startswith("5"):
            self.upgrade_outcome = "REJECTED"
            self.response_event = self.add_event(
                ProtocolEventType.UPGRADE_REJECTED,
                span,
                f"The server returned {code} to STARTTLS, a permanent rejection. TLS was "
                "not started and the session continues in plaintext.",
                reply_code=code,
                command_verb="STARTTLS",
            )
            return
        self.response_event = self.add_event(
            ProtocolEventType.SERVER_REPLY,
            span,
            f"The server returned {code} to STARTTLS, which RFC 3207 does not define for "
            "this command. The outcome is not determined.",
            reply_code=code,
            command_verb="STARTTLS",
            status=EvidenceStatus.UNKNOWN,
        )
        self.mark_negotiation_unsafe()

    def _finish_auth(self, span: StreamLine, code: str) -> None:
        self._awaiting_auth_continuation = False
        if self.auth and self._auth_continuations:
            last = self.auth[-1]
            self.auth[-1] = last.model_copy(
                update={"continuation_exchanges": self._auth_continuations}
            )
        self._auth_continuations = 0
        outcome = "succeeded" if code == "235" else "did not succeed"
        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            span,
            f"Server reply {code} to AUTH; the attempt {outcome}. No credential material "
            "is recorded.",
            reply_code=code,
            command_verb="AUTH",
        )

    # -- shared ------------------------------------------------------------
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
            f"An SMTP {what} at stream offset {line.start_offset} is not usable as "
            f"evidence: {reason}.",
            status=EvidenceStatus.UNKNOWN,
            limitations=("The record is not interpreted and no state is derived from it.",),
        )


def _split_token(data: bytes) -> tuple[bytes, bytes]:
    """First whitespace-delimited token and the remainder."""
    stripped = data.lstrip(b" \t")
    index = 0
    while index < len(stripped) and stripped[index : index + 1] not in (b" ", b"\t"):
        index += 1
    return stripped[:index], stripped[index:].lstrip(b" \t")
