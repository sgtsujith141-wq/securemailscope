"""IMAP dialogue parser (RFC 9051, RFC 3501, RFC 2595).

The parts that are easy to get wrong:

* **Tag matching.**  Every client command carries a tag and its completion
  carries the same tag.  A tagged ``OK`` only resolves ``STARTTLS`` when the
  tags match; an ``OK`` for some other command must never be read as
  acceptance.  Untagged (``*``) responses never complete a command.
* **Literals.**  A line ending in ``{n}`` or ``{n+}`` is followed by exactly
  ``n`` bytes of data and then the rest of the command.  Those bytes are
  skipped by length, so a literal containing the text ``a1 STARTTLS`` cannot
  be mistaken for a command.  A literal that runs past a TCP gap, or past the
  configured size cap, stops parsing rather than guessing where it ended.
* **Capabilities in the greeting.**  Servers commonly put
  ``[CAPABILITY ... STARTTLS ...]`` in the greeting, so the advertisement is
  looked for there as well as in ``* CAPABILITY`` responses.
* **AUTHENTICATE continuations.**  After a ``+`` continuation the client's
  next line is credential material; it is counted and discarded.
"""

from __future__ import annotations

from ..models.evidence import EvidenceStatus, Severity, WarningCode
from ..models.protocol import (
    EmailProtocol,
    ParseState,
    ProtocolEventType,
    UpgradeMechanism,
)
from ..models.tcp import Direction
from .base import ParseContext, ParseOutcome, PendingCommand, ProtocolParser
from .reader import DialogueDriver, StreamCursor, StreamLine
from .redaction import IMAP_VERBS, safe_capability, safe_mechanism, safe_tag, safe_verb

__all__ = ["IMAPParser"]

_GREETING_STATUSES = frozenset({"OK", "PREAUTH", "BYE"})
_COMPLETION_STATUSES = frozenset({"OK", "NO", "BAD"})


class IMAPParser(ProtocolParser):
    protocol = EmailProtocol.IMAP
    mechanism = UpgradeMechanism.STARTTLS

    def __init__(self, context: ParseContext) -> None:
        super().__init__(context)
        self._awaiting_auth_continuation = False
        self._auth_continuations = 0
        self._halt = False
        self._driver: DialogueDriver | None = None

    def run(self) -> ParseOutcome:
        driver = DialogueDriver(
            StreamCursor(self.ctx.client, self.ctx.config, self.ctx.sink, self.ctx.session_id),
            StreamCursor(self.ctx.server, self.ctx.config, self.ctx.sink, self.ctx.session_id),
        )
        self._driver = driver
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
        return ParseState.INCOMPLETE if self.pending else ParseState.COMPLETE

    # -- literals ----------------------------------------------------------
    def _consume_literal(self, line: StreamLine, direction: Direction) -> bool:
        """Skip a trailing ``{n}`` literal. Returns False if parsing must stop."""
        declared = _literal_length(line.content)
        if declared is None:
            return True
        assert self._driver is not None
        cursor = self._driver.cursor(direction)
        if declared > self.ctx.config.max_literal_bytes:
            self.ctx.sink.add(
                WarningCode.LIMIT_LITERAL_BYTES,
                f"An IMAP literal of {declared} bytes exceeds the "
                f"{self.ctx.config.max_literal_bytes}-byte limit; parsing stops rather than "
                "resuming at a guessed offset.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
                declared_length=declared,
            )
            self.state = ParseState.INDETERMINATE
            self.extra_limitations.append(
                "An oversized IMAP literal prevented the parser from locating the resumption "
                "point; nothing after it is interpreted."
            )
            return False

        outcome = cursor.skip_bytes(declared)
        self.add_event(
            ProtocolEventType.LITERAL_SKIPPED,
            line,
            f"An IMAP literal declaring {declared} byte(s) was skipped by length without "
            "interpretation. Literal contents are never parsed as commands or responses "
            "and are not recorded.",
            byte_count=outcome.skipped,
            end_offset=outcome.end_offset,
        )
        if outcome.complete:
            return True

        if outcome.stopped_at_gap:
            self.ctx.sink.add(
                WarningCode.PROTOCOL_GAP_IN_DIALOGUE,
                f"An IMAP literal declaring {declared} bytes runs into missing data at "
                f"{direction.value} stream offset {outcome.end_offset}; the command it "
                "belongs to cannot be resumed safely, so parsing stops here.",
                severity=Severity.ERROR,
                session_id=self.ctx.session_id,
                packet_refs=outcome.packet_refs,
                stream_offset=outcome.start_offset,
                declared_length=declared,
                skipped=outcome.skipped,
            )
        else:
            self.ctx.sink.add(
                WarningCode.PROTOCOL_GAP_IN_DIALOGUE,
                f"An IMAP literal declaring {declared} bytes runs past the end of the "
                f"captured {direction.value} stream; parsing stops rather than resuming at "
                "a guessed offset.",
                session_id=self.ctx.session_id,
                packet_refs=outcome.packet_refs,
                stream_offset=outcome.start_offset,
                declared_length=declared,
                skipped=outcome.skipped,
            )
        self.state = ParseState.INDETERMINATE
        self.extra_limitations.append(
            "An IMAP literal was cut short by missing data or the end of the capture, so "
            "the remainder of the dialogue is not interpreted."
        )
        self.mark_negotiation_unsafe()
        return False

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
        if not line.content.strip():
            # The bare CRLF that terminates a command continued by a literal.
            return

        tag_token, remainder = _split_token(line.content)
        tag = safe_tag(tag_token)
        verb_token, arguments = _split_token(remainder)
        verb = safe_verb(verb_token, IMAP_VERBS)

        if tag is None or verb is None:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A client line did not match the IMAP '<tag> <COMMAND>' grammar. Tokens are "
                "not reported because an unrecognised token may be credential material.",
            )
            self._consume_literal(line, Direction.CLIENT_TO_SERVER)
            return

        self.recognised_commands += 1
        is_upgrade = verb == "STARTTLS"
        is_auth = verb in {"LOGIN", "AUTHENTICATE"}
        mechanism = None
        if verb == "AUTHENTICATE":
            mechanism_token, _ = _split_token(arguments)
            mechanism = safe_mechanism(mechanism_token)

        self.pending.append(
            PendingCommand(
                verb=verb,
                tag=tag,
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
                f"The client issued STARTTLS with tag {tag}. Only a matching tagged OK "
                "accepts it.",
                command_verb=verb,
                tag=tag,
            )
        elif is_auth:
            self.add_event(
                ProtocolEventType.AUTHENTICATION_COMMAND,
                line,
                f"An IMAP {verb} command was observed."
                + (f" Mechanism: {mechanism}." if mechanism else ""),
                command_verb=verb,
                tag=tag,
            )
            self.record_auth(line, verb, mechanism)
        elif verb == "LOGOUT":
            self.add_event(
                ProtocolEventType.SESSION_TERMINATION,
                line,
                "The client issued LOGOUT.",
                command_verb=verb,
                tag=tag,
            )
        else:
            self.add_event(
                ProtocolEventType.CLIENT_COMMAND,
                line,
                f"Client command {verb} observed with tag {tag}.",
                command_verb=verb,
                tag=tag,
            )
        self._consume_literal(line, Direction.CLIENT_TO_SERVER)

    # -- server ------------------------------------------------------------
    def _server_line(self, line: StreamLine) -> None:
        if not line.usable:
            self._unusable(line, "server response")
            return

        first, remainder = _split_token(line.content)

        if first == b"+":
            if any(command.is_auth for command in self.pending):
                self._awaiting_auth_continuation = True
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                line,
                "Server sent a '+' continuation request. Any challenge payload is not "
                "recorded.",
                reply_code="+",
            )
            self._consume_literal(line, Direction.SERVER_TO_CLIENT)
            return

        if first == b"*":
            self._untagged(line, remainder)
            self._consume_literal(line, Direction.SERVER_TO_CLIENT)
            return

        tag = safe_tag(first)
        status_token, rest = _split_token(remainder)
        status = status_token.decode("ascii", errors="replace").upper()
        if tag is None or status not in _COMPLETION_STATUSES:
            self.foreign_lines += 1
            self.add_event(
                ProtocolEventType.PARSE_DESYNCHRONISED,
                line,
                "A server line matched neither an untagged response nor a tagged completion.",
            )
            return
        self._complete_command(line, tag, status, rest)

    def _untagged(self, line: StreamLine, remainder: bytes) -> None:
        keyword_token, rest = _split_token(remainder)
        keyword = keyword_token.decode("ascii", errors="replace").upper()

        first_response = not self.greeting_observed and not self.recognised_commands
        if first_response and keyword in _GREETING_STATUSES:
            self.greeting_observed = True
            capabilities = _capabilities_in_brackets(rest)
            self.add_event(
                ProtocolEventType.SERVER_GREETING,
                line,
                f"IMAP server greeting '* {keyword}'. The banner text is not recorded.",
                reply_code=keyword,
                capabilities=capabilities,
            )
            if capabilities:
                self._note_capabilities(line, capabilities)
            return

        if keyword == "CAPABILITY":
            capabilities = _capability_tokens(rest)
            self.add_event(
                ProtocolEventType.CAPABILITY_ADVERTISEMENT,
                line,
                f"The server advertised {len(capabilities)} IMAP capability keyword(s).",
                capabilities=capabilities,
            )
            self._note_capabilities(line, capabilities)
            return

        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            line,
            f"Untagged server response '* {keyword}'. Untagged responses do not complete "
            "a command.",
            reply_code=keyword if keyword.isalpha() else None,
        )

    def _note_capabilities(self, line: StreamLine, capabilities: tuple[str, ...]) -> None:
        if "STARTTLS" not in capabilities:
            return
        self.upgrade_seen = True
        if self.advertised_event is None:
            self.advertised_event = self.add_event(
                ProtocolEventType.UPGRADE_ADVERTISED,
                line,
                "The server advertised the STARTTLS capability (RFC 2595 / RFC 9051). "
                "Advertisement alone does not mean the upgrade was used.",
                capabilities=("STARTTLS",),
            )

    def _complete_command(
        self, line: StreamLine, tag: str, status: str, rest: bytes
    ) -> None:
        match = next((c for c in self.pending if c.tag == tag), None)
        if match is None:
            self.ctx.sink.add(
                WarningCode.PROTOCOL_UNSOLICITED_REPLY,
                f"A tagged IMAP completion for tag {tag} arrived with no matching "
                f"outstanding command at server stream offset {line.start_offset}.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
            )
            self.add_event(
                ProtocolEventType.SERVER_REPLY,
                line,
                f"Tagged completion '{status}' for tag {tag} matched no outstanding command; "
                "it is not treated as a response to any command.",
                reply_code=status,
                tag=tag,
            )
            return

        # Anything still queued ahead of the match was never answered.
        index = self.pending.index(match)
        if index > 0:
            for skipped in self.pending[:index]:
                if skipped.is_upgrade:
                    self.ctx.sink.add(
                        WarningCode.UPGRADE_TAG_MISMATCH,
                        f"A tagged completion for {tag} was matched while the STARTTLS "
                        f"command with tag {skipped.tag} was still outstanding; the "
                        "completion is not treated as accepting STARTTLS.",
                        session_id=self.ctx.session_id,
                        packet_refs=line.packet_refs,
                    )
        del self.pending[: index + 1]
        self.matched_exchanges += 1

        if match.is_upgrade:
            self._resolve_upgrade(line, tag, status)
            return
        if match.is_auth:
            self._finish_auth(line, tag, status)
            return
        if match.verb == "CAPABILITY":
            capabilities = _capability_tokens(rest)
            if capabilities:
                self._note_capabilities(line, capabilities)
        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            line,
            f"Tagged completion {status} for {match.verb} (tag {tag}).",
            reply_code=status,
            tag=tag,
            command_verb=match.verb,
        )

    def _resolve_upgrade(self, line: StreamLine, tag: str, status: str) -> None:
        self.response_code = status
        if status == "OK":
            self.upgrade_outcome = "ACCEPTED"
            self.response_event = self.add_event(
                ProtocolEventType.UPGRADE_ACCEPTED,
                line,
                f"The server returned a tagged OK for STARTTLS tag {tag}, so it agreed to "
                "begin TLS. Plaintext IMAP parsing stops at the end of this response. This "
                "is not evidence that a TLS handshake completed.",
                reply_code=status,
                tag=tag,
                command_verb="STARTTLS",
            )
            self._halt = True
            return
        self.upgrade_outcome = "REJECTED"
        self.response_event = self.add_event(
            ProtocolEventType.UPGRADE_REJECTED,
            line,
            f"The server returned {status} for STARTTLS tag {tag}. TLS was not started and "
            "the session continues in plaintext.",
            reply_code=status,
            tag=tag,
            command_verb="STARTTLS",
        )

    def _finish_auth(self, line: StreamLine, tag: str, status: str) -> None:
        self._awaiting_auth_continuation = False
        if self.auth and self._auth_continuations:
            last = self.auth[-1]
            self.auth[-1] = last.model_copy(
                update={"continuation_exchanges": self._auth_continuations}
            )
        self._auth_continuations = 0
        self.add_event(
            ProtocolEventType.SERVER_REPLY,
            line,
            f"Tagged completion {status} for the authentication command (tag {tag}). No "
            "credential material is recorded.",
            reply_code=status,
            tag=tag,
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
            f"An IMAP {what} at stream offset {line.start_offset} is not usable as "
            f"evidence: {reason}.",
            status=EvidenceStatus.UNKNOWN,
        )


def _split_token(data: bytes) -> tuple[bytes, bytes]:
    stripped = data.lstrip(b" \t")
    index = 0
    while index < len(stripped) and stripped[index : index + 1] not in (b" ", b"\t"):
        index += 1
    return stripped[:index], stripped[index:].lstrip(b" \t")


def _literal_length(content: bytes) -> int | None:
    """Declared length of a trailing ``{n}`` or ``{n+}`` literal, if present."""
    if not content.endswith(b"}"):
        return None
    open_brace = content.rfind(b"{")
    if open_brace == -1:
        return None
    digits = content[open_brace + 1 : -1]
    if digits.endswith(b"+"):
        digits = digits[:-1]
    if not digits or not digits.isdigit() or len(digits) > 12:
        return None
    return int(digits)


def _capability_tokens(data: bytes) -> tuple[str, ...]:
    tokens: list[str] = []
    for raw in data.split(b" "):
        keyword = safe_capability(raw.strip())
        if keyword:
            tokens.append(keyword)
        if len(tokens) >= 64:
            break
    return tuple(tokens)


def _capabilities_in_brackets(data: bytes) -> tuple[str, ...]:
    """Capabilities from a greeting's ``[CAPABILITY ...]`` response code."""
    start = data.find(b"[")
    end = data.find(b"]", start + 1)
    if start == -1 or end == -1:
        return ()
    inner = data[start + 1 : end]
    keyword, rest = _split_token(inner)
    if keyword.upper() != b"CAPABILITY":
        return ()
    return _capability_tokens(rest)
