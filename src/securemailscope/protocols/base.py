"""Shared machinery for the SMTP, IMAP and POP3 parsers.

Three things live here because all three protocols need them and getting any
of them subtly different per protocol would be a correctness bug:

* **Outstanding-command tracking.**  A server reply is matched against the
  command that was actually pending when it arrived.  This is what stops a
  ``220`` meant for ``EHLO`` being read as acceptance of a later ``STARTTLS``.
* **Upgrade bookkeeping.**  Advertisement, request, response, the two
  independent directional boundaries, and the record-framing probe that
  follows -- plus the rule that any gap or ambiguity touching the negotiation
  downgrades the result to ``INCOMPLETE`` rather than claiming success.
* **Detection scoring.**  Each parser reports how much application-level
  evidence it actually found, so the analyzer can pick a winner on evidence
  rather than on the port number.

No parser stores line content. Events carry offsets, packet references and
allowlisted keywords only.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.evidence import EvidenceStatus, PacketReference, Severity, WarningCode
from ..models.protocol import (
    AuthenticationObservation,
    DetectionStatus,
    EmailProtocol,
    ParseState,
    ProtocolEvent,
    ProtocolEventType,
    TLSBoundary,
    TLSFramingEvidence,
    TLSRecordObservation,
    TLSUpgradeAttempt,
    UpgradeMechanism,
    UpgradeState,
)
from ..models.tcp import Direction
from .framing import probe_tls_records
from .reader import DialogueDriver, DirectionalBuffer, StreamLine

__all__ = ["ParseContext", "ParseOutcome", "ProtocolParser", "PendingCommand"]

_STRONG_FRAMING = frozenset(
    {
        TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO,
        TLSFramingEvidence.HANDSHAKE_SERVER_HELLO,
        TLSFramingEvidence.RECORD_CHAIN,
        TLSFramingEvidence.HANDSHAKE_RECORD,
    }
)

_UPGRADE_LIMITATIONS: tuple[str, ...] = (
    "An accepted upgrade means the server agreed to begin TLS. It does not "
    "mean a TLS handshake completed or that the connection was encrypted.",
    "TLS handshake reconstruction, version negotiation and certificate "
    "analysis are not implemented (planned for M3).",
)


@dataclass(frozen=True, slots=True)
class ParseContext:
    session_id: str
    capture_id: str
    config: AnalysisConfig
    sink: WarningSink
    client: DirectionalBuffer
    server: DirectionalBuffer
    server_port: int


@dataclass(slots=True)
class PendingCommand:
    """A client command awaiting its server response."""

    verb: str | None
    tag: str | None
    line: StreamLine
    is_upgrade: bool = False
    is_auth: bool = False
    mechanism: str | None = None


@dataclass
class ParseOutcome:
    """What one parser found, and how strongly."""

    protocol: EmailProtocol
    state: ParseState
    events: tuple[ProtocolEvent, ...]
    upgrade: TLSUpgradeAttempt | None
    authentication: tuple[AuthenticationObservation, ...]
    limitations: tuple[str, ...]

    greeting_observed: bool
    matched_exchanges: int
    recognised_commands: int
    foreign_lines: int
    client_plaintext_end: int | None
    server_plaintext_end: int | None
    evidence_refs: tuple[PacketReference, ...]
    evidence_summary: tuple[str, ...]

    @property
    def evidence_score(self) -> int:
        """Higher means stronger application-level evidence for this protocol."""
        score = 4 if self.greeting_observed else 0
        score += 3 * min(self.matched_exchanges, 4)
        score += min(self.recognised_commands, 5)
        if self.upgrade is not None:
            score += 2
        score -= 2 * min(self.foreign_lines, 3)
        return max(score, 0)

    @property
    def detection_status(self) -> DetectionStatus:
        if self.matched_exchanges >= 1 and self.greeting_observed:
            return DetectionStatus.CONFIRMED
        if self.matched_exchanges >= 2:
            return DetectionStatus.CONFIRMED
        if self.greeting_observed or self.matched_exchanges >= 1:
            return DetectionStatus.PROBABLE
        if self.recognised_commands >= 1:
            return DetectionStatus.PROBABLE
        return DetectionStatus.UNKNOWN

    @property
    def confidence_basis(self) -> str:
        if self.matched_exchanges >= 1 and self.greeting_observed:
            return "GREETING_AND_MATCHED_EXCHANGE"
        if self.matched_exchanges >= 2:
            return "MATCHED_EXCHANGES_WITHOUT_GREETING"
        if self.greeting_observed:
            return "GREETING_ONLY"
        if self.matched_exchanges == 1:
            return "SINGLE_MATCHED_EXCHANGE"
        if self.recognised_commands >= 1:
            return "RECOGNISED_COMMANDS_ONLY"
        return "NO_APPLICATION_EVIDENCE"


class ProtocolParser:
    """Base class driving one protocol's dialogue over a :class:`DialogueDriver`."""

    protocol: EmailProtocol = EmailProtocol.UNKNOWN
    mechanism: UpgradeMechanism = UpgradeMechanism.STARTTLS

    def __init__(self, context: ParseContext) -> None:
        self.ctx = context
        self.events: list[ProtocolEvent] = []
        self.auth: list[AuthenticationObservation] = []
        self.pending: list[PendingCommand] = []

        self.greeting_observed = False
        self.matched_exchanges = 0
        self.recognised_commands = 0
        self.foreign_lines = 0
        self.events_suppressed = 0

        self.advertised_event: ProtocolEvent | None = None
        self.requested_event: ProtocolEvent | None = None
        self.response_event: ProtocolEvent | None = None
        self.response_code: str | None = None
        self.upgrade_outcome: str | None = None  # ACCEPTED | REJECTED | TEMPORARY
        self.gap_during_negotiation = False
        self.upgrade_seen = False
        #: True once any hole has interrupted the dialogue. A parse that
        #: lost state to a gap is never 'complete', even if it tidily ran
        #: out of input afterwards.
        self.gap_seen = False

        self.client_plaintext_end: int | None = None
        self.server_plaintext_end: int | None = None
        self.state = ParseState.NOT_APPLICABLE
        self.extra_limitations: list[str] = []

    # -- event recording ---------------------------------------------------
    def add_event(
        self,
        event_type: ProtocolEventType,
        line: StreamLine,
        detail: str,
        *,
        status: EvidenceStatus = EvidenceStatus.OBSERVED,
        command_verb: str | None = None,
        reply_code: str | None = None,
        tag: str | None = None,
        capabilities: tuple[str, ...] = (),
        byte_count: int | None = None,
        end_offset: int | None = None,
        limitations: tuple[str, ...] = (),
    ) -> ProtocolEvent | None:
        if len(self.events) >= self.ctx.config.max_protocol_events_per_session:
            if self.events_suppressed == 0:
                self.ctx.sink.add(
                    WarningCode.LIMIT_PROTOCOL_EVENTS,
                    f"Session reached the {self.ctx.config.max_protocol_events_per_session}"
                    "-event protocol limit; later protocol events are not recorded.",
                    severity=Severity.ERROR,
                    session_id=self.ctx.session_id,
                    limit=self.ctx.config.max_protocol_events_per_session,
                )
            self.events_suppressed += 1
            return None
        event = ProtocolEvent(
            event_type=event_type,
            protocol=self.protocol,
            direction=line.direction,
            stream_offset=line.start_offset,
            end_offset=end_offset if end_offset is not None else line.end_offset,
            packet_refs=line.packet_refs,
            first_timestamp=line.first_timestamp,
            last_timestamp=line.last_timestamp,
            status=status,
            command_verb=command_verb,
            reply_code=reply_code,
            tag=tag,
            capabilities=capabilities,
            byte_count=byte_count,
            detail=detail,
            complete=line.complete and not line.truncated,
            ambiguous=line.ambiguous,
            limitations=limitations,
        )
        self.events.append(event)
        return event

    def note_gap(self, line: StreamLine) -> None:
        """Record a hole immediately before ``line`` and invalidate pending state."""
        self.gap_seen = True
        self.add_event(
            ProtocolEventType.GAP_ENCOUNTERED,
            line,
            f"{line.gap_length} byte(s) are missing from the {line.direction.value} stream "
            f"immediately before stream offset {line.start_offset}. Protocol state before "
            "the gap is not carried across it.",
            status=EvidenceStatus.OBSERVED,
            end_offset=line.start_offset,
            limitations=(
                "Records that began before the gap are reported incomplete and are not "
                "reconstructed from the bytes after it.",
            ),
        )
        if self.pending:
            self.gap_during_negotiation = self.gap_during_negotiation or any(
                command.is_upgrade for command in self.pending
            )
            # A reply arriving after a hole cannot be matched to a command that
            # was outstanding before it.
            self.pending.clear()
            self.ctx.sink.add(
                WarningCode.PROTOCOL_DESYNCHRONISED,
                f"Missing data at {line.direction.value} stream offset {line.start_offset} "
                "left commands outstanding; they are not matched against any later reply.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
            )

    # -- upgrade bookkeeping -----------------------------------------------
    def mark_negotiation_unsafe(self) -> None:
        self.gap_during_negotiation = True

    def _upgrade_state(self) -> UpgradeState:
        if self.gap_during_negotiation and self.requested_event is not None:
            return UpgradeState.INCOMPLETE
        if self.upgrade_outcome == "ACCEPTED":
            return UpgradeState.UPGRADE_ACCEPTED
        if self.upgrade_outcome in {"REJECTED", "TEMPORARY"}:
            return UpgradeState.UPGRADE_REJECTED
        if self.requested_event is not None:
            return UpgradeState.UPGRADE_REQUESTED
        if self.advertised_event is not None:
            return UpgradeState.UPGRADE_ADVERTISED
        return UpgradeState.PLAINTEXT

    def _probe_client_tls(self, after_offset: int) -> tuple[
        TLSBoundary | None, tuple[TLSRecordObservation, ...]
    ]:
        """Find where the client's TLS bytes actually begin.

        The end of the upgrade command is where they are *expected*, not where
        they are assumed to be: the offset is only reported once record framing
        validates there. If a hole intervenes, the first run after it is tried
        and the result is downgraded to ``INFERRED``.
        """
        records = probe_tls_records(
            self.ctx.client,
            after_offset,
            direction=Direction.CLIENT_TO_SERVER,
            max_records=self.ctx.config.max_tls_records_probed,
        )
        if records:
            return (
                TLSBoundary(
                    direction=Direction.CLIENT_TO_SERVER,
                    stream_offset=after_offset,
                    basis="FIRST_TLS_RECORD",
                    packet_ref=records[0].packet_refs[0] if records[0].packet_refs else None,
                    timestamp=records[0].packet_refs[0].timestamp
                    if records[0].packet_refs
                    else None,
                    status=EvidenceStatus.OBSERVED,
                ),
                records,
            )
        for run_start, _ in self.ctx.client.runs:
            if run_start <= after_offset:
                continue
            candidate = probe_tls_records(
                self.ctx.client,
                run_start,
                direction=Direction.CLIENT_TO_SERVER,
                max_records=self.ctx.config.max_tls_records_probed,
            )
            if candidate:
                return (
                    TLSBoundary(
                        direction=Direction.CLIENT_TO_SERVER,
                        stream_offset=run_start,
                        basis="FIRST_TLS_RECORD",
                        packet_ref=candidate[0].packet_refs[0]
                        if candidate[0].packet_refs
                        else None,
                        timestamp=candidate[0].packet_refs[0].timestamp
                        if candidate[0].packet_refs
                        else None,
                        status=EvidenceStatus.INFERRED,
                    ),
                    candidate,
                )
            break
        return None, ()

    def build_upgrade(self) -> TLSUpgradeAttempt | None:
        if not self.upgrade_seen:
            return None

        state = self._upgrade_state()
        notes: list[str] = []
        limitations = list(_UPGRADE_LIMITATIONS)
        server_boundary: TLSBoundary | None = None
        client_boundary: TLSBoundary | None = None
        records: list[TLSRecordObservation] = []

        if self.upgrade_outcome == "ACCEPTED" and self.response_event is not None:
            server_offset = self.response_event.end_offset
            server_boundary = TLSBoundary(
                direction=Direction.SERVER_TO_CLIENT,
                stream_offset=server_offset,
                basis="SERVER_SUCCESS_REPLY_END",
                packet_ref=self.response_event.packet_refs[-1]
                if self.response_event.packet_refs
                else None,
                timestamp=self.response_event.last_timestamp,
                status=EvidenceStatus.OBSERVED,
            )
            server_records = probe_tls_records(
                self.ctx.server,
                server_offset,
                direction=Direction.SERVER_TO_CLIENT,
                max_records=self.ctx.config.max_tls_records_probed,
            )
            records.extend(server_records)
            if server_records:
                notes.append(
                    "TLS record framing begins in the server stream immediately after the "
                    "success reply; those bytes are preserved for TLS analysis."
                )

            if self.requested_event is not None:
                client_boundary, client_records = self._probe_client_tls(
                    self.requested_event.end_offset
                )
                records.extend(client_records)
                if client_boundary is None:
                    client_boundary = TLSBoundary(
                        direction=Direction.CLIENT_TO_SERVER,
                        stream_offset=self.requested_event.end_offset,
                        basis="NOT_OBSERVED",
                        status=EvidenceStatus.UNKNOWN,
                    )
                    notes.append(
                        "No TLS record framing was observed in the client stream after the "
                        "upgrade command, so the client's transition offset is not "
                        "established; the end of the command is not assumed to be it."
                    )
                elif client_boundary.status is EvidenceStatus.INFERRED:
                    notes.append(
                        "Missing data separates the upgrade command from the first client "
                        "TLS bytes, so the client transition offset is inferred."
                    )

            strong = any(record.evidence in _STRONG_FRAMING for record in records)
            if strong and state is UpgradeState.UPGRADE_ACCEPTED:
                state = UpgradeState.TLS_BYTES_OBSERVED
            elif not records:
                self.ctx.sink.add(
                    WarningCode.UPGRADE_ACCEPTED_WITHOUT_TLS_BYTES,
                    f"The server accepted {self.mechanism.value} but no TLS record framing "
                    "follows in this capture; the capture may simply end here. An accepted "
                    "upgrade is not evidence that TLS was established.",
                    severity=Severity.INFO,
                    session_id=self.ctx.session_id,
                    packet_refs=self.response_event.packet_refs,
                )
                notes.append(
                    "The upgrade was accepted but no TLS bytes appear afterwards in this "
                    "capture."
                )
            elif not strong:
                self.ctx.sink.add(
                    WarningCode.TLS_FRAMING_WEAK_EVIDENCE,
                    "Bytes after the upgrade acceptance are consistent with a TLS record "
                    "header but too weak to treat as observed TLS.",
                    severity=Severity.INFO,
                    session_id=self.ctx.session_id,
                )
                notes.append(
                    "Post-upgrade bytes matched a record header only weakly; TLS is not "
                    "treated as observed."
                )

        if state is UpgradeState.UPGRADE_REQUESTED and self.response_event is None:
            self.ctx.sink.add(
                WarningCode.UPGRADE_REQUEST_WITHOUT_RESPONSE,
                f"A {self.mechanism.value} command was issued but no matching server "
                "response appears in this capture; the outcome is unknown.",
                session_id=self.ctx.session_id,
                packet_refs=self.requested_event.packet_refs
                if self.requested_event
                else (),
            )
            notes.append("No server response to the upgrade command was observed.")

        if state is UpgradeState.INCOMPLETE:
            notes.append(
                "Missing or ambiguous data during the negotiation prevents any conclusion "
                "about whether the upgrade succeeded."
            )
            limitations.append(
                "A gap or overlap conflict touched the negotiation, so success cannot be "
                "claimed even though a response may appear present."
            )

        if state in {UpgradeState.UPGRADE_REJECTED, UpgradeState.PLAINTEXT}:
            limitations.append(
                "A rejected or absent upgrade is recorded as an observation only. Whether "
                "that constitutes a security weakness is an M4 assessment question."
            )

        return TLSUpgradeAttempt(
            mechanism=self.mechanism,
            protocol=self.protocol,
            state=state,
            advertised=self.advertised_event,
            requested=self.requested_event,
            response=self.response_event,
            response_code=self.response_code,
            server_boundary=server_boundary,
            client_boundary=client_boundary,
            tls_records=tuple(records),
            notes=tuple(notes),
            limitations=tuple(limitations),
        )

    # -- authentication ----------------------------------------------------
    def record_auth(
        self,
        line: StreamLine,
        verb: str,
        mechanism: str | None,
        *,
        continuation_exchanges: int = 0,
    ) -> None:
        state = self._upgrade_state()
        before_upgrade = state not in {
            UpgradeState.UPGRADE_ACCEPTED,
            UpgradeState.TLS_BYTES_OBSERVED,
        }
        limitations = [
            "No credential material is recorded: usernames, passwords, base64 tokens "
            "and SASL payloads are discarded during parsing.",
        ]
        if before_upgrade:
            limitations.append(
                "The attempt was observed in plaintext. Whether that is a finding is an "
                "M4 assessment question; this is an observation only."
            )
            self.ctx.sink.add(
                WarningCode.PLAINTEXT_AUTHENTICATION_OBSERVED,
                f"Observed a plaintext {self.protocol.value} authentication command "
                f"({verb}) at {line.direction.value} stream offset {line.start_offset} "
                "with no accepted TLS upgrade in effect. No credential material was "
                "recorded.",
                session_id=self.ctx.session_id,
                packet_refs=line.packet_refs,
                stream_offset=line.start_offset,
                command_verb=verb,
            )
        else:
            limitations.append(
                "The attempt followed an accepted TLS upgrade. This capture does not "
                "establish that the TLS handshake completed, so confidentiality of the "
                "credential is not confirmed."
            )
        self.auth.append(
            AuthenticationObservation(
                protocol=self.protocol,
                command_verb=verb,
                mechanism=mechanism,
                direction=line.direction,
                stream_offset=line.start_offset,
                packet_refs=line.packet_refs,
                timestamp=line.first_timestamp,
                occurred_before_tls_upgrade=before_upgrade,
                upgrade_state_at_attempt=state,
                continuation_exchanges=continuation_exchanges,
                limitations=tuple(limitations),
            )
        )

    # -- driving -----------------------------------------------------------
    def run(self) -> ParseOutcome:
        raise NotImplementedError  # pragma: no cover

    def _evidence_refs(self) -> tuple[PacketReference, ...]:
        seen: dict[int, PacketReference] = {}
        for event in self.events:
            if event.event_type in {
                ProtocolEventType.SERVER_GREETING,
                ProtocolEventType.CLIENT_COMMAND,
                ProtocolEventType.SERVER_REPLY,
                ProtocolEventType.UPGRADE_REQUESTED,
                ProtocolEventType.UPGRADE_ACCEPTED,
            }:
                for ref in event.packet_refs:
                    seen.setdefault(ref.packet_number, ref)
            if len(seen) >= 8:
                break
        return tuple(seen[number] for number in sorted(seen))

    def _evidence_summary(self) -> tuple[str, ...]:
        summary: list[str] = []
        if self.greeting_observed:
            summary.append(f"A conforming {self.protocol.value} server greeting was parsed.")
        if self.recognised_commands:
            summary.append(
                f"{self.recognised_commands} client command(s) matched the "
                f"{self.protocol.value} command grammar."
            )
        if self.matched_exchanges:
            summary.append(
                f"{self.matched_exchanges} command(s) were matched to their server response "
                "in capture order."
            )
        if self.foreign_lines:
            summary.append(
                f"{self.foreign_lines} line(s) did not fit the {self.protocol.value} grammar."
            )
        if not summary:
            summary.append(f"No {self.protocol.value} application evidence was found.")
        return tuple(summary)

    def finish(self, state: ParseState) -> ParseOutcome:
        upgrade = self.build_upgrade()
        if self.events_suppressed:
            self.extra_limitations.append(
                f"{self.events_suppressed} protocol event(s) were not recorded because the "
                "per-session event limit was reached."
            )
        return ParseOutcome(
            protocol=self.protocol,
            state=state,
            events=tuple(self.events),
            upgrade=upgrade,
            authentication=tuple(self.auth),
            limitations=tuple(self.extra_limitations),
            greeting_observed=self.greeting_observed,
            matched_exchanges=self.matched_exchanges,
            recognised_commands=self.recognised_commands,
            foreign_lines=self.foreign_lines,
            client_plaintext_end=self.client_plaintext_end,
            server_plaintext_end=self.server_plaintext_end,
            evidence_refs=self._evidence_refs(),
            evidence_summary=self._evidence_summary(),
        )

    def halt_plaintext(
        self, driver: DialogueDriver, *, client_end: int | None, server_end: int | None
    ) -> None:
        """Stop reading plaintext in both directions at a TLS boundary.

        The offsets are the exact transition points the parser determined, not
        wherever the cursors happened to be: the server stops after its success
        reply, the client after its upgrade command.
        """
        self.client_plaintext_end = client_end
        self.server_plaintext_end = server_end
        driver.stop_all()
