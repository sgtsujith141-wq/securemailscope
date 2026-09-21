"""Per-session protocol analysis: run the parsers, pick a winner on evidence.

All three parsers are run speculatively against the same reconstructed
streams and each reports how much application-level evidence it actually
found.  The winner is chosen by that evidence, not by the port number, which
is what lets the engine identify SMTP on port 8025 and refuse to call a
session IMAP just because it is on port 143.

Losing parsers must not pollute the output, so each runs against a throwaway
:class:`~securemailscope.diagnostics.WarningSink` and only the winner's
diagnostics are kept.

Implicit TLS is handled separately and deliberately weakly: observing TLS
record framing from the first byte establishes that the session is *encrypted
from the start*, and nothing at all about which email protocol is inside it.
On those sessions the protocol can never be better than a port hint.
"""

from __future__ import annotations

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.evidence import AnalysisWarning, EvidenceStatus, PacketReference
from ..models.protocol import (
    DetectionStatus,
    EmailProtocol,
    ImplicitTLSObservation,
    ParseState,
    ProtocolDetection,
    ProtocolInventory,
    ProtocolSessionAnalysis,
    TLSFramingEvidence,
    TLSRecordObservation,
    UpgradeState,
)
from ..models.tcp import Direction, TCPSession
from .base import ParseContext, ParseOutcome
from .framing import probe_tls_records
from .hints import IMPLICIT_TLS_PORTS, protocol_for_port
from .imap import IMAPParser
from .pop3 import POP3Parser
from .reader import DirectionalBuffer
from .smtp import SMTPParser

__all__ = ["analyze_session", "build_inventory"]

_PARSERS = (SMTPParser, IMAPParser, POP3Parser)

_STRONG_FRAMING = frozenset(
    {
        TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO,
        TLSFramingEvidence.HANDSHAKE_SERVER_HELLO,
        TLSFramingEvidence.RECORD_CHAIN,
        TLSFramingEvidence.HANDSHAKE_RECORD,
    }
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    "Only plaintext application traffic is parsed. Encrypted payload is never decoded.",
    "TLS handshake reconstruction, cipher suite and certificate analysis are not "
    "implemented (planned for M3).",
)

_IMPLICIT_LIMITATIONS: tuple[str, ...] = (
    "TLS record framing was observed, but the application protocol inside the TLS "
    "session is encrypted and cannot be identified from this capture.",
    "The port number is a convention, not evidence of which email protocol is in use.",
    "Record framing does not establish that a handshake completed successfully.",
)


def _detect_implicit_tls(
    client: DirectionalBuffer,
    server: DirectionalBuffer,
    config: AnalysisConfig,
    server_port: int,
) -> ImplicitTLSObservation | None:
    """Look for TLS record framing at the very start of the session."""
    records: list[TLSRecordObservation] = []
    if not client.empty:
        records.extend(
            probe_tls_records(
                client,
                client.runs[0][0],
                direction=Direction.CLIENT_TO_SERVER,
                max_records=config.max_tls_records_probed,
            )
        )
    if not server.empty:
        records.extend(
            probe_tls_records(
                server,
                server.runs[0][0],
                direction=Direction.SERVER_TO_CLIENT,
                max_records=config.max_tls_records_probed,
            )
        )
    if not records:
        return None

    strong = any(record.evidence in _STRONG_FRAMING for record in records)
    hint = protocol_for_port(server_port)
    limitations = list(_IMPLICIT_LIMITATIONS)
    if not strong:
        limitations.append(
            "The framing evidence is weak: a single record header can occur by chance in "
            "arbitrary binary payload."
        )
    truncated = [record for record in records if not record.complete]
    if truncated:
        limitations.append(
            f"{len(truncated)} record(s) are truncated in this capture, so the record "
            "chain could not be followed to its end."
        )

    if strong:
        explanation = (
            "The session carries TLS record framing from its first byte, so there is no "
            "plaintext phase to parse. Which email protocol runs inside the TLS session "
            "cannot be determined from a passive capture."
        )
    else:
        explanation = (
            "Bytes at the start of the session weakly resemble a TLS record header. This "
            "is not treated as observed TLS, and no email protocol identity follows from it."
        )
    return ImplicitTLSObservation(
        observed=strong,
        records=tuple(records),
        port_hint=hint,
        service_identity_status=(
            DetectionStatus.PORT_HINT if hint else DetectionStatus.UNKNOWN
        ),
        explanation=explanation,
        limitations=tuple(limitations),
    )


def _detection_from_outcome(
    outcome: ParseOutcome, port_hint: str | None, server_port: int
) -> ProtocolDetection:
    status = outcome.detection_status
    hint_protocol = EmailProtocol(port_hint) if port_hint else None
    agrees = None if hint_protocol is None else hint_protocol is outcome.protocol

    limitations = list(_BASE_LIMITATIONS)
    if status is DetectionStatus.PROBABLE:
        limitations.append(
            "The evidence is real but incomplete: the dialogue was not observed from "
            "greeting through to a matched response."
        )
    if agrees is False:
        limitations.append(
            f"TCP port {server_port} conventionally carries {port_hint}, but the observed "
            f"payload is {outcome.protocol.value}. The payload evidence is authoritative; "
            "the port is not."
        )

    explanation = (
        f"{outcome.protocol.value} was identified from application payload: "
        + " ".join(outcome.evidence_summary)
    )
    return ProtocolDetection(
        protocol=outcome.protocol,
        status=status,
        evidence_status=(
            EvidenceStatus.OBSERVED
            if status is DetectionStatus.CONFIRMED
            else EvidenceStatus.INFERRED
        ),
        confidence_basis=outcome.confidence_basis,
        explanation=explanation,
        evidence_refs=outcome.evidence_refs,
        evidence_summary=outcome.evidence_summary,
        port_hint=port_hint,
        port_hint_agrees=agrees,
        limitations=tuple(limitations),
    )


def _port_only_detection(
    port_hint: str | None,
    server_port: int,
    *,
    implicit: ImplicitTLSObservation | None,
    evidence_refs: tuple[PacketReference, ...],
) -> ProtocolDetection:
    limitations = list(_BASE_LIMITATIONS)
    if implicit is not None and implicit.observed:
        limitations.extend(_IMPLICIT_LIMITATIONS)
        explanation = (
            f"No plaintext email protocol was observable: the session is TLS-framed from "
            f"its first byte. TCP port {server_port} conventionally carries "
            f"{port_hint or 'no email protocol'}, which is a hint only."
        )
    elif port_hint:
        limitations.append(
            "No application payload confirmed this protocol; only the port number "
            "suggests it. A different service may be running on this port."
        )
        explanation = (
            f"No conforming email protocol dialogue was parsed. TCP port {server_port} "
            f"conventionally carries {port_hint}, which is a hint only."
        )
    else:
        explanation = (
            f"Neither the payload nor TCP port {server_port} indicates a known email "
            "protocol."
        )
    return ProtocolDetection(
        protocol=EmailProtocol(port_hint) if port_hint else EmailProtocol.UNKNOWN,
        status=DetectionStatus.PORT_HINT if port_hint else DetectionStatus.UNKNOWN,
        evidence_status=EvidenceStatus.INFERRED if port_hint else EvidenceStatus.UNKNOWN,
        confidence_basis="SERVER_PORT_ONLY" if port_hint else "NO_EVIDENCE",
        explanation=explanation,
        evidence_refs=evidence_refs,
        evidence_summary=("No application-level protocol evidence was parsed.",),
        port_hint=port_hint,
        port_hint_agrees=None,
        limitations=tuple(limitations),
    )


def analyze_session(
    session: TCPSession,
    client_runs: list[tuple[int, bytes]],
    server_runs: list[tuple[int, bytes]],
    *,
    config: AnalysisConfig,
    capture_id: str,
) -> ProtocolSessionAnalysis:
    """Analyse one reconstructed session's application layer."""
    client = DirectionalBuffer.build(
        Direction.CLIENT_TO_SERVER, client_runs, session.client_to_server
    )
    server = DirectionalBuffer.build(
        Direction.SERVER_TO_CLIENT, server_runs, session.server_to_client
    )
    server_port = session.flow.server.port
    port_hint = protocol_for_port(server_port)
    implicit = _detect_implicit_tls(client, server, config, server_port)

    if client.empty and server.empty:
        return ProtocolSessionAnalysis(
            session_id=session.session_id,
            capture_id=capture_id,
            detection=_port_only_detection(
                port_hint, server_port, implicit=None, evidence_refs=()
            ),
            parse_state=ParseState.NOT_APPLICABLE,
            limitations=(
                "The session carried no reconstructed application payload, so there was "
                "nothing to parse.",
            ),
        )

    best: tuple[ParseOutcome, list[AnalysisWarning]] | None = None
    for parser_class in _PARSERS:
        scratch = WarningSink(
            capture_id=capture_id, max_per_code=config.max_warnings_per_code
        )
        context = ParseContext(
            session_id=session.session_id,
            capture_id=capture_id,
            config=config,
            sink=scratch,
            client=client,
            server=server,
            server_port=server_port,
        )
        outcome = parser_class(context).run()
        if best is None or outcome.evidence_score > best[0].evidence_score:
            best = (outcome, list(scratch.collect()))
            continue
        # A genuine tie is broken by the port, which is then the only remaining
        # signal -- and the detection is reported as PROBABLE at best.
        tied = outcome.evidence_score == best[0].evidence_score
        if (
            tied
            and port_hint
            and outcome.protocol.value == port_hint
            and best[0].protocol.value != port_hint
        ):
            best = (outcome, list(scratch.collect()))

    assert best is not None
    outcome, warnings = best

    if outcome.evidence_score == 0 or outcome.detection_status is DetectionStatus.UNKNOWN:
        detection = _port_only_detection(
            port_hint,
            server_port,
            implicit=implicit,
            evidence_refs=(session.first_packet,),
        )
        limitations = list(_BASE_LIMITATIONS)
        if implicit is not None and implicit.observed:
            limitations.append(
                "Plaintext parsing was not attempted beyond the start of the session "
                "because the session is TLS-framed from its first byte."
            )
        return ProtocolSessionAnalysis(
            session_id=session.session_id,
            capture_id=capture_id,
            detection=detection,
            parse_state=ParseState.NOT_APPLICABLE,
            implicit_tls=implicit,
            limitations=tuple(limitations),
        )

    detection = _detection_from_outcome(outcome, port_hint, server_port)
    limitations = list(outcome.limitations)
    if server_port in IMPLICIT_TLS_PORTS:
        limitations.append(
            f"TCP port {server_port} conventionally carries implicit TLS, yet a plaintext "
            "dialogue was parsed here. The payload evidence is authoritative."
        )
    return ProtocolSessionAnalysis(
        session_id=session.session_id,
        capture_id=capture_id,
        detection=detection,
        parse_state=outcome.state,
        events=outcome.events,
        upgrade=outcome.upgrade,
        implicit_tls=implicit,
        authentication=outcome.authentication,
        warnings=tuple(warnings),
        limitations=tuple(limitations),
        client_plaintext_end_offset=outcome.client_plaintext_end,
        server_plaintext_end_offset=outcome.server_plaintext_end,
    )


def build_inventory(analyses: tuple[ProtocolSessionAnalysis, ...]) -> ProtocolInventory:
    def confirmed(protocol: EmailProtocol) -> int:
        return sum(
            1
            for analysis in analyses
            if analysis.detection.protocol is protocol
            and analysis.detection.status is DetectionStatus.CONFIRMED
        )

    upgrades = [analysis.upgrade for analysis in analyses if analysis.upgrade is not None]
    auth = [obs for analysis in analyses for obs in analysis.authentication]

    return ProtocolInventory(
        analysed_session_count=len(analyses),
        confirmed_smtp_count=confirmed(EmailProtocol.SMTP),
        confirmed_imap_count=confirmed(EmailProtocol.IMAP),
        confirmed_pop3_count=confirmed(EmailProtocol.POP3),
        probable_count=sum(
            1 for a in analyses if a.detection.status is DetectionStatus.PROBABLE
        ),
        port_hint_only_count=sum(
            1 for a in analyses if a.detection.status is DetectionStatus.PORT_HINT
        ),
        unknown_count=sum(
            1 for a in analyses if a.detection.status is DetectionStatus.UNKNOWN
        ),
        upgrade_advertised_count=sum(1 for u in upgrades if u.advertised is not None),
        upgrade_requested_count=sum(1 for u in upgrades if u.requested is not None),
        upgrade_accepted_count=sum(
            1
            for u in upgrades
            if u.state in {UpgradeState.UPGRADE_ACCEPTED, UpgradeState.TLS_BYTES_OBSERVED}
        ),
        upgrade_rejected_count=sum(
            1 for u in upgrades if u.state is UpgradeState.UPGRADE_REJECTED
        ),
        upgrade_incomplete_count=sum(
            1
            for u in upgrades
            if u.state in {UpgradeState.INCOMPLETE, UpgradeState.UPGRADE_REQUESTED}
        ),
        tls_bytes_observed_count=sum(
            1 for u in upgrades if u.state is UpgradeState.TLS_BYTES_OBSERVED
        ),
        implicit_tls_session_count=sum(
            1 for a in analyses if a.implicit_tls is not None and a.implicit_tls.observed
        ),
        authentication_observation_count=len(auth),
        authentication_before_upgrade_count=sum(
            1 for obs in auth if obs.occurred_before_tls_upgrade
        ),
        tls_handshakes_analysed=0,
    )
