"""The M1 analysis pipeline.

::

    capture file
      -> validated, hashed, format-detected capture source   (ingestion/reader)
      -> streamed container records                          (ingestion/pcap*_reader)
      -> link/IP/TCP dissection                              (ingestion/dissect)
      -> connection identification + payload reconstruction   (network/sessions)
      -> email protocol parsing + STARTTLS state             (protocols/analyzer)
      -> TLS records, handshake, crypto parameters           (tls/analyzer)
      -> X.509 extraction and independent validation         (certificates/)
      -> security rules, score, priority, remediation        (assessment/)
      -> session inventory with provenance                   (models)
      -> JSON                                                (reporting)

The pipeline has no dependency on a web framework, a database, a model, or a
network.  It is a pure function of the capture file and the configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .assessment.engine import assess_capture
from .assessment.policy import DEFAULT_POLICY, AssessmentPolicy
from .certificates.truststore import load_trust_store
from .config import AnalysisConfig
from .diagnostics import WarningSink
from .ingestion.dissect import DissectionOutcome, dissect
from .ingestion.reader import open_capture
from .models.analysis import (
    AnalysisLimits,
    AnalysisResult,
    SessionInventory,
    ToolInfo,
)
from .models.assessment import AssessmentMode
from .models.capture import CaptureMetadata
from .models.evidence import (
    AnalysisWarning,
    PacketReference,
    Severity,
    WarningCode,
    ns_to_datetime,
)
from .models.protocol import ProtocolSessionAnalysis
from .models.tcp import Direction, SessionCompleteness, TCPSession
from .models.tls import (
    ForwardSecrecyStatus,
    HandshakeState,
    TLSEntryPoint,
    TLSInventory,
    TLSSessionAnalysis,
)
from .network.sessions import TCPSessionEngine
from .protocols.analyzer import analyze_session, build_inventory
from .tls.analyzer import analyze_tls_session

__all__ = ["analyze_capture", "analyze_capture_with_payloads", "AnalysisArtifacts"]


@dataclass(frozen=True, slots=True)
class AnalysisArtifacts:
    """An analysis result plus the reconstructed bytes behind it.

    The bytes are kept out of :class:`AnalysisResult` on purpose -- a report
    must be safe to write to disk and share.  Callers that genuinely need the
    payload (the M2 protocol layer, the M3 TLS layer, and the reconstruction
    tests) ask for it explicitly through this type.
    """

    result: AnalysisResult
    #: ``(session_id, direction)`` -> contiguous ``(stream_offset, bytes)`` runs.
    payload_runs: dict[tuple[str, Direction], list[tuple[int, bytes]]]


def _limits_of(config: AnalysisConfig) -> AnalysisLimits:
    return AnalysisLimits(
        max_capture_bytes=config.max_capture_bytes,
        max_packets=config.max_packets,
        max_packet_bytes=config.max_packet_bytes,
        max_total_payload_bytes=config.max_total_payload_bytes,
        max_session_payload_bytes=config.max_session_payload_bytes,
        max_concurrent_sessions=config.max_concurrent_sessions,
        max_total_sessions=config.max_total_sessions,
        max_segments_per_direction=config.max_segments_per_direction,
    )


def _inventory(sessions: tuple[TCPSession, ...], tuple_reuse_count: int) -> SessionInventory:
    return SessionInventory(
        session_count=len(sessions),
        complete_session_count=sum(
            1 for s in sessions if s.completeness is SessionCompleteness.COMPLETE
        ),
        midstream_session_count=sum(
            1 for s in sessions if s.completeness is SessionCompleteness.MIDSTREAM
        ),
        partial_session_count=sum(
            1 for s in sessions if s.completeness is SessionCompleteness.PARTIAL
        ),
        truncated_session_count=sum(
            1 for s in sessions if s.completeness is SessionCompleteness.TRUNCATED
        ),
        total_bytes_reconstructed=sum(s.total_bytes_reconstructed for s in sessions),
        total_gap_count=sum(
            len(s.client_to_server.gaps) + len(s.server_to_client.gaps) for s in sessions
        ),
        total_overlap_conflict_count=sum(
            len(s.client_to_server.overlap_conflicts) + len(s.server_to_client.overlap_conflicts)
            for s in sessions
        ),
        tuple_reuse_count=tuple_reuse_count,
    )


def _attach_warnings(
    sessions: tuple[TCPSession, ...], warnings: tuple[AnalysisWarning, ...]
) -> tuple[tuple[TCPSession, ...], tuple[AnalysisWarning, ...]]:
    """Route each warning to its session, leaving capture-level ones at the top."""
    by_session: dict[str, list[AnalysisWarning]] = {}
    global_warnings: list[AnalysisWarning] = []
    for warning in warnings:
        if warning.session_id:
            by_session.setdefault(warning.session_id, []).append(warning)
        else:
            global_warnings.append(warning)
    updated = tuple(
        session.model_copy(update={"warnings": tuple(by_session.get(session.session_id, []))})
        for session in sessions
    )
    return updated, tuple(global_warnings)


def _analyze_protocols(
    sessions: tuple[TCPSession, ...],
    payload_runs: dict[tuple[str, Direction], list[tuple[int, bytes]]],
    config: AnalysisConfig,
    capture_id: str,
) -> tuple[ProtocolSessionAnalysis, ...]:
    """Run the application-layer analysis for every reconstructed session.

    Protocol diagnostics stay on their own session analysis rather than being
    merged into the capture-level warning list: they belong to one dialogue,
    and several candidate parsers are run speculatively, so only the winner's
    diagnostics are meaningful.
    """
    analyses: list[ProtocolSessionAnalysis] = []
    for session in sessions:
        analyses.append(
            analyze_session(
                session,
                payload_runs.get((session.session_id, Direction.CLIENT_TO_SERVER), []),
                payload_runs.get((session.session_id, Direction.SERVER_TO_CLIENT), []),
                config=config,
                capture_id=capture_id,
            )
        )
    return tuple(analyses)


def _analyze_tls(
    sessions: tuple[TCPSession, ...],
    protocols: tuple[ProtocolSessionAnalysis, ...],
    payload_runs: dict[tuple[str, Direction], list[tuple[int, bytes]]],
    config: AnalysisConfig,
    capture_id: str,
) -> tuple[TLSSessionAnalysis, ...]:
    """Run the TLS layer for every session that carries TLS.

    The trust store is loaded once per capture, not once per session, so every
    session in a report is judged against the same named anchor set.
    """
    trust_store = load_trust_store(config.trust_store_path)
    by_session = {analysis.session_id: analysis for analysis in protocols}
    results: list[TLSSessionAnalysis] = []
    for session in sessions:
        analysis = analyze_tls_session(
            session,
            by_session.get(session.session_id),
            payload_runs.get((session.session_id, Direction.CLIENT_TO_SERVER), []),
            payload_runs.get((session.session_id, Direction.SERVER_TO_CLIENT), []),
            config=config,
            capture_id=capture_id,
            trust_store=trust_store,
        )
        if analysis is not None:
            results.append(analysis)
    return tuple(results)


def _tls_inventory(analyses: tuple[TLSSessionAnalysis, ...]) -> TLSInventory:
    def version_count(label: str) -> int:
        return sum(
            1
            for analysis in analyses
            if analysis.version.selected_version is not None
            and analysis.version.selected_version.name == label
        )

    def check_passed(analysis: TLSSessionAnalysis, field: str) -> bool:
        validation = analysis.certificates.validation
        if validation is None:
            return False
        return getattr(validation, field).status.value == "PASSED"

    legacy = sum(
        1
        for analysis in analyses
        if analysis.version.selected_version is not None
        and analysis.version.selected_version.name in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
    )
    forward_secret = sum(
        1
        for analysis in analyses
        if analysis.forward_secrecy.status
        in {ForwardSecrecyStatus.EPHEMERAL_OBSERVED, ForwardSecrecyStatus.CAPABLE_NEGOTIATED}
    )
    return TLSInventory(
        tls_session_count=len(analyses),
        implicit_tls_count=sum(
            1 for a in analyses if a.entry_point is TLSEntryPoint.IMPLICIT
        ),
        starttls_upgrade_count=sum(
            1 for a in analyses if a.entry_point is TLSEntryPoint.STARTTLS_UPGRADE
        ),
        negotiated_count=sum(
            1
            for a in analyses
            if a.handshake_state
            not in {
                HandshakeState.NOT_OBSERVED,
                HandshakeState.CLIENT_HELLO_ONLY,
                HandshakeState.INDETERMINATE,
            }
        ),
        tls13_count=version_count("TLS 1.3"),
        tls12_count=version_count("TLS 1.2"),
        legacy_version_count=legacy,
        certificates_observed_count=sum(
            1 for a in analyses if a.certificates.visibility.value == "OBSERVED"
        ),
        certificates_encrypted_count=sum(
            1 for a in analyses if a.certificates.visibility.value == "ENCRYPTED_TLS13"
        ),
        chain_verified_count=sum(1 for a in analyses if check_passed(a, "chain_verified")),
        hostname_verified_count=sum(
            1 for a in analyses if check_passed(a, "hostname_verified")
        ),
        forward_secret_count=forward_secret,
        static_rsa_count=sum(
            1
            for a in analyses
            if a.forward_secrecy.status is ForwardSecrecyStatus.STATIC_RSA_KEY_EXCHANGE
        ),
        alert_count=sum(len(a.alerts) for a in analyses),
        handshakes_cryptographically_verified=0,
        revocation_checks_performed=0,
    )


def _policy_for(config: AnalysisConfig) -> AssessmentPolicy:
    """Build the active assessment policy from the run configuration.

    Overrides are recorded on the policy itself, so a report always states
    which settings were changed from the documented default.
    """
    disabled = (
        frozenset(
            item.strip() for item in config.disabled_rules.split(",") if item.strip()
        )
        if config.disabled_rules
        else None
    )
    return DEFAULT_POLICY.with_overrides(
        assessment_mode=(
            AssessmentMode.CURRENT_TIME if config.assess_at_current_time else None
        ),
        minimum_coverage_for_score=(
            config.minimum_score_coverage_percent / 100.0
            if config.minimum_score_coverage_percent != 50
            else None
        ),
        disabled_rules=disabled,
    )


def analyze_capture(
    path: Path | str,
    *,
    config: AnalysisConfig | None = None,
) -> AnalysisResult:
    """Analyse one capture file and return a fully provenanced result.

    Reconstructed payload bytes are discarded on return; use
    :func:`analyze_capture_with_payloads` when they are needed.
    """
    return analyze_capture_with_payloads(path, config=config).result


def analyze_capture_with_payloads(
    path: Path | str,
    *,
    config: AnalysisConfig | None = None,
) -> AnalysisArtifacts:
    """Analyse one capture file, returning the result and the reconstructed bytes."""
    config = config or AnalysisConfig()
    started_at = ToolInfo.now()
    sink = WarningSink(max_per_code=config.max_warnings_per_code)

    source = open_capture(path, config=config, sink=sink)
    engine = TCPSessionEngine(capture_id=source.capture_id, config=config, sink=sink)

    packet_count = 0
    tcp_count = 0
    non_ip = 0
    non_tcp = 0
    unsupported_link = 0
    malformed = 0
    first_ns: int | None = None
    last_ns: int | None = None

    for frame in source.frames():
        packet_count += 1
        if first_ns is None:
            first_ns = frame.timestamp_ns
        last_ns = frame.timestamp_ns

        dissected = dissect(frame)
        outcome = dissected.outcome
        if outcome is DissectionOutcome.TCP and dissected.packet is not None:
            tcp_count += 1
            engine.observe(dissected.packet)
        elif outcome is DissectionOutcome.NOT_IP:
            non_ip += 1
        elif outcome is DissectionOutcome.NOT_TCP:
            non_tcp += 1
        elif outcome is DissectionOutcome.UNSUPPORTED_LINK_TYPE:
            unsupported_link += 1
        elif outcome is DissectionOutcome.IP_FRAGMENT:
            non_tcp += 1
            sink.add(
                WarningCode.IP_FRAGMENT_NOT_REASSEMBLED,
                f"Packet {frame.packet_number} is an IP fragment ({dissected.detail}). IP "
                "fragment reassembly is not implemented, so this packet's data is absent "
                "from the reconstructed streams.",
                packet_refs=(PacketReference.create(frame.packet_number, frame.timestamp_ns),),
            )
        else:
            malformed += 1
            sink.add(
                WarningCode.MALFORMED_PACKET,
                f"Packet {frame.packet_number} could not be dissected: {dissected.detail}.",
                packet_refs=(PacketReference.create(frame.packet_number, frame.timestamp_ns),),
                detail=dissected.detail,
            )

    sessions = engine.finalize()
    payload_runs = engine.payload_runs()
    protocols = _analyze_protocols(sessions, payload_runs, config, source.capture_id)
    tls_sessions = _analyze_tls(sessions, protocols, payload_runs, config, source.capture_id)

    if non_ip:
        sink.add(
            WarningCode.NON_IP_PACKET,
            f"{non_ip} packet(s) were not IPv4 or IPv6 and were not analysed.",
            severity=Severity.INFO,
            count=non_ip,
        )
    if non_tcp:
        sink.add(
            WarningCode.NON_TCP_PACKET,
            f"{non_tcp} IP packet(s) did not carry TCP and were not analysed.",
            severity=Severity.INFO,
            count=non_tcp,
        )
    if unsupported_link:
        sink.add(
            WarningCode.UNSUPPORTED_LINK_TYPE,
            f"{unsupported_link} packet(s) used an unsupported link type and were skipped; "
            "no sessions were derived from them.",
            severity=Severity.ERROR,
            count=unsupported_link,
        )

    all_warnings = sink.collect()
    sessions, global_warnings = _attach_warnings(sessions, all_warnings)

    capture = CaptureMetadata(
        capture_id=source.capture_id,
        source_name=source.source_name,
        file_format=source.file_format,
        byte_order=source.byte_order,
        file_size_bytes=source.file_size,
        interfaces=source.interfaces,
        packet_count=packet_count,
        tcp_packet_count=tcp_count,
        non_ip_packet_count=non_ip,
        non_tcp_packet_count=non_tcp,
        unsupported_link_packet_count=unsupported_link,
        malformed_packet_count=malformed,
        first_packet_timestamp=ns_to_datetime(first_ns) if first_ns is not None else None,
        last_packet_timestamp=ns_to_datetime(last_ns) if last_ns is not None else None,
        first_packet_timestamp_ns=first_ns,
        last_packet_timestamp_ns=last_ns,
        truncated=source.truncated,
        warnings=tuple(
            warning
            for warning in global_warnings
            if warning.code
            in {
                WarningCode.TRUNCATED_CAPTURE_FILE,
                WarningCode.MALFORMED_BLOCK,
                WarningCode.UNSUPPORTED_LINK_TYPE,
                WarningCode.LIMIT_PACKET_COUNT,
                WarningCode.LIMIT_PACKET_BYTES,
            }
        ),
    )

    result = AnalysisResult(
        tool=ToolInfo(
            version=__version__,
            analysis_started_at=started_at,
            analysis_completed_at=ToolInfo.now(),
        ),
        limits=_limits_of(config),
        capture=capture,
        inventory=_inventory(sessions, engine.tuple_reuse_count),
        sessions=sessions,
        protocol_inventory=build_inventory(protocols),
        protocols=protocols,
        tls_inventory=_tls_inventory(tls_sessions),
        tls=tls_sessions,
        warnings=global_warnings,
    )
    if config.assess_security:
        result = result.model_copy(
            update={"assessment": assess_capture(result, policy=_policy_for(config))}
        )
    return AnalysisArtifacts(result=result, payload_runs=payload_runs)
