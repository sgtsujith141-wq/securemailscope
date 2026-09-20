"""The M1 analysis pipeline.

::

    capture file
      -> validated, hashed, format-detected capture source   (ingestion/reader)
      -> streamed container records                          (ingestion/pcap*_reader)
      -> link/IP/TCP dissection                              (ingestion/dissect)
      -> connection identification + payload reconstruction   (network/sessions)
      -> session inventory with provenance                   (models)
      -> JSON                                                (reporting)

The pipeline has no dependency on a web framework, a database, a model, or a
network.  It is a pure function of the capture file and the configuration.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import __version__
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
from .models.capture import CaptureMetadata
from .models.evidence import (
    AnalysisWarning,
    PacketReference,
    Severity,
    WarningCode,
    ns_to_datetime,
)
from .models.tcp import Direction, SessionCompleteness, TCPSession
from .network.sessions import TCPSessionEngine

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
        warnings=global_warnings,
    )
    return AnalysisArtifacts(result=result, payload_runs=engine.payload_runs())
