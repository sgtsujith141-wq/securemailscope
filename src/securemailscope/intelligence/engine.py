"""The forensic intelligence engine (M5).

Consumes completed :class:`AnalysisResult` objects and produces an
:class:`Investigation`. It **never reparses packets**: the single-capture
pipeline has already done that work, and re-doing it would risk the two
disagreeing about what the capture contained.

Batch semantics worth stating plainly:

* **A capture is identified by its content hash**, so the same file submitted
  twice, or under two names, is analysed once and recorded once as a
  ``DUPLICATE``. Counting it twice would double a blast radius by re-reading
  one piece of evidence.
* **A capture that fails is still in the inventory**, with its reason. Dropping
  it would let a reader take the surviving results as covering everything they
  submitted.
* **Output does not depend on argument order.** Captures are processed in the
  order given, so duplicate detection is stable, but every collection in the
  output is sorted by content, so two runs with the arguments shuffled produce
  identical investigations.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ..config import AnalysisConfig
from ..errors import SecureMailScopeError
from ..models.intelligence import (
    FINGERPRINT_ALGORITHM_VERSION,
    CaptureRecord,
    CaptureStatus,
    CryptographicFingerprint,
    DriftStatus,
    IntelligenceWarning,
    Investigation,
    TimelineEventType,
)
from ..pipeline import analyze_capture
from .blast_radius import build_blast_radius
from .correlation import correlate
from .drift import SessionSnapshot, drift_for_entity
from .fingerprints import build_fingerprint, configuration_fingerprint
from .identity import build_entities, entity_id_for, relate_entities
from .timeline import CLOCK_LIMITATIONS, build_timeline

if TYPE_CHECKING:
    from ..models.analysis import AnalysisResult

__all__ = ["INVESTIGATION_SCHEMA_VERSION", "BatchOutcome", "analyze_batch"]

#: Independent of the single-capture report schema: an investigation is a new
#: document, not a new version of the old one.
INVESTIGATION_SCHEMA_VERSION: Final = "1.0.0"

_INVESTIGATION_LIMITATIONS: Final = (
    "Observed within analyzed captures only. Nothing here describes hosts, "
    "sessions or services that were not captured.",
    "Entities are observed (ip, port) endpoints. They are never merged on a "
    "shared certificate, key, name or configuration; those appear as typed "
    "relationships instead.",
    "A cryptographic fingerprint groups configurations. It is not a globally "
    "unique identity.",
    "No attacker, campaign, intent or network topology is inferred anywhere in "
    "this document.",
    *CLOCK_LIMITATIONS,
)


class BatchOutcome:
    """The investigation plus the individual capture results behind it."""

    def __init__(
        self,
        investigation: Investigation,
        results: list[AnalysisResult],
    ) -> None:
        self.investigation = investigation
        self.results = results


def _offer_signature(tls: Any) -> tuple[str | None, str | None]:
    """Canonicalise what the client offered, so two offers can be compared.

    Returns ``(signature, human summary)``. The signature is sorted and
    GREASE-filtered, because GREASE values are deliberately random and would
    make every offer look unique.
    """
    if tls is None:
        return None, None
    versions = sorted(
        reference.name or reference.hex_value
        for reference in tls.version.offered_versions
        if not reference.grease
    )
    suites = sorted(
        reference.name or reference.hex_value
        for reference in tls.cipher_suite.offered
        if not reference.grease
    )
    if not versions and not suites:
        return None, None
    signature = "versions=" + ",".join(versions) + "|suites=" + ",".join(suites)
    summary = f"{len(versions)} version(s), {len(suites)} suite(s)"
    return signature, summary


def _certificate_validity(tls: Any) -> str | None:
    leaf = next(
        (c for c in tls.certificates.certificates if c.chain_position == 0), None
    ) if tls is not None else None
    if leaf is None or leaf.not_valid_before is None or leaf.not_valid_after is None:
        return None
    return f"{leaf.not_valid_before.isoformat()}..{leaf.not_valid_after.isoformat()}"


def _session_values(tls: Any, fingerprint: Any) -> dict[str, str | None]:
    values = {
        component.name: component.value if component.present else None
        for component in fingerprint.components
    }
    values["certificate_validity"] = _certificate_validity(tls)
    return values


def _session_evidence(tls: Any, fingerprint: Any) -> dict[str, tuple]:
    evidence = {
        component.name: component.evidence_refs for component in fingerprint.components
    }
    if tls is not None:
        evidence["certificate_validity"] = tuple(
            reference
            for certificate in tls.certificates.certificates
            if certificate.chain_position == 0
            for reference in certificate.packet_refs
        )
    return evidence


def _timeline_events_for(
    result: AnalysisResult, entity_of: dict[str, str]
) -> list[dict[str, Any]]:
    """Every observable event in one capture, as raw dicts for the timeline."""
    capture_id = result.capture.capture_id
    protocols = {item.session_id: item for item in result.protocols}
    tls_by_session = {item.session_id: item for item in result.tls}
    events: list[dict[str, Any]] = []

    def add(session_id: str | None, event_type: TimelineEventType, **kwargs: Any) -> None:
        events.append(
            {
                "capture_id": capture_id,
                "session_id": session_id,
                "entity_id": entity_of.get(session_id) if session_id else None,
                "event_type": event_type,
                **kwargs,
            }
        )

    for session in result.sessions:
        add(
            session.session_id,
            TimelineEventType.SESSION_FIRST_PACKET,
            timestamp=session.first_packet.timestamp,
            timestamp_ns=session.first_packet.timestamp_ns,
            description=(
                f"First packet of session {session.session_id} "
                f"({session.flow.client.ip}:{session.flow.client.port} -> "
                f"{session.flow.server.ip}:{session.flow.server.port})"
            ),
            packet_refs=(session.first_packet,),
            anchor=f"first-packet:{session.first_packet.packet_number}",
        )

        protocol = protocols.get(session.session_id)
        if protocol is not None:
            detection = protocol.detection
            if detection.evidence_refs:
                add(
                    session.session_id,
                    TimelineEventType.PROTOCOL_IDENTIFIED,
                    timestamp=detection.evidence_refs[0].timestamp,
                    timestamp_ns=detection.evidence_refs[0].timestamp_ns,
                    description=(
                        f"{detection.protocol.value} identified "
                        f"({detection.status.value}, {detection.confidence_basis})"
                    ),
                    packet_refs=detection.evidence_refs,
                    evidence_status=detection.evidence_status.value,
                    anchor=f"detect:{detection.protocol.value}:{detection.status.value}",
                )
            upgrade = protocol.upgrade
            if upgrade is not None:
                for attribute, event_type, label in (
                    ("advertised", TimelineEventType.UPGRADE_ADVERTISED, "advertised"),
                    ("requested", TimelineEventType.UPGRADE_REQUESTED, "requested"),
                ):
                    observation = getattr(upgrade, attribute)
                    if observation is not None and observation.packet_refs:
                        add(
                            session.session_id,
                            event_type,
                            timestamp=observation.packet_refs[0].timestamp,
                            timestamp_ns=observation.packet_refs[0].timestamp_ns,
                            description=f"{upgrade.mechanism.value} {label}",
                            packet_refs=observation.packet_refs,
                            stream_offsets=(observation.stream_offset,),
                            anchor=f"upgrade-{label}:{observation.stream_offset}",
                        )
                response = upgrade.response
                if response is not None and response.packet_refs:
                    accepted = upgrade.state.value.startswith(
                        ("ACCEPTED", "COMPLETED", "ESTABLISHED", "UPGRADED")
                    )
                    add(
                        session.session_id,
                        TimelineEventType.UPGRADE_ACCEPTED
                        if accepted
                        else TimelineEventType.UPGRADE_REJECTED,
                        timestamp=response.packet_refs[0].timestamp,
                        timestamp_ns=response.packet_refs[0].timestamp_ns,
                        description=(
                            f"{upgrade.mechanism.value} response "
                            f"{upgrade.response_code or ''} -> {upgrade.state.value}"
                        ).replace("  ", " "),
                        packet_refs=response.packet_refs,
                        stream_offsets=(response.stream_offset,),
                        anchor=f"upgrade-response:{upgrade.state.value}",
                    )
            for attempt in protocol.authentication:
                if not attempt.packet_refs:
                    continue
                add(
                    session.session_id,
                    TimelineEventType.AUTHENTICATION_OBSERVED,
                    timestamp=attempt.packet_refs[0].timestamp,
                    timestamp_ns=attempt.packet_refs[0].timestamp_ns,
                    description=(
                        f"{attempt.protocol.value} {attempt.command_verb} observed"
                        + (f" (mechanism {attempt.mechanism})" if attempt.mechanism else "")
                        + ". No credential material is recorded."
                    ),
                    packet_refs=attempt.packet_refs,
                    stream_offsets=(attempt.stream_offset,),
                    anchor=f"auth:{attempt.command_verb}:{attempt.stream_offset}",
                )

        tls = tls_by_session.get(session.session_id)
        if tls is None:
            continue
        for message in tls.messages:
            message_event: TimelineEventType | None = {
                "client_hello": TimelineEventType.CLIENT_HELLO,
                "server_hello": TimelineEventType.SERVER_HELLO,
                "certificate": TimelineEventType.CERTIFICATE_OBSERVED,
            }.get(message.message_type_name or "")
            if message_event is None or not message.packet_refs:
                continue
            add(
                session.session_id,
                message_event,
                timestamp=message.first_timestamp,
                timestamp_ns=message.packet_refs[0].timestamp_ns,
                description=f"{message.message_type_name} observed",
                packet_refs=message.packet_refs,
                stream_offsets=(message.stream_offset,),
                evidence_status=message.status.value,
                anchor=f"msg:{message.message_type_name}:{message.stream_offset}",
            )
        version, suite = tls.version.selected_version, tls.cipher_suite.selected
        if version is not None and suite is not None and tls.cipher_suite.evidence_refs:
            # The *latest* supporting packet, not the earliest: the cipher
            # suite evidence spans the ClientHello that offered it and the
            # ServerHello that selected it, and a selection cannot be dated
            # before the message that made it.
            reference = max(
                tls.cipher_suite.evidence_refs,
                key=lambda item: (item.timestamp_ns, item.packet_number),
            )
            add(
                session.session_id,
                TimelineEventType.CRYPTO_PARAMETERS_SELECTED,
                timestamp=reference.timestamp,
                timestamp_ns=reference.timestamp_ns,
                description=(
                    f"Negotiated {version.name or version.hex_value} with "
                    f"{suite.name or suite.hex_value}"
                ),
                packet_refs=tls.cipher_suite.evidence_refs,
                evidence_status="INFERRED",
                derived_from=("tls.version.selected_version", "tls.cipher_suite.selected"),
                anchor=f"negotiated:{version.hex_value}:{suite.hex_value}",
            )
        for alert in tls.alerts:
            if not alert.packet_refs:
                continue
            add(
                session.session_id,
                TimelineEventType.TLS_ALERT,
                timestamp=alert.packet_refs[0].timestamp,
                timestamp_ns=alert.packet_refs[0].timestamp_ns,
                description=(
                    f"TLS alert {alert.level_name or alert.level}/"
                    f"{alert.description_name or alert.description}"
                ),
                packet_refs=alert.packet_refs,
                stream_offsets=(alert.stream_offset,),
                evidence_status=alert.status.value,
                anchor=f"alert:{alert.stream_offset}",
            )

    if result.assessment is not None:
        for finding in result.assessment.findings:
            if not finding.evidence_refs:
                continue
            add(
                finding.session_id,
                TimelineEventType.SECURITY_FINDING,
                timestamp=finding.first_observed,
                timestamp_ns=finding.evidence_refs[0].timestamp_ns,
                description=f"{finding.rule_id} ({finding.severity.value}): {finding.title}",
                packet_refs=finding.evidence_refs,
                stream_offsets=finding.stream_offsets,
                evidence_status="INFERRED",
                derived_from=(
                    f"rule:{finding.rule_id}",
                    f"policy:{finding.policy_id}@{finding.policy_fingerprint}",
                ),
                anchor=f"finding:{finding.finding_id}",
            )
    return events


def analyze_batch(
    paths: Sequence[Path | str],
    *,
    config: AnalysisConfig | None = None,
    on_capture: Callable[[int, int, str], None] | None = None,
) -> BatchOutcome:
    """Analyse several captures together and build an investigation.

    ``on_capture(done, total, name)`` is invoked after each capture. It exists
    so a caller can report *real* progress -- captures finished out of captures
    submitted -- rather than animating a timer. Exceptions from the callback
    are not caught: a broken progress reporter is a bug worth seeing.
    """
    config = config or AnalysisConfig()
    warnings: list[IntelligenceWarning] = []
    inventory: list[CaptureRecord] = []
    results: list[AnalysisResult] = []
    seen_hashes: dict[str, str] = {}

    limit = config.max_batch_captures
    if len(paths) > limit:
        warnings.append(
            IntelligenceWarning(
                code="BATCH_CAPTURE_LIMIT",
                message=(
                    f"{len(paths)} captures were supplied but the configured limit "
                    f"is {limit}. The remainder were not analysed and are not "
                    "represented anywhere in this investigation."
                ),
                detail=f"limit={limit}",
            )
        )
        paths = list(paths)[:limit]

    for path in paths:
        resolved = Path(path)
        name = resolved.name
        try:
            result = analyze_capture(resolved, config=config)
        except (SecureMailScopeError, OSError) as exc:
            # Narrow on purpose: the project forbids broad exception handling,
            # so an unexpected error still propagates and is seen rather than
            # being recorded as a tidy "failed capture" and forgotten.
            inventory.append(
                CaptureRecord(
                    capture_id=f"unanalysed:{name}",
                    source_name=name,
                    status=CaptureStatus.FAILED,
                    failure_reason=f"{type(exc).__name__}: {exc}",
                )
            )
            warnings.append(
                IntelligenceWarning(
                    code="CAPTURE_FAILED",
                    message=(
                        f"{name} could not be analysed and contributes nothing to "
                        "this investigation. Results below do not cover it."
                    ),
                    detail=type(exc).__name__,
                )
            )
            if on_capture is not None:
                on_capture(len(inventory), len(paths), name)
            continue

        capture_id = result.capture.capture_id
        if capture_id in seen_hashes:
            inventory.append(
                CaptureRecord(
                    capture_id=capture_id,
                    source_name=name,
                    status=CaptureStatus.DUPLICATE,
                    sha256=capture_id,
                    duplicate_of_source=seen_hashes[capture_id],
                )
            )
            warnings.append(
                IntelligenceWarning(
                    code="DUPLICATE_CAPTURE",
                    message=(
                        f"{name} has the same content hash as "
                        f"{seen_hashes[capture_id]} and was counted once. "
                        "Different file names are not different evidence."
                    ),
                    capture_id=capture_id,
                )
            )
            if on_capture is not None:
                on_capture(len(inventory), len(paths), name)
            continue

        seen_hashes[capture_id] = name
        assessment = result.assessment
        inventory.append(
            CaptureRecord(
                capture_id=capture_id,
                source_name=name,
                status=CaptureStatus.EMPTY if not result.sessions else CaptureStatus.ANALYZED,
                sha256=capture_id,
                file_size_bytes=result.capture.file_size_bytes,
                packet_count=result.capture.packet_count,
                session_count=len(result.sessions),
                first_packet_timestamp=result.capture.first_packet_timestamp,
                last_packet_timestamp=result.capture.last_packet_timestamp,
                policy_id=assessment.policy.policy_id if assessment else None,
                policy_version=assessment.policy.policy_version if assessment else None,
                policy_fingerprint=(
                    assessment.policy.policy_fingerprint if assessment else None
                ),
            )
        )
        if not result.sessions:
            warnings.append(
                IntelligenceWarning(
                    code="EMPTY_CAPTURE",
                    message=f"{name} contained no TCP sessions.",
                    capture_id=capture_id,
                )
            )
        results.append(result)
        if on_capture is not None:
            on_capture(len(inventory), len(paths), name)

    return _build_investigation(results, inventory, warnings, config)


def _build_investigation(
    results: list[AnalysisResult],
    inventory: list[CaptureRecord],
    warnings: list[IntelligenceWarning],
    config: AnalysisConfig,
) -> BatchOutcome:
    observations: list[dict[str, Any]] = []
    fingerprints: list[CryptographicFingerprint] = []
    session_members: list[dict[str, Any]] = []
    finding_members: list[dict[str, Any]] = []
    snapshots_by_entity: dict[str, list[SessionSnapshot]] = defaultdict(list)
    entity_of_session: dict[str, str] = {}

    total_sessions = sum(len(result.sessions) for result in results)
    if total_sessions > config.max_batch_sessions:
        warnings.append(
            IntelligenceWarning(
                code="BATCH_SESSION_LIMIT",
                message=(
                    f"{total_sessions} sessions exceed the configured limit of "
                    f"{config.max_batch_sessions}. Correlation and drift were "
                    "computed over a truncated set and are not complete."
                ),
                detail=f"limit={config.max_batch_sessions}",
            )
        )

    budget = config.max_batch_sessions
    for result in results:
        capture_id = result.capture.capture_id
        tls_by_session = {item.session_id: item for item in result.tls}
        protocols = {item.session_id: item for item in result.protocols}
        assessment = result.assessment

        for session in result.sessions:
            if budget <= 0:
                break
            budget -= 1
            tls = tls_by_session.get(session.session_id)
            fingerprint = build_fingerprint(session, tls, capture_id)
            configuration = configuration_fingerprint(fingerprint)
            if len(fingerprints) < config.max_batch_fingerprints:
                fingerprints.append(fingerprint)

            certificates = tuple(
                certificate.sha256_fingerprint
                for certificate in (tls.certificates.certificates if tls else ())
            )
            keys = tuple(
                certificate.public_key.spki_sha256
                for certificate in (tls.certificates.certificates if tls else ())
                if certificate.public_key.spki_sha256
            )
            protocol = protocols.get(session.session_id)
            protocol_name = (
                protocol.detection.protocol.value if protocol is not None else None
            )
            entity_id = entity_id_for(session.flow.server.ip, session.flow.server.port)
            entity_of_session[session.session_id] = entity_id

            observations.append(
                {
                    "ip": session.flow.server.ip,
                    "port": session.flow.server.port,
                    "session_id": session.session_id,
                    "capture_id": capture_id,
                    "sni": tls.server_name_indication if tls else None,
                    "certificates": certificates,
                    "public_keys": keys,
                    "fingerprint_id": fingerprint.fingerprint_id,
                    "configuration_fingerprint": configuration,
                    "protocol": protocol_name,
                    "first_timestamp": session.first_packet.timestamp,
                    "first_timestamp_ns": session.first_packet.timestamp_ns,
                    "last_timestamp": session.last_packet.timestamp,
                    "last_timestamp_ns": session.last_packet.timestamp_ns,
                }
            )
            session_members.append(
                {
                    "session_id": session.session_id,
                    "capture_id": capture_id,
                    "entity_id": entity_id,
                    "certificates": certificates,
                    "public_keys": keys,
                    "fingerprint_id": fingerprint.fingerprint_id,
                    "configuration_fingerprint": configuration,
                    "protocol": protocol_name,
                    "timestamp": session.first_packet.timestamp,
                    "evidence": (session.first_packet,),
                }
            )

            signature, summary = _offer_signature(tls)
            session_assessment = next(
                (
                    item
                    for item in (assessment.sessions if assessment else ())
                    if item.session_id == session.session_id
                ),
                None,
            )
            snapshots_by_entity[entity_id].append(
                SessionSnapshot(
                    capture_id=capture_id,
                    session_id=session.session_id,
                    timestamp=session.first_packet.timestamp,
                    timestamp_ns=session.first_packet.timestamp_ns,
                    values=_session_values(tls, fingerprint),
                    evidence=_session_evidence(tls, fingerprint),
                    client_offer_signature=signature,
                    client_offer_summary=summary,
                    policy_fingerprint=(
                        assessment.policy.policy_fingerprint if assessment else None
                    ),
                    posture_score=(
                        session_assessment.posture_score.score
                        if session_assessment is not None
                        else None
                    ),
                    coverage_ratio=(
                        session_assessment.posture_score.coverage.coverage_ratio
                        if session_assessment is not None
                        else None
                    ),
                )
            )

        for finding in assessment.findings if assessment else ():
            if finding.session_id not in entity_of_session:
                continue
            protocol = protocols.get(finding.session_id)
            finding_members.append(
                {
                    "rule_id": finding.rule_id,
                    "session_id": finding.session_id,
                    "capture_id": capture_id,
                    "entity_id": entity_of_session[finding.session_id],
                    "finding_ids": (finding.finding_id,),
                    "policy_version": finding.policy_version,
                    "protocol": (
                        protocol.detection.protocol.value if protocol is not None else None
                    ),
                    "timestamp": finding.first_observed,
                    "evidence": finding.evidence_refs,
                }
            )

    entities = relate_entities(build_entities(observations))

    drift_events = [
        event
        for entity_id, entity in entities.items()
        for event in drift_for_entity(entity, snapshots_by_entity.get(entity_id, []))
    ]
    drift_events.sort(key=lambda event: (event.entity_id, event.kind.value, event.drift_id))

    correlations, correlations_truncated = correlate(
        finding_members, session_members, max_correlations=config.max_batch_correlations
    )
    if correlations_truncated:
        warnings.append(
            IntelligenceWarning(
                code="CORRELATION_LIMIT",
                message=(
                    f"More correlations were found than the configured limit of "
                    f"{config.max_batch_correlations}. The list below is truncated "
                    "and is not a complete account of what was correlated."
                ),
            )
        )

    raw_events = [
        event
        for result in results
        for event in _timeline_events_for(result, entity_of_session)
    ]
    for event in drift_events:
        if event.status is not DriftStatus.OBSERVED_CHANGE:
            continue
        raw_events.append(
            {
                "capture_id": event.after.capture_id,
                "session_id": event.after.session_id,
                "entity_id": event.entity_id,
                "event_type": TimelineEventType.CONFIGURATION_DRIFT,
                "timestamp": event.after.timestamp,
                "timestamp_ns": event.after.timestamp_ns,
                "description": f"{event.kind.value}: {event.explanation}",
                "packet_refs": event.after.evidence_refs,
                "evidence_status": "INFERRED",
                "derived_from": (
                    f"capture:{event.before.capture_id}",
                    f"capture:{event.after.capture_id}",
                ),
                "anchor": f"drift:{event.drift_id}",
            }
        )
    timeline, timeline_truncated = build_timeline(
        raw_events, max_events=config.max_timeline_events
    )
    if timeline_truncated:
        warnings.append(
            IntelligenceWarning(
                code="TIMELINE_LIMIT",
                message=(
                    f"The timeline was truncated at {config.max_timeline_events} "
                    "events. Later events exist and are not shown."
                ),
            )
        )

    investigation = Investigation(
        investigation_id=_investigation_id(inventory),
        schema_version=INVESTIGATION_SCHEMA_VERSION,
        fingerprint_algorithm_version=FINGERPRINT_ALGORITHM_VERSION,
        created_at=datetime.now(UTC),
        capture_inventory=tuple(
            sorted(inventory, key=lambda record: (record.source_name, record.capture_id))
        ),
        server_entities=tuple(entities.values()),
        cryptographic_fingerprints=tuple(
            sorted(fingerprints, key=lambda item: (item.capture_id, item.session_id))
        ),
        drift_events=tuple(drift_events),
        session_correlations=tuple(correlations),
        evidence_timeline=tuple(timeline),
        blast_radius=tuple(build_blast_radius(finding_members)),
        intelligence_warnings=tuple(
            sorted(warnings, key=lambda item: (item.code, item.message))
        ),
        limitations=_INVESTIGATION_LIMITATIONS,
    )
    return BatchOutcome(investigation, results)


def _investigation_id(inventory: list[CaptureRecord]) -> str:
    """Derived from the set of capture hashes, sorted.

    Independent of argument order and of file names, so the same evidence
    analysed twice yields the same investigation identifier.
    """
    material = "|".join(
        sorted(
            record.capture_id
            for record in inventory
            if record.status is not CaptureStatus.DUPLICATE
        )
    )
    return "inv-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
