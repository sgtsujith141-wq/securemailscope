"""The canonical report model (M7).

JSON, HTML and PDF are three renderings of **one** structure. That is the
whole point of this module: a fact that appears in two formats must come from
one place, so the formats cannot disagree.

Nothing here computes a security conclusion. The posture score, the coverage,
the findings, the drift statuses and the blast-radius counts are all copied
from what the M4 and M5 engines already decided. A template that recalculated
a score in Jinja, or a React component that summed severities in JavaScript,
would be a second engine with no tests -- and the first time it disagreed with
the real one, the report would be wrong in a way nobody could see.

So: **selection and structuring only.** If a number is not already in the
analysis result, it does not appear in a report.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from ..models.analysis import AnalysisResult
    from ..models.intelligence import Investigation

__all__ = [
    "REPORT_MODEL_VERSION",
    "ReportModel",
    "ReportCapture",
    "ReportFinding",
    "ReportSession",
    "build_report",
]

REPORT_MODEL_VERSION = "smsreport/1"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ReportCapture(_Frozen):
    capture_id: str
    source_name: str
    status: str
    file_size_bytes: int | None = None
    packet_count: int = 0
    session_count: int = 0
    first_packet_timestamp: datetime | None = None
    last_packet_timestamp: datetime | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    policy_fingerprint: str | None = None
    failure_reason: str | None = None
    duplicate_of_source: str | None = None


class ReportEvidence(_Frozen):
    """A packet reference, carried through to every format.

    Metadata only: a packet number, a timestamp and a stream offset. No payload
    byte ever reaches a report.
    """

    capture_id: str
    session_id: str | None = None
    packet_number: int
    timestamp: datetime | None = None
    stream_offset: int | None = None
    source_observation: str
    evidence_status: str


class ReportFinding(_Frozen):
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    evaluation_status: str
    capture_id: str
    session_id: str
    priority: str | None = None
    rank: int | None = None
    technical_impact: str
    standards_references: tuple[str, ...] = ()
    remediation_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    evidence: tuple[ReportEvidence, ...] = ()


class ReportSession(_Frozen):
    session_id: str
    capture_id: str
    client: str
    server: str
    protocol: str | None = None
    detection_status: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    forward_secrecy: str | None = None
    certificate_visibility: str | None = None
    certificate_subject: str | None = None
    upgrade_state: str | None = None
    completeness: str | None = None
    packet_count: int = 0
    first_packet: datetime | None = None
    last_packet: datetime | None = None
    finding_count: int = 0
    #: None when the session had too little evidence for a score.
    posture_score: int | None = None
    score_status: str | None = None
    coverage_ratio: float | None = None


class ReportScore(_Frozen):
    status: str
    score: int | None = None
    band: str | None = None
    coverage_ratio: float | None = None
    coverage_sufficient: bool | None = None
    evaluated_units: int = 0
    passed_units: int = 0
    failed_units: int = 0
    unknown_units: int = 0
    formula: str | None = None
    explanation: str | None = None
    scope: str | None = None
    limitations: tuple[str, ...] = ()


class ReportRemediation(_Frozen):
    remediation_id: str
    title: str
    related_rule_ids: tuple[str, ...] = ()
    technical_explanation: str
    recommended_action: str
    expected_security_effect: str
    operational_considerations: str
    validation_steps: tuple[str, ...] = ()


class ReportDrift(_Frozen):
    drift_id: str
    kind: str
    status: str
    entity_id: str
    before_value: str | None = None
    before_capture: str | None = None
    before_observed: bool = False
    after_value: str | None = None
    after_capture: str | None = None
    after_observed: bool = False
    client_offers_comparable: bool | None = None
    explanation: str
    limitations: tuple[str, ...] = ()


class ReportCorrelation(_Frozen):
    correlation_id: str
    correlation_type: str
    relationship_basis: str
    session_count: int
    capture_count: int
    finding_count: int
    policy_versions: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class ReportBlastRadius(_Frozen):
    subject: str
    subject_kind: str
    session_count: int
    entity_count: int
    capture_count: int
    finding_count: int
    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    scope_statement: str
    counting_method: str
    limitations: tuple[str, ...] = ()


class ReportFingerprint(_Frozen):
    fingerprint_id: str
    algorithm_version: str
    completeness: str
    session_id: str
    capture_id: str
    endpoint: str
    components: tuple[tuple[str, str, str], ...] = ()
    missing_components: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class ReportEntity(_Frozen):
    entity_id: str
    endpoint: str
    session_count: int
    capture_count: int
    protocols: tuple[str, ...] = ()
    certificate_fingerprints: tuple[str, ...] = ()
    relationship_count: int = 0
    limitations: tuple[str, ...] = ()


class ReportTimelineEvent(_Frozen):
    event_id: str
    event_type: str
    timestamp: datetime | None = None
    capture_id: str
    session_id: str | None = None
    description: str
    evidence_status: str
    packet_numbers: tuple[int, ...] = ()
    order_index: int = 0


class ReportML(_Frozen):
    """ML status, carried with its validation caveats intact.

    ``anomaly_algorithm`` says what actually decided, because M6 selected a
    deterministic rarity baseline over Isolation Forest and a report that
    called it "machine learning" would be misrepresenting the result.
    """

    ml_status: str
    feature_schema_version: str | None = None
    anomaly_algorithm: str | None = None
    anomaly_model_id: str | None = None
    anomaly_model_version: str | None = None
    anomaly_training_samples: int | None = None
    anomaly_reference_population: str | None = None
    classifier_model_id: str | None = None
    classifier_algorithm: str | None = None
    classification_validation_status: str = "NOT_VALIDATED"
    anomalous_session_count: int = 0
    not_evaluable_session_count: int = 0
    evaluation_limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    disclosure: str = ""


class ReportModel(_Frozen):
    """Everything a report renders, in one place."""

    report_model_version: str = REPORT_MODEL_VERSION
    generated_at: datetime
    tool_name: str
    tool_version: str
    schema_version: str
    title: str
    investigation_id: str | None = None
    scope_statement: str

    captures: tuple[ReportCapture, ...] = ()
    sessions: tuple[ReportSession, ...] = ()
    findings: tuple[ReportFinding, ...] = ()
    remediations: tuple[ReportRemediation, ...] = ()
    posture: ReportScore | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    policy_fingerprint: str | None = None

    fingerprints: tuple[ReportFingerprint, ...] = ()
    entities: tuple[ReportEntity, ...] = ()
    drift: tuple[ReportDrift, ...] = ()
    correlations: tuple[ReportCorrelation, ...] = ()
    blast_radius: tuple[ReportBlastRadius, ...] = ()
    timeline: tuple[ReportTimelineEvent, ...] = ()
    ml: ReportML | None = None

    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def analysed_captures(self) -> tuple[ReportCapture, ...]:
        return tuple(c for c in self.captures if c.status == "ANALYZED")

    @property
    def failed_captures(self) -> tuple[ReportCapture, ...]:
        return tuple(c for c in self.captures if c.status == "FAILED")


# ---------------------------------------------------------------------------
# construction
# ---------------------------------------------------------------------------
def _evidence_from(
    refs: Any, capture_id: str, session_id: str | None, source: str, status: str,
    offsets: tuple[int, ...] = (),
) -> tuple[ReportEvidence, ...]:
    offset = offsets[0] if offsets else None
    return tuple(
        ReportEvidence(
            capture_id=capture_id,
            session_id=session_id,
            packet_number=reference.packet_number,
            timestamp=reference.timestamp,
            stream_offset=offset,
            source_observation=source,
            evidence_status=status,
        )
        for reference in refs
    )


def _session_rows(result: AnalysisResult) -> list[ReportSession]:
    tls_by_session = {item.session_id: item for item in result.tls}
    protocols = {item.session_id: item for item in result.protocols}
    assessments = {
        item.session_id: item
        for item in (result.assessment.sessions if result.assessment else ())
    }
    findings_per_session: dict[str, int] = {}
    for finding in result.assessment.findings if result.assessment else ():
        findings_per_session[finding.session_id] = (
            findings_per_session.get(finding.session_id, 0) + 1
        )

    rows: list[ReportSession] = []
    for session in result.sessions:
        tls = tls_by_session.get(session.session_id)
        protocol = protocols.get(session.session_id)
        assessment = assessments.get(session.session_id)
        leaf = next(
            (
                certificate
                for certificate in (tls.certificates.certificates if tls else ())
                if certificate.chain_position == 0
            ),
            None,
        )
        version = tls.version.selected_version if tls else None
        suite = tls.cipher_suite.selected if tls else None
        score = assessment.posture_score if assessment else None
        rows.append(
            ReportSession(
                session_id=session.session_id,
                capture_id=result.capture.capture_id,
                client=f"{session.flow.client.ip}:{session.flow.client.port}",
                server=f"{session.flow.server.ip}:{session.flow.server.port}",
                protocol=protocol.detection.protocol.value if protocol else None,
                detection_status=protocol.detection.status.value if protocol else None,
                tls_version=(version.name or version.hex_value) if version else None,
                cipher_suite=(suite.name or suite.hex_value) if suite else None,
                key_exchange=tls.key_exchange.method if tls else None,
                forward_secrecy=(
                    tls.forward_secrecy.status.value
                    if tls and tls.forward_secrecy
                    else None
                ),
                certificate_visibility=(
                    tls.certificates.visibility.value if tls else None
                ),
                certificate_subject=leaf.subject if leaf else None,
                upgrade_state=(
                    protocol.upgrade.state.value
                    if protocol and protocol.upgrade
                    else None
                ),
                completeness=session.completeness.value,
                packet_count=session.packet_count,
                first_packet=session.first_packet.timestamp,
                last_packet=session.last_packet.timestamp,
                finding_count=findings_per_session.get(session.session_id, 0),
                posture_score=score.score if score else None,
                score_status=score.status.value if score else None,
                coverage_ratio=score.coverage.coverage_ratio if score else None,
            )
        )
    return rows


def _finding_rows(result: AnalysisResult) -> list[ReportFinding]:
    if result.assessment is None:
        return []
    priorities = {
        item.finding_id: item for item in result.assessment.prioritised_findings
    }
    rows: list[ReportFinding] = []
    for finding in result.assessment.findings:
        prioritised = priorities.get(finding.finding_id)
        rows.append(
            ReportFinding(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                category=finding.category.value,
                evaluation_status=finding.evaluation_status.value,
                capture_id=finding.capture_id,
                session_id=finding.session_id,
                priority=prioritised.priority.value if prioritised else None,
                rank=prioritised.rank if prioritised else None,
                technical_impact=finding.technical_impact,
                standards_references=tuple(
                    reference.document
                    + (f" §{reference.section}" if reference.section else "")
                    for reference in finding.standards_references
                ),
                remediation_ids=tuple(finding.remediation_ids),
                limitations=tuple(finding.limitations),
                evidence=_evidence_from(
                    finding.evidence_refs,
                    finding.capture_id,
                    finding.session_id,
                    f"assessment rule {finding.rule_id}",
                    "INFERRED",
                    tuple(finding.stream_offsets),
                ),
            )
        )
    return rows


def _ml_block(result: AnalysisResult) -> ReportML | None:
    ml = result.ml
    if ml is None:
        return None
    anomaly = ml.anomaly_model
    classifier = ml.classification_model
    return ReportML(
        ml_status=ml.ml_status.value,
        feature_schema_version=ml.feature_schema_version,
        anomaly_algorithm=anomaly.algorithm if anomaly else None,
        anomaly_model_id=anomaly.model_id if anomaly else None,
        anomaly_model_version=anomaly.model_version if anomaly else None,
        anomaly_training_samples=anomaly.training_sample_count if anomaly else None,
        anomaly_reference_population=anomaly.reference_population if anomaly else None,
        classifier_model_id=classifier.model_id if classifier else None,
        classifier_algorithm=classifier.algorithm if classifier else None,
        classification_validation_status=(
            ml.risk_classification[0].status.value
            if ml.risk_classification
            else "MODEL_UNAVAILABLE"
        ),
        anomalous_session_count=sum(
            1 for item in ml.anomaly_results if item.status.value == "ANOMALOUS"
        ),
        not_evaluable_session_count=sum(
            1 for item in ml.anomaly_results if item.status.value == "NOT_EVALUABLE"
        ),
        evaluation_limitations=tuple(ml.evaluation_limitations),
        warnings=tuple(f"{w.code}: {w.message}" for w in ml.ml_warnings),
        disclosure=ml.disclosure,
    )


def build_report(
    results: list[AnalysisResult],
    investigation: Investigation | None = None,
    *,
    title: str = "SecureMailScope forensic report",
    generated_at: datetime | None = None,
) -> ReportModel:
    """Assemble the canonical report from analysis results.

    Everything is copied. No score is recomputed, no severity is re-derived and
    no count is invented: if a value is not in the analysis, it is absent from
    the report rather than filled in.
    """
    if not results:
        raise ValueError("a report needs at least one analysis result")

    sessions: list[ReportSession] = []
    findings: list[ReportFinding] = []
    captures: list[ReportCapture] = []
    protocol_distribution: dict[str, int] = {}
    warnings: list[str] = []

    inventory = {
        record.capture_id: record
        for record in (investigation.capture_inventory if investigation else ())
    }

    for result in results:
        sessions.extend(_session_rows(result))
        findings.extend(_finding_rows(result))
        record = inventory.get(result.capture.capture_id)
        captures.append(
            ReportCapture(
                capture_id=result.capture.capture_id,
                source_name=result.capture.source_name,
                status=record.status.value if record else "ANALYZED",
                file_size_bytes=result.capture.file_size_bytes,
                packet_count=result.capture.packet_count,
                session_count=len(result.sessions),
                first_packet_timestamp=result.capture.first_packet_timestamp,
                last_packet_timestamp=result.capture.last_packet_timestamp,
                policy_id=(
                    result.assessment.policy.policy_id if result.assessment else None
                ),
                policy_version=(
                    result.assessment.policy.policy_version
                    if result.assessment
                    else None
                ),
                policy_fingerprint=(
                    result.assessment.policy.policy_fingerprint
                    if result.assessment
                    else None
                ),
            )
        )
        for item in result.protocols:
            name = item.detection.protocol.value
            protocol_distribution[name] = protocol_distribution.get(name, 0) + 1
        warnings.extend(warning.message for warning in result.warnings)

    # Captures the investigation knows about but which produced no result --
    # failures and duplicates. They must stay visible.
    seen = {capture.capture_id for capture in captures}
    for record in inventory.values():
        if record.capture_id in seen:
            continue
        captures.append(
            ReportCapture(
                capture_id=record.capture_id,
                source_name=record.source_name,
                status=record.status.value,
                file_size_bytes=record.file_size_bytes,
                packet_count=record.packet_count,
                session_count=record.session_count,
                failure_reason=record.failure_reason,
                duplicate_of_source=record.duplicate_of_source,
            )
        )

    severity_distribution: dict[str, int] = {}
    for finding in findings:
        severity_distribution[finding.severity] = (
            severity_distribution.get(finding.severity, 0) + 1
        )

    primary = results[0]
    assessment = primary.assessment
    posture = None
    remediations: list[ReportRemediation] = []
    if assessment is not None:
        score = assessment.posture_score
        posture = ReportScore(
            status=score.status.value,
            score=score.score,
            band=score.band.value,
            coverage_ratio=score.coverage.coverage_ratio,
            coverage_sufficient=score.coverage.sufficient,
            evaluated_units=score.tally.evaluated,
            passed_units=score.tally.passed,
            failed_units=score.tally.failed,
            unknown_units=score.tally.unknown,
            formula=score.formula,
            explanation=score.explanation,
            scope=score.scope,
            limitations=tuple(score.limitations),
        )
        remediations = [
            ReportRemediation(
                remediation_id=item.remediation_id,
                title=item.title,
                related_rule_ids=tuple(item.related_rule_ids),
                technical_explanation=item.technical_explanation,
                recommended_action=item.recommended_action,
                expected_security_effect=item.expected_security_effect,
                operational_considerations=item.operational_considerations,
                validation_steps=tuple(item.validation_steps),
            )
            for item in assessment.remediations
        ]

    fingerprints: list[ReportFingerprint] = []
    entities: list[ReportEntity] = []
    drift: list[ReportDrift] = []
    correlations: list[ReportCorrelation] = []
    blast: list[ReportBlastRadius] = []
    timeline: list[ReportTimelineEvent] = []
    limitations: list[str] = []
    scope = "Observed within analyzed captures only."

    if investigation is not None:
        scope = investigation.scope_statement
        limitations.extend(investigation.limitations)
        warnings.extend(
            f"{warning.code}: {warning.message}"
            for warning in investigation.intelligence_warnings
        )
        fingerprints = [
            ReportFingerprint(
                fingerprint_id=item.fingerprint_id,
                algorithm_version=item.algorithm_version,
                completeness=item.completeness.value,
                session_id=item.session_id,
                capture_id=item.capture_id,
                endpoint=item.endpoint.label,
                components=tuple(
                    (
                        component.name,
                        component.value or "" if component.present else "",
                        component.source.value,
                    )
                    for component in item.components
                ),
                missing_components=tuple(item.missing_components),
                limitations=tuple(item.limitations),
            )
            for item in investigation.cryptographic_fingerprints
        ]
        entities = [
            ReportEntity(
                entity_id=item.entity_id,
                endpoint=item.endpoint.label,
                session_count=len(item.session_ids),
                capture_count=len(item.capture_ids),
                protocols=tuple(item.protocols),
                certificate_fingerprints=tuple(item.certificate_fingerprints),
                relationship_count=len(item.relationships),
                limitations=tuple(item.limitations),
            )
            for item in investigation.server_entities
        ]
        drift = [
            ReportDrift(
                drift_id=item.drift_id,
                kind=item.kind.value,
                status=item.status.value,
                entity_id=item.entity_id,
                before_value=item.before.value,
                before_capture=item.before.capture_id,
                before_observed=item.before.observed,
                after_value=item.after.value,
                after_capture=item.after.capture_id,
                after_observed=item.after.observed,
                client_offers_comparable=item.client_offers_comparable,
                explanation=item.explanation,
                limitations=tuple(item.limitations),
            )
            for item in investigation.drift_events
        ]
        correlations = [
            ReportCorrelation(
                correlation_id=item.correlation_id,
                correlation_type=item.correlation_type.value,
                relationship_basis=item.relationship_basis,
                session_count=len(item.related_session_ids),
                capture_count=len(item.related_capture_ids),
                finding_count=len(item.related_finding_ids),
                policy_versions=tuple(item.policy_versions),
                limitations=tuple(item.limitations),
            )
            for item in investigation.session_correlations
        ]
        blast = [
            ReportBlastRadius(
                subject=item.subject,
                subject_kind=item.subject_kind,
                session_count=item.session_count,
                entity_count=item.entity_count,
                capture_count=item.capture_count,
                finding_count=item.finding_count,
                protocol_distribution=dict(item.protocol_distribution),
                scope_statement=item.scope_statement,
                counting_method=item.counting_method,
                limitations=tuple(item.limitations),
            )
            for item in investigation.blast_radius
        ]
        timeline = [
            ReportTimelineEvent(
                event_id=item.event_id,
                event_type=item.event_type.value,
                timestamp=item.timestamp,
                capture_id=item.capture_id,
                session_id=item.session_id,
                description=item.description,
                evidence_status=item.evidence_status,
                packet_numbers=tuple(
                    reference.packet_number for reference in item.packet_refs
                ),
                order_index=item.order_index,
            )
            for item in investigation.evidence_timeline
        ]

    return ReportModel(
        generated_at=generated_at or datetime.now(UTC),
        tool_name=primary.tool.name,
        tool_version=primary.tool.version,
        schema_version=primary.tool.report_schema_version,
        title=title,
        investigation_id=investigation.investigation_id if investigation else None,
        scope_statement=scope,
        captures=tuple(captures),
        sessions=tuple(sessions),
        findings=tuple(findings),
        remediations=tuple(remediations),
        posture=posture,
        policy_id=assessment.policy.policy_id if assessment else None,
        policy_version=assessment.policy.policy_version if assessment else None,
        policy_fingerprint=(
            assessment.policy.policy_fingerprint if assessment else None
        ),
        fingerprints=tuple(fingerprints),
        entities=tuple(entities),
        drift=tuple(drift),
        correlations=tuple(correlations),
        blast_radius=tuple(blast),
        timeline=tuple(timeline),
        ml=_ml_block(primary),
        protocol_distribution=dict(sorted(protocol_distribution.items())),
        severity_distribution=dict(sorted(severity_distribution.items())),
        limitations=tuple(limitations),
        warnings=tuple(warnings),
    )
