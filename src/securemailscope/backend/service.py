"""Analysis execution and persistence (M7).

One bounded worker pool runs the **existing** analyzer. There is no second
forensic engine here: this module schedules `analyze_batch`, records what it
produced, and gets out of the way.

Concurrency is deliberately small. Analysis is CPU-bound and a local tool has
one user; a large pool would make every job slower and the interface less
responsive, not more. The pool bounds memory as much as it bounds CPU.

Duplicate work is prevented by an in-process guard keyed on the investigation:
starting the same investigation twice would have two workers writing the same
rows, and the second would overwrite the first's results halfway through.
"""

from __future__ import annotations

import json
import secrets
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from ..config import AnalysisConfig
from ..intelligence.engine import analyze_batch
from ..models.analysis import AnalysisResult
from ..models.intelligence import Investigation
from ..reporting.json_report import result_to_dict
from ..reporting.report_model import build_report
from .database import (
    CaptureRow,
    Database,
    FindingRow,
    IntelligenceRow,
    InvestigationRow,
    JobRow,
    MLResultRow,
    SessionRow,
    utcnow,
)
from .storage import CaptureStorage

__all__ = ["AnalysisService", "JobHandle", "MAX_CONCURRENT_JOBS"]

#: One analysis at a time by default. See the module docstring.
MAX_CONCURRENT_JOBS: Final = 2


@dataclass
class JobHandle:
    job_id: str
    investigation_id: str


class AnalysisService:
    """Schedules analyses, persists results, answers status questions."""

    def __init__(
        self,
        database: Database,
        storage: CaptureStorage,
        *,
        config: AnalysisConfig | None = None,
        max_workers: int = MAX_CONCURRENT_JOBS,
    ) -> None:
        self.database = database
        self.storage = storage
        self.config = config or AnalysisConfig()
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="sms-analysis"
        )
        self._lock = threading.Lock()
        self._running: dict[str, Future[None]] = {}
        # A restart leaves jobs that produced nothing. Record that before
        # accepting new work, so the UI never shows a job from a dead process.
        self.recovered_jobs = database.recover_interrupted_jobs()

    # -- submission -------------------------------------------------------
    def create_investigation(
        self, name: str, capture_ids: list[str]
    ) -> InvestigationRow:
        investigation_id = "inv-" + secrets.token_hex(8)
        with self.database.session() as db_session:
            row = InvestigationRow(
                investigation_id=investigation_id,
                name=name[:255] or "Investigation",
                status="QUEUED",
                capture_count=len(capture_ids),
                capture_ids=json.dumps(capture_ids),
            )
            db_session.add(row)
        with self.database.session() as db_session:
            return db_session.get(InvestigationRow, investigation_id)  # type: ignore[return-value]

    def start(self, investigation_id: str) -> JobHandle:
        """Queue an analysis, refusing to start the same one twice."""
        with self._lock:
            existing = self._running.get(investigation_id)
            if existing is not None and not existing.done():
                raise RuntimeError(
                    f"investigation {investigation_id} is already being analysed; "
                    "starting it again would have two workers writing the same rows"
                )

            with self.database.session() as db_session:
                investigation = db_session.get(InvestigationRow, investigation_id)
                if investigation is None:
                    raise KeyError(investigation_id)
                capture_ids: list[str] = json.loads(investigation.capture_ids)
                job_id = "job-" + secrets.token_hex(8)
                db_session.add(
                    JobRow(
                        job_id=job_id,
                        investigation_id=investigation_id,
                        status="QUEUED",
                        stage="queued",
                        captures_total=len(capture_ids),
                    )
                )
                investigation.status = "QUEUED"

            future = self._pool.submit(self._run, job_id, investigation_id, capture_ids)
            self._running[investigation_id] = future
            return JobHandle(job_id=job_id, investigation_id=investigation_id)

    def wait(self, investigation_id: str, timeout: float = 120.0) -> None:
        """Block until an investigation finishes. For tests and the CLI."""
        future = self._running.get(investigation_id)
        if future is not None:
            future.result(timeout=timeout)

    # -- execution --------------------------------------------------------
    def _set_job(self, job_id: str, **fields: Any) -> None:
        with self.database.session() as db_session:
            job = db_session.get(JobRow, job_id)
            if job is None:  # pragma: no cover - the row is created before submit
                return
            for key, value in fields.items():
                setattr(job, key, value)

    def _run(self, job_id: str, investigation_id: str, capture_ids: list[str]) -> None:
        self._set_job(
            job_id, status="RUNNING", stage="reading captures", started_at=utcnow()
        )
        with self.database.session() as db_session:
            investigation = db_session.get(InvestigationRow, investigation_id)
            if investigation is not None:
                investigation.status = "RUNNING"
            rows = (
                db_session.query(CaptureRow)
                .filter(CaptureRow.capture_id.in_(capture_ids))
                .all()
            )
            paths = {row.capture_id: Path(row.stored_path) for row in rows}

        ordered = [paths[capture_id] for capture_id in capture_ids if capture_id in paths]
        if not ordered:
            self._fail(job_id, investigation_id, "no stored capture files were found")
            return

        def progress(done: int, total: int, name: str) -> None:
            self._set_job(
                job_id, captures_done=done, stage=f"analysed {done}/{total}: {name}"
            )

        try:
            outcome = analyze_batch(ordered, config=self.config, on_capture=progress)
        except Exception as exc:
            # Broad on purpose, and the one place in the codebase where it is
            # right: a worker thread that raises would lose the error entirely
            # and leave the job stuck at RUNNING for ever. It is recorded on
            # the job, never swallowed.
            self._fail(job_id, investigation_id, f"{type(exc).__name__}: {exc}")
            return

        try:
            self._set_job(job_id, stage="persisting results")
            self._persist(investigation_id, outcome.investigation, outcome.results)
        except Exception as exc:
            self._fail(job_id, investigation_id, f"persistence failed: {exc}")
            return

        self._set_job(
            job_id,
            status="COMPLETED",
            stage="completed",
            finished_at=utcnow(),
            warnings_json=json.dumps(
                [
                    f"{w.code}: {w.message}"
                    for w in outcome.investigation.intelligence_warnings
                ]
            ),
        )

    def _fail(self, job_id: str, investigation_id: str, reason: str) -> None:
        self._set_job(
            job_id, status="FAILED", stage="failed", finished_at=utcnow(), error=reason
        )
        with self.database.session() as db_session:
            investigation = db_session.get(InvestigationRow, investigation_id)
            if investigation is not None:
                investigation.status = "FAILED"

    # -- persistence ------------------------------------------------------
    def _persist(
        self,
        investigation_id: str,
        investigation: Investigation,
        results: list[AnalysisResult],
    ) -> None:
        """Write everything in one transaction.

        A partial write would leave an investigation whose findings referred to
        sessions that were never stored, so the whole thing commits or none of
        it does.
        """
        report = build_report(
            results,
            investigation,
            title="SecureMailScope investigation",
        )
        with self.database.session() as db_session:
            row = db_session.get(InvestigationRow, investigation_id)
            if row is None:
                raise KeyError(investigation_id)

            # Re-running an investigation replaces its derived rows rather
            # than accumulating duplicates beside them.
            for model in (SessionRow, FindingRow):
                db_session.query(model).filter(
                    model.investigation_id == investigation_id
                ).delete(synchronize_session=False)

            for result in results:
                capture = db_session.get(CaptureRow, result.capture.capture_id)
                if capture is not None:
                    capture.status = "ANALYZED"
                    capture.packet_count = result.capture.packet_count
                    capture.session_count = len(result.sessions)
                    capture.first_packet_timestamp = _naive(
                        result.capture.first_packet_timestamp
                    )
                    capture.last_packet_timestamp = _naive(
                        result.capture.last_packet_timestamp
                    )
                    capture.result_json = json.dumps(
                        result_to_dict(result, include_segments=False),
                        default=str,
                    )

            for record in investigation.capture_inventory:
                if record.status.value in ("FAILED", "DUPLICATE", "EMPTY"):
                    capture = db_session.get(CaptureRow, record.capture_id)
                    if capture is not None:
                        capture.status = record.status.value
                        capture.failure_reason = record.failure_reason

            detail_by_session = _session_details(results)
            for session in report.sessions:
                db_session.add(
                    SessionRow(
                        session_id=session.session_id,
                        investigation_id=investigation_id,
                        capture_id=session.capture_id,
                        client=session.client,
                        server=session.server,
                        protocol=session.protocol,
                        detection_status=session.detection_status,
                        tls_version=session.tls_version,
                        cipher_suite=session.cipher_suite,
                        key_exchange=session.key_exchange,
                        forward_secrecy=session.forward_secrecy,
                        certificate_visibility=session.certificate_visibility,
                        certificate_subject=session.certificate_subject,
                        upgrade_state=session.upgrade_state,
                        completeness=session.completeness,
                        packet_count=session.packet_count,
                        first_packet=_naive(session.first_packet),
                        last_packet=_naive(session.last_packet),
                        finding_count=session.finding_count,
                        posture_score=session.posture_score,
                        score_status=session.score_status,
                        coverage_ratio=session.coverage_ratio,
                        detail_json=json.dumps(
                            detail_by_session.get(session.session_id, {}), default=str
                        ),
                    )
                )

            for finding in report.findings:
                db_session.add(
                    FindingRow(
                        finding_id=finding.finding_id,
                        investigation_id=investigation_id,
                        capture_id=finding.capture_id,
                        session_id=finding.session_id,
                        rule_id=finding.rule_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        category=finding.category,
                        evaluation_status=finding.evaluation_status,
                        priority=finding.priority,
                        rank=finding.rank,
                        technical_impact=finding.technical_impact,
                        policy_version=report.policy_version,
                        standards_json=json.dumps(list(finding.standards_references)),
                        remediation_json=json.dumps(list(finding.remediation_ids)),
                        limitations_json=json.dumps(list(finding.limitations)),
                        evidence_json=json.dumps(
                            [e.model_dump(mode="json") for e in finding.evidence]
                        ),
                    )
                )

            db_session.merge(
                IntelligenceRow(
                    investigation_id=investigation_id,
                    fingerprint_count=len(investigation.cryptographic_fingerprints),
                    entity_count=len(investigation.server_entities),
                    drift_count=len(investigation.drift_events),
                    correlation_count=len(investigation.session_correlations),
                    timeline_event_count=len(investigation.evidence_timeline),
                    investigation_json=json.dumps(
                        investigation.model_dump(mode="json"), default=str
                    ),
                )
            )

            ml = report.ml
            if ml is not None:
                db_session.merge(
                    MLResultRow(
                        investigation_id=investigation_id,
                        ml_status=ml.ml_status,
                        feature_schema_version=ml.feature_schema_version,
                        anomaly_algorithm=ml.anomaly_algorithm,
                        anomaly_model_id=ml.anomaly_model_id,
                        anomaly_model_version=ml.anomaly_model_version,
                        classifier_model_id=ml.classifier_model_id,
                        classification_validation_status=(
                            ml.classification_validation_status
                        ),
                        anomalous_session_count=ml.anomalous_session_count,
                        not_evaluable_session_count=ml.not_evaluable_session_count,
                        results_json=json.dumps(
                            [
                                r.ml.model_dump(mode="json")
                                for r in results
                                if r.ml is not None
                            ],
                            default=str,
                        ),
                    )
                )

            posture = report.posture
            row.status = "COMPLETED"
            row.updated_at = utcnow()
            row.analysed_capture_count = len(report.analysed_captures)
            row.failed_capture_count = len(report.failed_captures)
            row.session_count = len(report.sessions)
            row.finding_count = len(report.findings)
            row.posture_score = posture.score if posture else None
            row.score_status = posture.status if posture else None
            row.score_band = posture.band if posture else None
            row.coverage_ratio = posture.coverage_ratio if posture else None
            row.policy_id = report.policy_id
            row.policy_version = report.policy_version
            row.policy_fingerprint = report.policy_fingerprint
            row.severity_counts = json.dumps(report.severity_distribution)
            row.protocol_counts = json.dumps(report.protocol_distribution)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _naive(value: datetime | None) -> datetime | None:
    """SQLite's DateTime column does not keep a timezone; store UTC naive."""
    if value is None:
        return None
    return value.replace(tzinfo=None)


def _session_details(results: list[AnalysisResult]) -> dict[str, dict[str, Any]]:
    """Per-session detail for the session page, built once at persist time.

    Assembled here rather than on every request: the source documents are
    large, and re-deriving this per page view would mean parsing the whole
    analysis JSON to render one session.
    """
    details: dict[str, dict[str, Any]] = {}
    for result in results:
        tls_by_session = {item.session_id: item for item in result.tls}
        protocols = {item.session_id: item for item in result.protocols}
        assessments = {
            item.session_id: item
            for item in (result.assessment.sessions if result.assessment else ())
        }
        ml_anomaly = {
            item.session_id: item
            for item in (result.ml.anomaly_results if result.ml else ())
        }
        ml_class = {
            item.session_id: item
            for item in (result.ml.risk_classification if result.ml else ())
        }
        for session in result.sessions:
            tls = tls_by_session.get(session.session_id)
            protocol = protocols.get(session.session_id)
            assessment = assessments.get(session.session_id)
            details[session.session_id] = {
                "tcp": session.model_dump(
                    mode="json",
                    exclude={"client_to_server", "server_to_client"},
                ),
                "streams": {
                    "client_to_server": _stream_summary(session.client_to_server),
                    "server_to_client": _stream_summary(session.server_to_client),
                },
                "protocol": protocol.model_dump(mode="json", exclude={"events"})
                if protocol
                else None,
                "protocol_events": [
                    event.model_dump(mode="json")
                    for event in (protocol.events[:80] if protocol else ())
                ],
                "tls": tls.model_dump(mode="json", exclude={"records"}) if tls else None,
                "assessment": assessment.model_dump(mode="json") if assessment else None,
                "ml": {
                    "anomaly": (
                        ml_anomaly[session.session_id].model_dump(mode="json")
                        if session.session_id in ml_anomaly
                        else None
                    ),
                    "classification": (
                        ml_class[session.session_id].model_dump(mode="json")
                        if session.session_id in ml_class
                        else None
                    ),
                },
            }
    return details


def _stream_summary(stream: Any) -> dict[str, Any]:
    """Counts and gaps only. Reconstructed payload never leaves the engine."""
    return {
        "direction": stream.direction.value,
        "packet_count": stream.packet_count,
        "payload_packet_count": stream.payload_packet_count,
        "bytes_reconstructed": stream.bytes_reconstructed,
        "highest_offset_observed": stream.highest_offset_observed,
        "segment_count": len(stream.segments),
        "run_count": len(stream.runs),
        "gap_count": len(stream.gaps),
        "gaps": [gap.model_dump(mode="json") for gap in stream.gaps[:20]],
        "overlap_conflict_count": len(stream.overlap_conflicts),
        "retransmission_count": stream.retransmission_count,
        "duplicate_count": stream.duplicate_count,
        "out_of_order_count": stream.out_of_order_count,
        "truncated_by_limit": stream.truncated_by_limit,
        "fin_observed": stream.fin_observed,
        "rst_observed": stream.rst_observed,
    }
