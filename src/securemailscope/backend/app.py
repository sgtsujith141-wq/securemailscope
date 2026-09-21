"""The local FastAPI application (M7).

A thin adapter over the existing engine. Every analytical answer here was
computed by M1-M6 and persisted; this module reads rows and shapes responses.
There is no second forensic engine inside FastAPI, and no endpoint recomputes
a score, a severity or a count.

Security posture is in :mod:`securemailscope.backend.security` and is applied
as middleware here: host allowlist, explicit CORS origins, a local token, and
error bodies that say what went wrong without describing the server.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select

from ..config import AnalysisConfig
from ..models.analysis import REPORT_SCHEMA_VERSION
from ..reporting.html_report import render_html
from ..reporting.pdf_report import render_pdf
from ..reporting.report_model import build_report
from .database import (
    CaptureRow,
    Database,
    FindingRow,
    IntelligenceRow,
    InvestigationRow,
    JobRow,
    MLResultRow,
    ReportExportRow,
    SessionRow,
)
from .schemas import (
    CaptureSummary,
    ErrorResponse,
    EvidenceRef,
    ExportSummary,
    FindingDetail,
    FindingSummary,
    HealthResponse,
    InvestigationDetail,
    InvestigationSummary,
    JobStatus,
    MLSummary,
    Page,
    SessionDetail,
    SessionSummary,
    SettingsPayload,
    TimelineEntry,
)
from .security import (
    ALLOWED_HOSTS,
    DEFAULT_PORT,
    TOKEN_HEADER,
    LocalToken,
    allowed_origins,
)
from .service import AnalysisService
from .storage import CaptureStorage, UploadRejected

__all__ = ["create_app", "AppState", "API_VERSION"]

API_VERSION: Final = "1.0.0"
_LOG = logging.getLogger("securemailscope.api")

#: Paths that must work before a token exists, so a client can bootstrap.
_OPEN_PATHS: Final = frozenset({"/api/health", "/docs", "/openapi.json", "/redoc"})


class AppState:
    """Everything one running application owns."""

    def __init__(
        self,
        root: Path,
        *,
        config: AnalysisConfig | None = None,
        max_upload_bytes: int = 512 << 20,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.database = Database(self.root / "securemailscope.sqlite3")
        self.storage = CaptureStorage(self.root / "storage", max_bytes=max_upload_bytes)
        self.config = config or AnalysisConfig()
        self.service = AnalysisService(self.database, self.storage, config=self.config)
        self.token = LocalToken(self.root / "api-token")
        self.max_upload_bytes = max_upload_bytes
        self.default_report_format = "pdf"
        self.retain_captures = True

    def shutdown(self) -> None:
        self.service.shutdown()
        self.database.close()


def _json_field(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:  # pragma: no cover - only a corrupted row
        return default


def _investigation_summary(row: InvestigationRow) -> InvestigationSummary:
    return InvestigationSummary(
        investigation_id=row.investigation_id,
        name=row.name,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        capture_count=row.capture_count,
        analysed_capture_count=row.analysed_capture_count,
        failed_capture_count=row.failed_capture_count,
        session_count=row.session_count,
        finding_count=row.finding_count,
        posture_score=row.posture_score,
        score_status=row.score_status,
        score_band=row.score_band,
        coverage_ratio=row.coverage_ratio,
        severity_counts=_json_field(row.severity_counts, {}),
        protocol_counts=_json_field(row.protocol_counts, {}),
    )


def _job_status(row: JobRow) -> JobStatus:
    return JobStatus(
        job_id=row.job_id,
        investigation_id=row.investigation_id,
        status=row.status,
        stage=row.stage,
        captures_total=row.captures_total,
        captures_done=row.captures_done,
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        error=row.error,
        warnings=_json_field(row.warnings_json, []),
    )


def _ml_summary(row: MLResultRow | None) -> MLSummary | None:
    if row is None:
        return None
    return MLSummary(
        ml_status=row.ml_status,
        feature_schema_version=row.feature_schema_version,
        anomaly_algorithm=row.anomaly_algorithm,
        # M6 selected a deterministic frequency table over Isolation Forest.
        # Saying so explicitly is the only way a UI can avoid calling it ML.
        anomaly_detector_is_ml=row.anomaly_algorithm not in (None, "rarity_baseline"),
        anomaly_model_id=row.anomaly_model_id,
        anomaly_model_version=row.anomaly_model_version,
        classifier_model_id=row.classifier_model_id,
        classification_validation_status=row.classification_validation_status,
        anomalous_session_count=row.anomalous_session_count,
        not_evaluable_session_count=row.not_evaluable_session_count,
        evaluation_available=True,
    )


def _session_summary(row: SessionRow) -> SessionSummary:
    return SessionSummary.model_validate(row)


def _finding_summary(row: FindingRow) -> FindingSummary:
    return FindingSummary.model_validate(row)


def _results_for(state: AppState, investigation_id: str) -> tuple[list[Any], Any]:
    """Rebuild the analysis objects a report needs, from persisted documents.

    Deserialising what was stored rather than re-analysing the captures: the
    engine already produced these, and re-running it would risk a report that
    disagrees with the investigation it claims to describe.
    """
    from ..models.analysis import AnalysisResult
    from ..models.intelligence import Investigation

    with state.database.session() as db_session:
        investigation_row = db_session.get(InvestigationRow, investigation_id)
        if investigation_row is None:
            raise HTTPException(status_code=404, detail="investigation not found")
        capture_ids: list[str] = _json_field(investigation_row.capture_ids, [])
        captures = (
            db_session.query(CaptureRow)
            .filter(CaptureRow.capture_id.in_(capture_ids))
            .all()
        )
        documents = [row.result_json for row in captures if row.result_json]
        intelligence = db_session.get(IntelligenceRow, investigation_id)
        intelligence_json = intelligence.investigation_json if intelligence else None

    if not documents:
        raise HTTPException(
            status_code=409,
            detail=(
                "this investigation has no analysed captures yet, so there is "
                "nothing to export"
            ),
        )
    results = [AnalysisResult.model_validate(json.loads(text)) for text in documents]
    investigation = (
        Investigation.model_validate(json.loads(intelligence_json))
        if intelligence_json
        else None
    )
    return results, investigation


def create_app(
    state: AppState,
    *,
    port: int = DEFAULT_PORT,
    require_token: bool = True,
) -> FastAPI:
    """Build the application. One state object, injected everywhere."""
    app = FastAPI(
        title="SecureMailScope local API",
        version=API_VERSION,
        description=(
            "Local-only API over the SecureMailScope forensic engine. Binds to "
            "127.0.0.1, validates the Host header, uses an explicit CORS origin "
            "allowlist and a local token. It makes no outbound network request "
            "and sends no telemetry."
        ),
    )
    app.state.sms = state

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(port),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["content-type", TOKEN_HEADER],
        max_age=600,
    )

    @app.middleware("http")
    async def _guard(request: Request, call_next: Any) -> Response:
        # Host allowlist first: this is the DNS-rebinding defence, and it has
        # to run before anything reads the request body.
        host = (request.headers.get("host") or "").split(":")[0].strip("[]")
        if host and host not in {h.strip("[]") for h in ALLOWED_HOSTS}:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    error="host_not_allowed",
                    detail=(
                        f"requests for host {host!r} are refused. This API answers "
                        "only to localhost names, which prevents a rebound DNS "
                        "name from reaching it."
                    ),
                    status_code=400,
                ).model_dump(),
            )
        if (
            require_token
            and request.method != "OPTIONS"
            and request.url.path not in _OPEN_PATHS
            and not state.token.matches(request.headers.get(TOKEN_HEADER))
        ):
            return JSONResponse(
                status_code=401,
                content=ErrorResponse(
                    error="unauthorised",
                    detail=(
                        "a valid local API token is required. It is written to "
                        "the application data directory at startup."
                    ),
                    status_code=401,
                ).model_dump(),
            )
        response: Response = await call_next(request)
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["content-security-policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Logged in full locally, reported briefly to the caller. An API that
        # echoes a stack trace tells an attacker about the filesystem.
        _LOG.exception("unhandled error serving %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_error",
                detail=(
                    "the request could not be completed. The reason was written "
                    "to the local application log."
                ),
                status_code=500,
            ).model_dump(),
        )

    def get_state() -> AppState:
        return state

    # -- health -----------------------------------------------------------
    @app.get("/api/health", response_model=HealthResponse, tags=["system"])
    def health(app_state: AppState = Depends(get_state)) -> HealthResponse:
        ml_status = "DISABLED"
        available = False
        if app_state.config.enable_ml:
            from ..ml.inference import get_engine

            engine = get_engine()
            ml_status = engine.status.value
            available = engine.anomaly is not None
        return HealthResponse(
            status="ok",
            tool_name="securemailscope",
            tool_version=API_VERSION,
            report_schema_version=REPORT_SCHEMA_VERSION,
            database_schema_version=app_state.database.schema_version,
            ml_available=available,
            ml_status=ml_status,
        )

    # -- captures ---------------------------------------------------------
    @app.post("/api/captures", response_model=CaptureSummary, tags=["captures"])
    async def upload_capture(
        file: UploadFile = File(...),
        app_state: AppState = Depends(get_state),
    ) -> CaptureSummary:
        """Store an uploaded capture privately, validating as it streams."""
        try:
            stored = app_state.storage.store(file.file, file.filename or "capture")
        except UploadRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        capture_id = f"sha256:{stored.sha256}"
        with app_state.database.session() as db_session:
            existing = db_session.get(CaptureRow, capture_id)
            if existing is not None:
                # Identical bytes under a new name are the same evidence. The
                # duplicate upload is discarded, not stored twice.
                app_state.storage.delete_capture(stored.storage_id)
                return CaptureSummary.model_validate(existing)
            row = CaptureRow(
                capture_id=capture_id,
                storage_id=stored.storage_id,
                original_name=stored.original_name,
                stored_path=str(stored.path),
                file_size_bytes=stored.size_bytes,
                sha256=capture_id,
                file_format=stored.file_format,
                status="UPLOADED",
            )
            db_session.add(row)
        with app_state.database.session() as db_session:
            return CaptureSummary.model_validate(
                db_session.get(CaptureRow, capture_id)
            )

    @app.get("/api/captures", response_model=Page[CaptureSummary], tags=["captures"])
    def list_captures(
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        app_state: AppState = Depends(get_state),
    ) -> Page[CaptureSummary]:
        with app_state.database.session() as db_session:
            total = db_session.scalar(select(func.count()).select_from(CaptureRow)) or 0
            rows = (
                db_session.query(CaptureRow)
                .order_by(CaptureRow.uploaded_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return Page[CaptureSummary](
                items=[CaptureSummary.model_validate(row) for row in rows],
                total=total,
                offset=offset,
                limit=limit,
            )

    # -- investigations ---------------------------------------------------
    @app.post(
        "/api/investigations", response_model=InvestigationSummary, tags=["investigations"]
    )
    def create_investigation(
        payload: dict[str, Any],
        app_state: AppState = Depends(get_state),
    ) -> InvestigationSummary:
        capture_ids = payload.get("capture_ids") or []
        if not isinstance(capture_ids, list) or not capture_ids:
            raise HTTPException(
                status_code=422, detail="at least one capture_id is required"
            )
        with app_state.database.session() as db_session:
            found = (
                db_session.query(CaptureRow)
                .filter(CaptureRow.capture_id.in_(capture_ids))
                .count()
            )
        if found != len(set(capture_ids)):
            raise HTTPException(
                status_code=404, detail="one or more captures were not found"
            )
        row = app_state.service.create_investigation(
            str(payload.get("name") or "Investigation"), list(capture_ids)
        )
        return _investigation_summary(row)

    @app.post(
        "/api/investigations/{investigation_id}/analyze",
        response_model=JobStatus,
        tags=["investigations"],
    )
    def start_analysis(
        investigation_id: str, app_state: AppState = Depends(get_state)
    ) -> JobStatus:
        try:
            handle = app_state.service.start(investigation_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404, detail="investigation not found"
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        with app_state.database.session() as db_session:
            row = db_session.get(JobRow, handle.job_id)
            if row is None:  # pragma: no cover - created moments earlier
                raise HTTPException(status_code=500, detail="job row was not created")
            return _job_status(row)

    @app.get(
        "/api/investigations", response_model=Page[InvestigationSummary],
        tags=["investigations"],
    )
    def list_investigations(
        offset: int = Query(0, ge=0),
        limit: int = Query(25, ge=1, le=100),
        app_state: AppState = Depends(get_state),
    ) -> Page[InvestigationSummary]:
        with app_state.database.session() as db_session:
            total = (
                db_session.scalar(select(func.count()).select_from(InvestigationRow)) or 0
            )
            rows = (
                db_session.query(InvestigationRow)
                .order_by(InvestigationRow.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return Page[InvestigationSummary](
                items=[_investigation_summary(row) for row in rows],
                total=total,
                offset=offset,
                limit=limit,
            )

    @app.get(
        "/api/investigations/{investigation_id}",
        response_model=InvestigationDetail,
        tags=["investigations"],
    )
    def get_investigation(
        investigation_id: str, app_state: AppState = Depends(get_state)
    ) -> InvestigationDetail:
        with app_state.database.session() as db_session:
            row = db_session.get(InvestigationRow, investigation_id)
            if row is None:
                raise HTTPException(status_code=404, detail="investigation not found")
            capture_ids: list[str] = _json_field(row.capture_ids, [])
            captures = (
                db_session.query(CaptureRow)
                .filter(CaptureRow.capture_id.in_(capture_ids))
                .all()
            )
            jobs = (
                db_session.query(JobRow)
                .filter(JobRow.investigation_id == investigation_id)
                .order_by(JobRow.created_at.desc())
                .all()
            )
            intelligence = db_session.get(IntelligenceRow, investigation_id)
            ml = _ml_summary(db_session.get(MLResultRow, investigation_id))
            warnings: list[str] = []
            for job in jobs:
                warnings.extend(_json_field(job.warnings_json, []))
            return InvestigationDetail(
                investigation=_investigation_summary(row),
                captures=[CaptureSummary.model_validate(c) for c in captures],
                jobs=[_job_status(job) for job in jobs],
                policy_id=row.policy_id,
                policy_version=row.policy_version,
                policy_fingerprint=row.policy_fingerprint,
                fingerprint_count=intelligence.fingerprint_count if intelligence else 0,
                entity_count=intelligence.entity_count if intelligence else 0,
                drift_count=intelligence.drift_count if intelligence else 0,
                correlation_count=intelligence.correlation_count if intelligence else 0,
                timeline_event_count=(
                    intelligence.timeline_event_count if intelligence else 0
                ),
                ml=ml,
                warnings=warnings,
            )

    @app.get(
        "/api/investigations/{investigation_id}/jobs",
        response_model=list[JobStatus],
        tags=["investigations"],
    )
    def list_jobs(
        investigation_id: str, app_state: AppState = Depends(get_state)
    ) -> list[JobStatus]:
        with app_state.database.session() as db_session:
            rows = (
                db_session.query(JobRow)
                .filter(JobRow.investigation_id == investigation_id)
                .order_by(JobRow.created_at.desc())
                .all()
            )
            return [_job_status(row) for row in rows]

    @app.get("/api/jobs/{job_id}", response_model=JobStatus, tags=["investigations"])
    def get_job(job_id: str, app_state: AppState = Depends(get_state)) -> JobStatus:
        with app_state.database.session() as db_session:
            row = db_session.get(JobRow, job_id)
            if row is None:
                raise HTTPException(status_code=404, detail="job not found")
            return _job_status(row)

    # -- sessions ---------------------------------------------------------
    @app.get(
        "/api/investigations/{investigation_id}/sessions",
        response_model=Page[SessionSummary],
        tags=["sessions"],
    )
    def list_sessions(
        investigation_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        search: str | None = None,
        protocol: str | None = None,
        tls_version: str | None = None,
        capture_id: str | None = None,
        has_findings: bool | None = None,
        sort: str = Query("session_id"),
        direction: str = Query("asc", pattern="^(asc|desc)$"),
        app_state: AppState = Depends(get_state),
    ) -> Page[SessionSummary]:
        sortable = {
            "session_id": SessionRow.session_id,
            "server": SessionRow.server,
            "protocol": SessionRow.protocol,
            "tls_version": SessionRow.tls_version,
            "packet_count": SessionRow.packet_count,
            "finding_count": SessionRow.finding_count,
            "posture_score": SessionRow.posture_score,
        }
        if sort not in sortable:
            raise HTTPException(
                status_code=422,
                detail=f"sort must be one of {', '.join(sorted(sortable))}",
            )
        with app_state.database.session() as db_session:
            query = db_session.query(SessionRow).filter(
                SessionRow.investigation_id == investigation_id
            )
            if protocol:
                query = query.filter(SessionRow.protocol == protocol)
            if tls_version:
                query = query.filter(SessionRow.tls_version == tls_version)
            if capture_id:
                query = query.filter(SessionRow.capture_id == capture_id)
            if has_findings is True:
                query = query.filter(SessionRow.finding_count > 0)
            if has_findings is False:
                query = query.filter(SessionRow.finding_count == 0)
            if search:
                pattern = f"%{search}%"
                query = query.filter(
                    SessionRow.session_id.like(pattern)
                    | SessionRow.server.like(pattern)
                    | SessionRow.client.like(pattern)
                    | SessionRow.cipher_suite.like(pattern)
                )
            total = query.count()
            column = sortable[sort]
            query = query.order_by(
                column.desc() if direction == "desc" else column.asc()
            )
            rows = query.offset(offset).limit(limit).all()
            return Page[SessionSummary](
                items=[_session_summary(row) for row in rows],
                total=total,
                offset=offset,
                limit=limit,
            )

    @app.get(
        "/api/sessions/{session_id}", response_model=SessionDetail, tags=["sessions"]
    )
    def get_session(
        session_id: str, app_state: AppState = Depends(get_state)
    ) -> SessionDetail:
        with app_state.database.session() as db_session:
            row = db_session.get(SessionRow, session_id)
            if row is None:
                raise HTTPException(status_code=404, detail="session not found")
            findings = (
                db_session.query(FindingRow)
                .filter(FindingRow.session_id == session_id)
                .order_by(FindingRow.rank)
                .all()
            )
            return SessionDetail(
                session=_session_summary(row),
                findings=[_finding_summary(f) for f in findings],
                detail=_json_field(row.detail_json, {}),
            )

    # -- findings ---------------------------------------------------------
    @app.get(
        "/api/investigations/{investigation_id}/findings",
        response_model=Page[FindingSummary],
        tags=["findings"],
    )
    def list_findings(
        investigation_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=500),
        severity: str | None = None,
        category: str | None = None,
        rule_id: str | None = None,
        session_id: str | None = None,
        capture_id: str | None = None,
        evaluation_status: str | None = None,
        app_state: AppState = Depends(get_state),
    ) -> Page[FindingSummary]:
        with app_state.database.session() as db_session:
            query = db_session.query(FindingRow).filter(
                FindingRow.investigation_id == investigation_id
            )
            for column, value in (
                (FindingRow.severity, severity),
                (FindingRow.category, category),
                (FindingRow.rule_id, rule_id),
                (FindingRow.session_id, session_id),
                (FindingRow.capture_id, capture_id),
                (FindingRow.evaluation_status, evaluation_status),
            ):
                if value:
                    query = query.filter(column == value)
            total = query.count()
            rows = (
                query.order_by(FindingRow.rank, FindingRow.finding_id)
                .offset(offset)
                .limit(limit)
                .all()
            )
            return Page[FindingSummary](
                items=[_finding_summary(row) for row in rows],
                total=total,
                offset=offset,
                limit=limit,
            )

    @app.get(
        "/api/findings/{finding_id}", response_model=FindingDetail, tags=["findings"]
    )
    def get_finding(
        finding_id: str, app_state: AppState = Depends(get_state)
    ) -> FindingDetail:
        with app_state.database.session() as db_session:
            row = db_session.get(FindingRow, finding_id)
            if row is None:
                raise HTTPException(status_code=404, detail="finding not found")
            return FindingDetail(
                finding=_finding_summary(row),
                description=row.description,
                technical_impact=row.technical_impact,
                policy_version=row.policy_version,
                standards_references=_json_field(row.standards_json, []),
                remediation_ids=_json_field(row.remediation_json, []),
                limitations=_json_field(row.limitations_json, []),
                evidence=[
                    EvidenceRef.model_validate(item)
                    for item in _json_field(row.evidence_json, [])
                ],
            )

    # -- intelligence -----------------------------------------------------
    @app.get(
        "/api/investigations/{investigation_id}/intelligence", tags=["intelligence"]
    )
    def get_intelligence(
        investigation_id: str,
        section: str | None = Query(
            None,
            description=(
                "fingerprints, entities, drift, correlations, blast_radius or "
                "warnings. Omit for the whole document."
            ),
        ),
        app_state: AppState = Depends(get_state),
    ) -> dict[str, Any]:
        with app_state.database.session() as db_session:
            row = db_session.get(IntelligenceRow, investigation_id)
            if row is None:
                raise HTTPException(
                    status_code=404,
                    detail="no cryptographic intelligence for this investigation",
                )
            document: dict[str, Any] = json.loads(row.investigation_json)
        if section is None:
            return document
        mapping = {
            "fingerprints": "cryptographic_fingerprints",
            "entities": "server_entities",
            "drift": "drift_events",
            "correlations": "session_correlations",
            "blast_radius": "blast_radius",
            "warnings": "intelligence_warnings",
        }
        key = mapping.get(section)
        if key is None:
            raise HTTPException(
                status_code=422,
                detail=f"section must be one of {', '.join(sorted(mapping))}",
            )
        return {
            "investigation_id": investigation_id,
            "section": section,
            "items": document.get(key, []),
            "scope_statement": document.get("scope_statement"),
            "limitations": document.get("limitations", []),
        }

    @app.get(
        "/api/investigations/{investigation_id}/timeline",
        response_model=Page[TimelineEntry],
        tags=["intelligence"],
    )
    def get_timeline(
        investigation_id: str,
        offset: int = Query(0, ge=0),
        limit: int = Query(200, ge=1, le=2000),
        event_type: str | None = None,
        session_id: str | None = None,
        capture_id: str | None = None,
        app_state: AppState = Depends(get_state),
    ) -> Page[TimelineEntry]:
        with app_state.database.session() as db_session:
            row = db_session.get(IntelligenceRow, investigation_id)
            if row is None:
                raise HTTPException(status_code=404, detail="no timeline available")
            document = json.loads(row.investigation_json)
        events = document.get("evidence_timeline", [])
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if session_id:
            events = [e for e in events if e.get("session_id") == session_id]
        if capture_id:
            events = [e for e in events if e.get("capture_id") == capture_id]
        window = events[offset : offset + limit]
        return Page[TimelineEntry](
            items=[
                TimelineEntry(
                    event_id=e["event_id"],
                    event_type=e["event_type"],
                    timestamp=e.get("timestamp"),
                    capture_id=e["capture_id"],
                    session_id=e.get("session_id"),
                    description=e["description"],
                    evidence_status=e["evidence_status"],
                    packet_numbers=[
                        reference["packet_number"] for reference in e.get("packet_refs", [])
                    ],
                    order_index=e["order_index"],
                )
                for e in window
            ],
            total=len(events),
            offset=offset,
            limit=limit,
        )

    @app.get("/api/investigations/{investigation_id}/ml", tags=["ml"])
    def get_ml(
        investigation_id: str, app_state: AppState = Depends(get_state)
    ) -> dict[str, Any]:
        """ML results, with the evaluation record the model card refers to.

        Benchmark numbers are read from the versioned evaluation artifact, not
        written into the UI, so they cannot drift from the model that produced
        them.
        """
        with app_state.database.session() as db_session:
            row = db_session.get(MLResultRow, investigation_id)
            if row is None:
                raise HTTPException(
                    status_code=404, detail="no ML results for this investigation"
                )
            summary = _ml_summary(row)
            results = _json_field(row.results_json, [])

        evaluation: dict[str, Any] | None = None
        from ..ml.registry import MODEL_DIRECTORY

        evaluation_path = MODEL_DIRECTORY / "evaluation.json"
        if evaluation_path.is_file():
            evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        return {
            "summary": summary.model_dump() if summary else None,
            "results": results,
            "evaluation": evaluation,
        }

    # -- exports ----------------------------------------------------------
    def _export(
        app_state: AppState, investigation_id: str, report_format: str
    ) -> tuple[bytes, str, str]:
        results, investigation = _results_for(app_state, investigation_id)
        model = build_report(
            results, investigation, title="SecureMailScope forensic report"
        )
        if report_format == "json":
            payload = json.dumps(
                model.model_dump(mode="json"), indent=2, sort_keys=True, default=str
            ).encode("utf-8")
            return payload, "application/json", "json"
        if report_format == "html":
            return render_html(model).encode("utf-8"), "text/html; charset=utf-8", "html"
        return render_pdf(model), "application/pdf", "pdf"

    @app.get(
        "/api/investigations/{investigation_id}/export/{report_format}",
        tags=["reports"],
    )
    def export_report(
        investigation_id: str,
        report_format: str,
        app_state: AppState = Depends(get_state),
    ) -> Response:
        if report_format not in ("json", "html", "pdf"):
            raise HTTPException(
                status_code=422, detail="format must be json, html or pdf"
            )
        payload, media_type, suffix = _export(
            app_state, investigation_id, report_format
        )
        export_id = secrets.token_hex(8)
        path = app_state.storage.store_report(payload, export_id, suffix)
        filename = f"securemailscope-{investigation_id}.{suffix}"
        with app_state.database.session() as db_session:
            db_session.add(
                ReportExportRow(
                    export_id=export_id,
                    investigation_id=investigation_id,
                    report_format=suffix,
                    filename=filename,
                    stored_path=str(path),
                    size_bytes=len(payload),
                )
            )
        return Response(
            content=payload,
            media_type=media_type,
            headers={
                "content-disposition": f'attachment; filename="{filename}"',
                "x-securemailscope-export-id": export_id,
            },
        )

    @app.get(
        "/api/investigations/{investigation_id}/exports",
        response_model=list[ExportSummary],
        tags=["reports"],
    )
    def list_exports(
        investigation_id: str, app_state: AppState = Depends(get_state)
    ) -> list[ExportSummary]:
        with app_state.database.session() as db_session:
            rows = (
                db_session.query(ReportExportRow)
                .filter(ReportExportRow.investigation_id == investigation_id)
                .order_by(ReportExportRow.created_at.desc())
                .all()
            )
            return [ExportSummary.model_validate(row) for row in rows]

    # -- settings ---------------------------------------------------------
    @app.get("/api/settings", response_model=SettingsPayload, tags=["system"])
    def get_settings(app_state: AppState = Depends(get_state)) -> SettingsPayload:
        config = app_state.config
        return SettingsPayload(
            max_upload_bytes=app_state.max_upload_bytes,
            max_capture_bytes=config.max_capture_bytes,
            max_packets=config.max_packets,
            max_total_sessions=config.max_total_sessions,
            assess_security=config.assess_security,
            minimum_score_coverage_percent=config.minimum_score_coverage_percent,
            enable_ml=config.enable_ml,
            default_report_format=app_state.default_report_format,
            retain_captures=app_state.retain_captures,
            requires_reanalysis=[
                "max_capture_bytes",
                "max_packets",
                "max_total_sessions",
                "assess_security",
                "minimum_score_coverage_percent",
                "enable_ml",
            ],
            storage_root=str(app_state.storage.root),
            storage_usage_bytes=app_state.storage.usage_bytes(),
        )

    @app.post("/api/settings", response_model=SettingsPayload, tags=["system"])
    def update_settings(
        payload: dict[str, Any], app_state: AppState = Depends(get_state)
    ) -> SettingsPayload:
        """Update settings the backend genuinely acts on.

        Existing results are never rewritten: a changed threshold applies to
        the next analysis, which is why ``requires_reanalysis`` is reported.
        """
        from dataclasses import replace

        overrides: dict[str, Any] = {}
        for key in (
            "max_capture_bytes",
            "max_packets",
            "max_total_sessions",
            "minimum_score_coverage_percent",
        ):
            if key in payload:
                value = payload[key]
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    raise HTTPException(
                        status_code=422, detail=f"{key} must be a positive integer"
                    )
                overrides[key] = value
        for key in ("assess_security", "enable_ml"):
            if key in payload:
                if not isinstance(payload[key], bool):
                    raise HTTPException(
                        status_code=422, detail=f"{key} must be true or false"
                    )
                overrides[key] = payload[key]
        if "default_report_format" in payload:
            value = payload["default_report_format"]
            if value not in ("json", "html", "pdf"):
                raise HTTPException(
                    status_code=422,
                    detail="default_report_format must be json, html or pdf",
                )
            app_state.default_report_format = value
        if "retain_captures" in payload:
            app_state.retain_captures = bool(payload["retain_captures"])
        if "max_upload_bytes" in payload:
            value = payload["max_upload_bytes"]
            if not isinstance(value, int) or value < 1024:
                raise HTTPException(
                    status_code=422, detail="max_upload_bytes must be at least 1024"
                )
            app_state.max_upload_bytes = value
            app_state.storage.max_bytes = value

        if overrides:
            app_state.config = replace(app_state.config, **overrides)
            app_state.service.config = app_state.config
        return get_settings(app_state)

    @app.delete("/api/captures/{capture_id}", tags=["captures"])
    def delete_capture(
        capture_id: str, app_state: AppState = Depends(get_state)
    ) -> dict[str, Any]:
        """Delete a capture and its stored bytes. Explicit user action only.

        The analysis results are kept: deleting the evidence file does not
        retract what was observed, and silently discarding an investigation
        would lose work the user did not ask to lose.
        """
        with app_state.database.session() as db_session:
            row = db_session.get(CaptureRow, capture_id)
            if row is None:
                raise HTTPException(status_code=404, detail="capture not found")
            storage_id = row.storage_id
            row.status = "DELETED"
            row.stored_path = ""
        removed = app_state.storage.delete_capture(storage_id)
        return {
            "capture_id": capture_id,
            "file_removed": removed,
            "detail": (
                "The stored capture file was removed. Analysis results and "
                "findings are retained; deleting evidence does not retract what "
                "was already observed."
            ),
        }

    return app


def _naive(value: datetime | None) -> datetime | None:  # pragma: no cover - helper
    return value.replace(tzinfo=None) if value else None
