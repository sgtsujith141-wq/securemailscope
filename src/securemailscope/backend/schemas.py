"""Typed API response contracts (M7).

Separate from the engine's models on purpose. The engine's contracts describe
*evidence*; these describe what a page needs. Serving the engine models
directly would tie every UI change to the forensic schema and would push whole
analysis documents down the wire for a table that needs eight columns.

Every list response is paginated, and every one reports its own total, so a UI
never has to guess whether it has everything.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Page",
    "HealthResponse",
    "CaptureSummary",
    "InvestigationSummary",
    "InvestigationDetail",
    "JobStatus",
    "SessionSummary",
    "SessionDetail",
    "FindingSummary",
    "FindingDetail",
    "EvidenceRef",
    "TimelineEntry",
    "MLSummary",
    "ExportSummary",
    "SettingsPayload",
    "ErrorResponse",
]

T = TypeVar("T")


class _Model(BaseModel):
    model_config = ConfigDict(from_attributes=True, protected_namespaces=())


class Page(_Model, Generic[T]):
    """A page of results, always with the true total beside it."""

    items: list[T]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1)

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class ErrorResponse(_Model):
    """A problem, described without leaking internals.

    ``detail`` is written for a user. Stack traces, absolute paths and database
    errors never appear here.
    """

    error: str
    detail: str
    status_code: int


class HealthResponse(_Model):
    status: str
    tool_name: str
    tool_version: str
    report_schema_version: str
    database_schema_version: int
    ml_available: bool
    ml_status: str
    #: True when the analyzer works but no model artifact is installed.
    analyzer_works_without_ml: bool = True


class CaptureSummary(_Model):
    capture_id: str
    original_name: str
    file_size_bytes: int
    file_format: str | None = None
    packet_count: int
    session_count: int
    status: str
    failure_reason: str | None = None
    uploaded_at: datetime
    first_packet_timestamp: datetime | None = None
    last_packet_timestamp: datetime | None = None


class InvestigationSummary(_Model):
    investigation_id: str
    name: str
    status: str
    created_at: datetime
    updated_at: datetime
    capture_count: int
    analysed_capture_count: int
    failed_capture_count: int
    session_count: int
    finding_count: int
    #: ``None`` means no score, which is not the same as zero.
    posture_score: int | None = None
    score_status: str | None = None
    score_band: str | None = None
    #: What the headline score describes. For an investigation of several
    #: captures this names the weakest one and the range it sits in.
    score_scope: str | None = None
    coverage_ratio: float | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    protocol_counts: dict[str, int] = Field(default_factory=dict)


class JobStatus(_Model):
    job_id: str
    investigation_id: str
    status: str
    stage: str | None = None
    captures_total: int
    captures_done: int
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @property
    def progress_is_measurable(self) -> bool:
        """Whether a determinate progress bar is honest for this job.

        Per-capture progress is real. Within one capture the analyzer reports a
        stage but no fraction, so a UI must show an indeterminate indicator
        rather than inventing one.
        """
        return self.captures_total > 0


class InvestigationDetail(_Model):
    investigation: InvestigationSummary
    captures: list[CaptureSummary]
    jobs: list[JobStatus]
    policy_id: str | None = None
    policy_version: str | None = None
    policy_fingerprint: str | None = None
    fingerprint_count: int = 0
    entity_count: int = 0
    drift_count: int = 0
    correlation_count: int = 0
    timeline_event_count: int = 0
    ml: MLSummary | None = None
    warnings: list[str] = Field(default_factory=list)
    scope_statement: str = "Observed within analyzed captures only."


class SessionSummary(_Model):
    session_id: str
    investigation_id: str
    capture_id: str
    client: str
    server: str
    protocol: str | None = None
    detection_status: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    key_exchange: str | None = None
    certificate_visibility: str | None = None
    completeness: str | None = None
    packet_count: int
    finding_count: int
    posture_score: int | None = None
    score_status: str | None = None
    coverage_ratio: float | None = None


class SessionDetail(_Model):
    session: SessionSummary
    findings: list[FindingSummary] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class EvidenceRef(_Model):
    capture_id: str
    session_id: str | None = None
    packet_number: int
    timestamp: datetime | None = None
    stream_offset: int | None = None
    source_observation: str
    evidence_status: str


class FindingSummary(_Model):
    finding_id: str
    investigation_id: str
    capture_id: str
    session_id: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    evaluation_status: str
    priority: str | None = None
    rank: int | None = None


class FindingDetail(_Model):
    finding: FindingSummary
    description: str
    technical_impact: str
    policy_version: str | None = None
    standards_references: list[str] = Field(default_factory=list)
    remediation_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence: list[EvidenceRef] = Field(default_factory=list)


class TimelineEntry(_Model):
    event_id: str
    event_type: str
    timestamp: datetime | None = None
    capture_id: str
    session_id: str | None = None
    description: str
    evidence_status: str
    packet_numbers: list[int] = Field(default_factory=list)
    order_index: int


class MLSummary(_Model):
    """ML status, with M6's distinctions intact.

    ``anomaly_algorithm`` is reported as-is. M6 selected a deterministic rarity
    baseline over Isolation Forest, and a UI that labelled it "machine
    learning" would be misrepresenting that result, so the field carries the
    algorithm name and ``anomaly_detector_is_ml`` states plainly whether it is
    a model at all.
    """

    ml_status: str
    feature_schema_version: str | None = None
    anomaly_algorithm: str | None = None
    anomaly_detector_is_ml: bool = False
    anomaly_model_id: str | None = None
    anomaly_model_version: str | None = None
    classifier_model_id: str | None = None
    classification_validation_status: str = "NOT_VALIDATED"
    anomalous_session_count: int = 0
    not_evaluable_session_count: int = 0
    evaluation_available: bool = False


class ExportSummary(_Model):
    export_id: str
    investigation_id: str
    report_format: str
    filename: str
    size_bytes: int
    created_at: datetime


class SettingsPayload(_Model):
    """Settings the backend genuinely acts on. Nothing decorative."""

    max_upload_bytes: int = Field(ge=1024)
    max_capture_bytes: int = Field(ge=1024)
    max_packets: int = Field(ge=1)
    max_total_sessions: int = Field(ge=1)
    assess_security: bool
    minimum_score_coverage_percent: int = Field(ge=0, le=100)
    enable_ml: bool
    default_report_format: str
    retain_captures: bool
    #: Changing any of these only affects future analyses; existing results
    #: are never silently rewritten.
    requires_reanalysis: list[str] = Field(default_factory=list)
    storage_root: str
    storage_usage_bytes: int = 0
