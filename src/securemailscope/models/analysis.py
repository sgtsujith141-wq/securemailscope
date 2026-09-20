"""Top-level analysis result contract (the shape of `securemailscope analyze` output)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .capture import CaptureMetadata
from .evidence import AnalysisWarning
from .tcp import TCPSession

__all__ = ["AnalysisStage", "ToolInfo", "AnalysisLimits", "SessionInventory", "AnalysisResult"]

#: Bumped whenever the JSON output contract changes incompatibly.
REPORT_SCHEMA_VERSION = "1.0.0"


class AnalysisStage(StrEnum):
    """Pipeline stages, with the honest implementation state of each.

    This enum is reflected verbatim into every report so a reader never has to
    guess whether an absent TLS section means "no TLS in the capture" or "not
    built yet".
    """

    CAPTURE_INGESTION = "CAPTURE_INGESTION"
    TCP_REASSEMBLY = "TCP_REASSEMBLY"
    PROTOCOL_HINTS = "PROTOCOL_HINTS"
    EMAIL_PROTOCOL_PARSING = "EMAIL_PROTOCOL_PARSING"
    TLS_ANALYSIS = "TLS_ANALYSIS"
    CERTIFICATE_ASSESSMENT = "CERTIFICATE_ASSESSMENT"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    ML_ANALYSIS = "ML_ANALYSIS"


#: Implementation status of each stage as of this build.
STAGE_STATUS: dict[AnalysisStage, str] = {
    AnalysisStage.CAPTURE_INGESTION: "IMPLEMENTED",
    AnalysisStage.TCP_REASSEMBLY: "IMPLEMENTED",
    AnalysisStage.PROTOCOL_HINTS: "PARTIAL",
    AnalysisStage.EMAIL_PROTOCOL_PARSING: "NOT_IMPLEMENTED",
    AnalysisStage.TLS_ANALYSIS: "NOT_IMPLEMENTED",
    AnalysisStage.CERTIFICATE_ASSESSMENT: "NOT_IMPLEMENTED",
    AnalysisStage.RISK_ASSESSMENT: "NOT_IMPLEMENTED",
    AnalysisStage.ML_ANALYSIS: "NOT_IMPLEMENTED",
}


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolInfo(_Frozen):
    name: str = "securemailscope"
    version: str
    report_schema_version: str = REPORT_SCHEMA_VERSION
    analysis_started_at: datetime
    analysis_completed_at: datetime
    passive_only: bool = Field(
        default=True,
        description="Constant: the engine never contacts captured hosts or any network service.",
    )

    @staticmethod
    def now() -> datetime:
        return datetime.now(tz=UTC)


class AnalysisLimits(_Frozen):
    """The limit configuration actually in force for this run.

    Echoed into the report because a truncated result is only interpretable if
    the reader knows which ceiling was hit.
    """

    max_capture_bytes: int
    max_packets: int
    max_packet_bytes: int
    max_total_payload_bytes: int
    max_session_payload_bytes: int
    max_concurrent_sessions: int
    max_total_sessions: int
    max_segments_per_direction: int


class SessionInventory(_Frozen):
    session_count: int = Field(ge=0)
    complete_session_count: int = Field(ge=0)
    midstream_session_count: int = Field(ge=0)
    partial_session_count: int = Field(ge=0)
    truncated_session_count: int = Field(ge=0)
    total_bytes_reconstructed: int = Field(ge=0)
    total_gap_count: int = Field(ge=0)
    total_overlap_conflict_count: int = Field(ge=0)
    tuple_reuse_count: int = Field(
        ge=0, description="Connections that reused an already-seen 5-tuple."
    )


class AnalysisResult(_Frozen):
    """The complete, self-describing result of analysing one capture file."""

    tool: ToolInfo
    stage_status: dict[str, str] = Field(
        default_factory=lambda: {k.value: v for k, v in STAGE_STATUS.items()}
    )
    limits: AnalysisLimits
    capture: CaptureMetadata
    inventory: SessionInventory
    sessions: tuple[TCPSession, ...] = ()
    warnings: tuple[AnalysisWarning, ...] = Field(
        default=(), description="Warnings not attributable to a single session."
    )
