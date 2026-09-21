"""Top-level analysis result contract (the shape of `securemailscope analyze` output)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .capture import CaptureMetadata
from .evidence import AnalysisWarning
from .protocol import ProtocolInventory, ProtocolSessionAnalysis
from .tcp import TCPSession
from .tls import TLSInventory, TLSSessionAnalysis

__all__ = [
    "AnalysisStage",
    "ToolInfo",
    "AnalysisLimits",
    "SessionInventory",
    "AnalysisResult",
    "REPORT_SCHEMA_VERSION",
    "STAGE_STATUS",
]

#: Bumped whenever the JSON output contract changes.
#:
#: 1.1.0 (M2) adds the top-level ``protocols`` array and ``protocol_inventory``
#: object, and adds members to ``stage_status``.
#:
#: 1.2.0 (M3) adds the top-level ``tls`` array and ``tls_inventory`` object,
#: adds optional M3 fields to ``TLSRecordObservation``, and adds further
#: ``stage_status`` members. Still backward compatible: every 1.0.0 and 1.1.0
#: field keeps its name, type and meaning, and the M1 TCP and M2 protocol
#: models are unchanged. An older consumer can ignore the new keys.
REPORT_SCHEMA_VERSION = "1.2.0"


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
    STARTTLS_DETECTION = "STARTTLS_DETECTION"
    TLS_RECORD_FRAMING = "TLS_RECORD_FRAMING"
    TLS_HANDSHAKE_ANALYSIS = "TLS_HANDSHAKE_ANALYSIS"
    TLS_ANALYSIS = "TLS_ANALYSIS"
    KEY_EXCHANGE_ANALYSIS = "KEY_EXCHANGE_ANALYSIS"
    FORWARD_SECRECY_ASSESSMENT = "FORWARD_SECRECY_ASSESSMENT"
    CERTIFICATE_EXTRACTION = "CERTIFICATE_EXTRACTION"
    CERTIFICATE_VALIDATION = "CERTIFICATE_VALIDATION"
    CERTIFICATE_REVOCATION = "CERTIFICATE_REVOCATION"
    CERTIFICATE_ASSESSMENT = "CERTIFICATE_ASSESSMENT"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    ML_ANALYSIS = "ML_ANALYSIS"


#: Implementation status of each stage as of this build.
STAGE_STATUS: dict[AnalysisStage, str] = {
    AnalysisStage.CAPTURE_INGESTION: "IMPLEMENTED",
    AnalysisStage.TCP_REASSEMBLY: "IMPLEMENTED",
    AnalysisStage.PROTOCOL_HINTS: "IMPLEMENTED",
    AnalysisStage.EMAIL_PROTOCOL_PARSING: "IMPLEMENTED",
    AnalysisStage.STARTTLS_DETECTION: "IMPLEMENTED",
    AnalysisStage.TLS_RECORD_FRAMING: "IMPLEMENTED",
    AnalysisStage.TLS_HANDSHAKE_ANALYSIS: "IMPLEMENTED",
    # Implemented for the observable plaintext portion of a handshake. Nothing
    # is decrypted, so TLS 1.3 traffic after the ServerHello stays opaque.
    AnalysisStage.TLS_ANALYSIS: "PARTIAL",
    AnalysisStage.KEY_EXCHANGE_ANALYSIS: "IMPLEMENTED",
    AnalysisStage.FORWARD_SECRECY_ASSESSMENT: "IMPLEMENTED",
    # TLS 1.2 and earlier only; TLS 1.3 certificates are encrypted.
    AnalysisStage.CERTIFICATE_EXTRACTION: "PARTIAL",
    # Dates, chain and hostname are implemented and independently reported.
    AnalysisStage.CERTIFICATE_VALIDATION: "IMPLEMENTED",
    # No OCSP or CRL retrieval exists; the engine makes no network requests.
    AnalysisStage.CERTIFICATE_REVOCATION: "NOT_IMPLEMENTED",
    # Turning certificate observations into a posture judgement is M4.
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

    protocol_inventory: ProtocolInventory = Field(
        default_factory=ProtocolInventory,
        description="Capture-wide totals for the application protocol layer (M2).",
    )
    protocols: tuple[ProtocolSessionAnalysis, ...] = Field(
        default=(),
        description=(
            "Application-layer analysis, one entry per session, joined to "
            "'sessions' by session_id. Kept separate so the M1 TCP contract is "
            "unchanged."
        ),
    )

    tls_inventory: TLSInventory = Field(
        default_factory=TLSInventory,
        description="Capture-wide totals for the TLS and certificate layer (M3).",
    )
    tls: tuple[TLSSessionAnalysis, ...] = Field(
        default=(),
        description=(
            "TLS analysis, one entry per session that carried TLS, joined to "
            "'sessions' and 'protocols' by session_id."
        ),
    )

    warnings: tuple[AnalysisWarning, ...] = Field(
        default=(), description="Warnings not attributable to a single session."
    )
