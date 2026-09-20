"""Typed data contracts for SecureMailScope.

Everything that crosses a module boundary or reaches a report is a model
defined here.  Nested free-form dictionaries are deliberately avoided so that
provenance fields cannot quietly be dropped.
"""

from .analysis import (
    REPORT_SCHEMA_VERSION,
    STAGE_STATUS,
    AnalysisLimits,
    AnalysisResult,
    AnalysisStage,
    SessionInventory,
    ToolInfo,
)
from .capture import CaptureFormat, CaptureMetadata, InterfaceInfo, LinkType
from .evidence import (
    AnalysisWarning,
    EvidenceStatus,
    Observation,
    PacketReference,
    Severity,
    WarningCode,
    ns_to_datetime,
)
from .tcp import (
    AddressFamily,
    ByteRun,
    Direction,
    DirectionalStream,
    Endpoint,
    GapReason,
    HandshakeInfo,
    OverlapConflict,
    ReassembledSegment,
    ReassemblyGap,
    SegmentDisposition,
    SessionCompleteness,
    TCPFlow,
    TCPSession,
    TerminationInfo,
    TerminationReason,
)

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "STAGE_STATUS",
    "AddressFamily",
    "AnalysisLimits",
    "AnalysisResult",
    "AnalysisStage",
    "AnalysisWarning",
    "ByteRun",
    "CaptureFormat",
    "CaptureMetadata",
    "Direction",
    "DirectionalStream",
    "Endpoint",
    "EvidenceStatus",
    "GapReason",
    "HandshakeInfo",
    "InterfaceInfo",
    "LinkType",
    "Observation",
    "OverlapConflict",
    "PacketReference",
    "ReassembledSegment",
    "ReassemblyGap",
    "SegmentDisposition",
    "SessionCompleteness",
    "SessionInventory",
    "Severity",
    "TCPFlow",
    "TCPSession",
    "TerminationInfo",
    "TerminationReason",
    "ToolInfo",
    "WarningCode",
    "ns_to_datetime",
]
