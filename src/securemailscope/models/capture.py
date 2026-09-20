"""Capture-file level metadata."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import AnalysisWarning

__all__ = ["CaptureFormat", "LinkType", "InterfaceInfo", "CaptureMetadata"]


class CaptureFormat(StrEnum):
    PCAP = "PCAP"
    PCAP_NS = "PCAP_NS"  # libpcap with nanosecond timestamps (magic 0xa1b23c4d)
    PCAPNG = "PCAPNG"
    UNKNOWN = "UNKNOWN"


class LinkType(StrEnum):
    """Link types SecureMailScope can dissect.

    Anything not listed here produces an ``UNSUPPORTED_LINK_TYPE`` diagnostic
    and its packets are skipped rather than guessed at.
    """

    ETHERNET = "ETHERNET"  # DLT 1
    RAW_IP = "RAW_IP"  # DLT 101 / 228 / 229
    NULL = "NULL"  # DLT 0 (BSD loopback)
    LOOP = "LOOP"  # DLT 108 (OpenBSD loopback)
    LINUX_SLL = "LINUX_SLL"  # DLT 113
    LINUX_SLL2 = "LINUX_SLL2"  # DLT 276
    UNSUPPORTED = "UNSUPPORTED"


class InterfaceInfo(BaseModel):
    """One capture interface (a pcapng IDB, or the single implicit pcap iface)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    interface_id: int
    link_type_code: int
    link_type: LinkType
    snap_length: int | None = None
    name: str | None = None
    timestamp_resolution_ns: int = Field(
        default=1000,
        description="Nanoseconds per timestamp tick as declared by the capture file.",
    )


class CaptureMetadata(BaseModel):
    """Everything known about the capture container itself.

    ``capture_id`` is the SHA-256 of the *original file bytes*, so two analyses
    of the same file always agree and a report can be tied back to the exact
    artefact it came from.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capture_id: str = Field(description="'sha256:<hex>' over the original capture bytes.")
    source_name: str = Field(description="Base file name only; no directory component.")
    file_format: CaptureFormat
    byte_order: str | None = Field(default=None, description="'little' or 'big' for pcap files.")
    file_size_bytes: int = Field(ge=0)
    interfaces: tuple[InterfaceInfo, ...] = ()

    packet_count: int = Field(default=0, ge=0, description="Packet records read from the file.")
    tcp_packet_count: int = Field(default=0, ge=0)
    non_ip_packet_count: int = Field(default=0, ge=0)
    non_tcp_packet_count: int = Field(default=0, ge=0)
    unsupported_link_packet_count: int = Field(default=0, ge=0)
    malformed_packet_count: int = Field(default=0, ge=0)

    first_packet_timestamp: datetime | None = None
    last_packet_timestamp: datetime | None = None
    first_packet_timestamp_ns: int | None = None
    last_packet_timestamp_ns: int | None = None

    truncated: bool = Field(
        default=False,
        description="True if parsing stopped early (malformed tail or a resource limit).",
    )
    warnings: tuple[AnalysisWarning, ...] = ()

    @property
    def duration_seconds(self) -> float | None:
        if self.first_packet_timestamp_ns is None or self.last_packet_timestamp_ns is None:
            return None
        return (self.last_packet_timestamp_ns - self.first_packet_timestamp_ns) / 1e9
