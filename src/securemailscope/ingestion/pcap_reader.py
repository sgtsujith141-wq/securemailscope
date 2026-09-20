"""Streaming libpcap (``.pcap``) container reader.

Implements the classic libpcap file format directly rather than delegating to
a library, for three reasons documented in
``docs/adr/0002-custom-container-reader.md``: we need byte-exact control over
resource limits, we must distinguish "damaged container" from "undissectable
packet", and truncation has to become a diagnostic instead of an exception.

File layout::

    struct pcap_file_header { u32 magic; u16 major; u16 minor;
                              i32 thiszone; u32 sigfigs;
                              u32 snaplen;  u32 network; }      # 24 bytes
    struct pcap_pkthdr      { u32 ts_sec; u32 ts_frac;
                              u32 incl_len; u32 orig_len; }     # 16 bytes
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import BinaryIO, Final

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.capture import CaptureFormat, InterfaceInfo, LinkType
from ..models.evidence import Severity, WarningCode
from .formats import PCAP_MAGICS
from .frames import RawFrame
from .linktypes import resolve_link_type

__all__ = ["PcapReader"]

FILE_HEADER_SIZE: Final = 24
PACKET_HEADER_SIZE: Final = 16


class PcapReader:
    """Iterate packet records from an open binary stream positioned at byte 0."""

    def __init__(
        self,
        stream: BinaryIO,
        *,
        config: AnalysisConfig,
        sink: WarningSink,
    ) -> None:
        self._stream = stream
        self._config = config
        self._sink = sink
        self.format: CaptureFormat = CaptureFormat.UNKNOWN
        self.byte_order: str | None = None
        self.interfaces: list[InterfaceInfo] = []
        self.truncated = False
        self._link_type_code = -1
        self._link_type = LinkType.UNSUPPORTED
        self._tick_ns = 1000
        self._endian = "<"

    # -- header ------------------------------------------------------------
    def read_header(self) -> None:
        raw = self._stream.read(FILE_HEADER_SIZE)
        if len(raw) < FILE_HEADER_SIZE:
            raise ValueError(
                f"pcap file header truncated: {len(raw)} of {FILE_HEADER_SIZE} bytes"
            )
        magic = raw[:4]
        if magic not in PCAP_MAGICS:
            raise ValueError(f"unrecognised pcap magic {magic.hex()}")
        self.format, self.byte_order = PCAP_MAGICS[magic]
        self._endian = "<" if self.byte_order == "little" else ">"
        self._tick_ns = 1 if self.format is CaptureFormat.PCAP_NS else 1000

        _major, _minor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
            self._endian + "HHiIII", raw[4:]
        )
        self._link_type_code = int(network)
        self._link_type = resolve_link_type(self._link_type_code)
        if self._link_type is LinkType.UNSUPPORTED:
            self._sink.add(
                WarningCode.UNSUPPORTED_LINK_TYPE,
                f"Capture link type {self._link_type_code} is not supported; "
                "its packets cannot be dissected and are skipped.",
                severity=Severity.ERROR,
                link_type_code=self._link_type_code,
            )
        self.interfaces.append(
            InterfaceInfo(
                interface_id=0,
                link_type_code=self._link_type_code,
                link_type=self._link_type,
                snap_length=int(snaplen) or None,
                timestamp_resolution_ns=self._tick_ns,
            )
        )

    # -- packets -----------------------------------------------------------
    def frames(self) -> Iterator[RawFrame]:
        """Yield frames until EOF, a damaged record, or a configured limit."""
        packet_number = 0
        while True:
            header = self._stream.read(PACKET_HEADER_SIZE)
            if not header:
                return
            if len(header) < PACKET_HEADER_SIZE:
                self.truncated = True
                self._sink.add(
                    WarningCode.TRUNCATED_CAPTURE_FILE,
                    f"Capture ends with a partial packet header after packet {packet_number} "
                    f"({len(header)} of {PACKET_HEADER_SIZE} bytes).",
                    severity=Severity.ERROR,
                    bytes_available=len(header),
                )
                return

            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(self._endian + "IIII", header)

            if incl_len > self._config.max_packet_bytes:
                self.truncated = True
                self._sink.add(
                    WarningCode.LIMIT_PACKET_BYTES,
                    f"Packet {packet_number + 1} declares {incl_len} captured bytes, above the "
                    f"{self._config.max_packet_bytes}-byte limit; parsing stopped.",
                    severity=Severity.ERROR,
                    declared_length=int(incl_len),
                    limit=self._config.max_packet_bytes,
                )
                return

            data = self._stream.read(incl_len)
            if len(data) < incl_len:
                self.truncated = True
                self._sink.add(
                    WarningCode.TRUNCATED_CAPTURE_FILE,
                    f"Packet {packet_number + 1} declares {incl_len} bytes but only "
                    f"{len(data)} remain in the file; parsing stopped.",
                    severity=Severity.ERROR,
                    declared_length=int(incl_len),
                    bytes_available=len(data),
                )
                return

            packet_number += 1
            timestamp_ns = int(ts_sec) * 1_000_000_000 + int(ts_frac) * self._tick_ns
            yield RawFrame(
                packet_number=packet_number,
                timestamp_ns=timestamp_ns,
                data=data,
                original_length=int(orig_len) if orig_len >= incl_len else incl_len,
                link_type_code=self._link_type_code,
                link_type=self._link_type,
                interface_id=0,
            )
