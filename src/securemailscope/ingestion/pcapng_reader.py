"""Streaming pcapng container reader.

Supports the block types needed for offline TCP analysis:

===== ================================ ===========================
Type  Block                            Handling
===== ================================ ===========================
0x0A0D0D0A Section Header Block         Sets endianness; resets interface table
0x00000001 Interface Description Block  Records link type and ``if_tsresol``
0x00000006 Enhanced Packet Block        Yields a frame
0x00000003 Simple Packet Block          Yields a frame (no timestamp available)
other      any                          Skipped with an ``UNSUPPORTED_BLOCK_TYPE`` note
===== ================================ ===========================

Per-interface timestamp resolution is honoured, so nanosecond captures keep
their precision.  Multiple sections in one file are supported; each section
restarts interface numbering as the specification requires.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import BinaryIO, Final

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.capture import InterfaceInfo, LinkType
from ..models.evidence import Severity, WarningCode
from .frames import RawFrame
from .linktypes import resolve_link_type

__all__ = ["PcapngReader"]

BT_SHB: Final = 0x0A0D0D0A
BT_IDB: Final = 0x00000001
BT_SPB: Final = 0x00000003
BT_EPB: Final = 0x00000006

_BOM_LE: Final = 0x1A2B3C4D
#: Largest block we are willing to buffer, independent of the packet limit:
#: a corrupt length field must not cause a multi-gigabyte allocation.
_MAX_BLOCK_BYTES: Final = 64 * 1024 * 1024
_OPT_ENDOFOPT: Final = 0
_OPT_IF_NAME: Final = 2
_OPT_IF_TSRESOL: Final = 9


class PcapngReader:
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
        self.byte_order: str | None = None
        self.interfaces: list[InterfaceInfo] = []
        self.truncated = False
        self._endian = "<"
        # Interface table for the *current* section, keyed by in-section index.
        self._section_ifaces: list[InterfaceInfo] = []
        self._global_index: dict[int, int] = {}

    def read_header(self) -> None:
        """Validate that the stream begins with a Section Header Block."""
        head = self._stream.read(12)
        if len(head) < 12:
            raise ValueError("pcapng file is shorter than a Section Header Block")
        if struct.unpack("<I", head[:4])[0] != BT_SHB:
            raise ValueError(f"pcapng file does not start with an SHB: {head[:4].hex()}")
        bom_le = struct.unpack("<I", head[8:12])[0]
        if bom_le == _BOM_LE:
            self._endian, self.byte_order = "<", "little"
        elif struct.unpack(">I", head[8:12])[0] == _BOM_LE:
            self._endian, self.byte_order = ">", "big"
        else:
            raise ValueError(f"pcapng byte-order magic is invalid: {head[8:12].hex()}")
        self._stream.seek(0)

    # -- block plumbing ----------------------------------------------------
    def _read_block(self) -> tuple[int, bytes] | None:
        """Read one block. Returns ``(type, body)`` or ``None`` at clean EOF."""
        header = self._stream.read(8)
        if not header:
            return None
        if len(header) < 8:
            self.truncated = True
            self._sink.add(
                WarningCode.TRUNCATED_CAPTURE_FILE,
                f"File ends with {len(header)} bytes of a block header; parsing stopped.",
                severity=Severity.ERROR,
                bytes_available=len(header),
            )
            return None

        block_type = struct.unpack(self._endian + "I", header[:4])[0]
        if block_type == BT_SHB:
            # A new section may switch endianness, so decode its length after
            # inspecting the byte-order magic.
            rest = self._stream.read(4)
            if len(rest) < 4:
                self.truncated = True
                self._sink.add(
                    WarningCode.TRUNCATED_CAPTURE_FILE,
                    "Section Header Block truncated before its byte-order magic.",
                    severity=Severity.ERROR,
                )
                return None
            if struct.unpack("<I", rest)[0] == _BOM_LE:
                self._endian, self.byte_order = "<", "little"
            elif struct.unpack(">I", rest)[0] == _BOM_LE:
                self._endian, self.byte_order = ">", "big"
            else:
                self.truncated = True
                self._sink.add(
                    WarningCode.MALFORMED_BLOCK,
                    f"Section Header Block has an invalid byte-order magic {rest.hex()}.",
                    severity=Severity.ERROR,
                )
                return None
            total_length = struct.unpack(self._endian + "I", header[4:8])[0]
            body_prefix = rest
        else:
            total_length = struct.unpack(self._endian + "I", header[4:8])[0]
            body_prefix = b""

        if total_length < 12 or total_length % 4 != 0:
            self.truncated = True
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                f"Block type 0x{block_type:08x} declares an invalid length {total_length}; "
                "parsing stopped.",
                severity=Severity.ERROR,
                block_type=int(block_type),
                declared_length=int(total_length),
            )
            return None
        if total_length > _MAX_BLOCK_BYTES:
            self.truncated = True
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                f"Block type 0x{block_type:08x} declares {total_length} bytes, above the "
                f"{_MAX_BLOCK_BYTES}-byte ceiling; parsing stopped.",
                severity=Severity.ERROR,
                block_type=int(block_type),
                declared_length=int(total_length),
            )
            return None

        remaining = total_length - 8 - len(body_prefix)
        body = body_prefix + self._stream.read(remaining)
        if len(body) < total_length - 8:
            self.truncated = True
            self._sink.add(
                WarningCode.TRUNCATED_CAPTURE_FILE,
                f"Block type 0x{block_type:08x} declares {total_length} bytes but the file ends "
                "early; parsing stopped.",
                severity=Severity.ERROR,
                block_type=int(block_type),
                declared_length=int(total_length),
            )
            return None

        # Trailing total-length copy must match the leading one.
        trailing = struct.unpack(self._endian + "I", body[-4:])[0]
        if trailing != total_length:
            self.truncated = True
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                f"Block type 0x{block_type:08x} has mismatched length fields "
                f"({total_length} vs {trailing}); parsing stopped.",
                severity=Severity.ERROR,
                block_type=int(block_type),
            )
            return None
        return block_type, body[:-4]

    def _parse_options(self, blob: bytes) -> dict[int, bytes]:
        options: dict[int, bytes] = {}
        offset = 0
        while offset + 4 <= len(blob):
            code, length = struct.unpack(self._endian + "HH", blob[offset : offset + 4])
            offset += 4
            if code == _OPT_ENDOFOPT:
                break
            if offset + length > len(blob):
                break
            options[code] = blob[offset : offset + length]
            offset += length + ((4 - length % 4) % 4)
        return options

    @staticmethod
    def _tsresol_to_ns(raw: bytes) -> int:
        """Decode ``if_tsresol`` into nanoseconds per timestamp tick."""
        if not raw:
            return 1000
        value = raw[0]
        if value & 0x80:
            exponent = value & 0x7F
            if exponent > 63:
                return 1000
            ticks_per_second = 2**exponent
        else:
            if value > 18:
                return 1000
            ticks_per_second = 10**value
        return max(1, 1_000_000_000 // ticks_per_second)

    def _add_interface(self, body: bytes) -> None:
        if len(body) < 8:
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                "Interface Description Block is too short to decode.",
                severity=Severity.ERROR,
            )
            return
        link_type_code, _reserved, snaplen = struct.unpack(self._endian + "HHI", body[:8])
        options = self._parse_options(body[8:])
        link_type = resolve_link_type(int(link_type_code))
        if link_type is LinkType.UNSUPPORTED:
            self._sink.add(
                WarningCode.UNSUPPORTED_LINK_TYPE,
                f"Interface {len(self._section_ifaces)} uses link type {link_type_code}, "
                "which is not supported; its packets are skipped.",
                severity=Severity.ERROR,
                link_type_code=int(link_type_code),
            )
        name_bytes = options.get(_OPT_IF_NAME)
        info = InterfaceInfo(
            interface_id=len(self.interfaces),
            link_type_code=int(link_type_code),
            link_type=link_type,
            snap_length=int(snaplen) or None,
            name=name_bytes.decode("utf-8", errors="replace") if name_bytes else None,
            timestamp_resolution_ns=self._tsresol_to_ns(options.get(_OPT_IF_TSRESOL, b"")),
        )
        self._global_index[len(self._section_ifaces)] = len(self.interfaces)
        self._section_ifaces.append(info)
        self.interfaces.append(info)

    # -- iteration ---------------------------------------------------------
    def frames(self) -> Iterator[RawFrame]:
        packet_number = 0
        while True:
            block = self._read_block()
            if block is None:
                return
            block_type, body = block

            if block_type == BT_SHB:
                self._section_ifaces = []
                self._global_index = {}
                continue
            if block_type == BT_IDB:
                self._add_interface(body)
                continue
            if block_type == BT_EPB:
                frame = self._parse_epb(body, packet_number + 1)
            elif block_type == BT_SPB:
                frame = self._parse_spb(body, packet_number + 1)
            else:
                self._sink.add(
                    WarningCode.UNSUPPORTED_BLOCK_TYPE,
                    f"Skipped pcapng block type 0x{block_type:08x}.",
                    severity=Severity.INFO,
                    block_type=int(block_type),
                )
                continue

            if frame is None:
                continue
            packet_number += 1
            yield frame

    def _interface(self, section_index: int) -> InterfaceInfo | None:
        if 0 <= section_index < len(self._section_ifaces):
            return self._section_ifaces[section_index]
        return None

    def _parse_epb(self, body: bytes, packet_number: int) -> RawFrame | None:
        if len(body) < 20:
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                "Enhanced Packet Block is too short to decode; skipped.",
                severity=Severity.ERROR,
            )
            return None
        iface_index, ts_high, ts_low, captured_len, original_len = struct.unpack(
            self._endian + "IIIII", body[:20]
        )
        iface = self._interface(int(iface_index))
        if iface is None:
            self._sink.add(
                WarningCode.MISSING_INTERFACE_DESCRIPTION,
                f"Packet references interface {iface_index}, which this section never "
                "described; packet skipped.",
                severity=Severity.ERROR,
                interface_id=int(iface_index),
            )
            return None
        if iface.link_type is LinkType.UNSUPPORTED:
            # Still counted, but the dissector will refuse it. Produce the
            # frame so the packet appears in the inventory with a diagnostic.
            pass
        if captured_len > self._config.max_packet_bytes:
            self._sink.add(
                WarningCode.LIMIT_PACKET_BYTES,
                f"Packet {packet_number} declares {captured_len} captured bytes, above the "
                f"{self._config.max_packet_bytes}-byte limit; packet skipped.",
                severity=Severity.ERROR,
                declared_length=int(captured_len),
                limit=self._config.max_packet_bytes,
            )
            return None
        if 20 + captured_len > len(body):
            self._sink.add(
                WarningCode.MALFORMED_BLOCK,
                f"Enhanced Packet Block declares {captured_len} packet bytes but the block "
                f"holds only {len(body) - 20}; packet skipped.",
                severity=Severity.ERROR,
                declared_length=int(captured_len),
            )
            return None
        ticks = (int(ts_high) << 32) | int(ts_low)
        return RawFrame(
            packet_number=packet_number,
            timestamp_ns=ticks * iface.timestamp_resolution_ns,
            data=body[20 : 20 + captured_len],
            original_length=int(original_len) if original_len >= captured_len else captured_len,
            link_type_code=iface.link_type_code,
            link_type=iface.link_type,
            interface_id=iface.interface_id,
        )

    def _parse_spb(self, body: bytes, packet_number: int) -> RawFrame | None:
        """Simple Packet Blocks carry no timestamp and no interface id.

        They are accepted (interface 0 is assumed, as the format requires) but
        the missing timestamp is recorded rather than invented.
        """
        if len(body) < 4:
            return None
        iface = self._interface(0)
        if iface is None:
            self._sink.add(
                WarningCode.MISSING_INTERFACE_DESCRIPTION,
                "Simple Packet Block seen before any Interface Description Block; skipped.",
                severity=Severity.ERROR,
            )
            return None
        original_len = struct.unpack(self._endian + "I", body[:4])[0]
        data = body[4:]
        if len(data) > self._config.max_packet_bytes:
            self._sink.add(
                WarningCode.LIMIT_PACKET_BYTES,
                f"Packet {packet_number} exceeds the {self._config.max_packet_bytes}-byte "
                "limit; packet skipped.",
                severity=Severity.ERROR,
                limit=self._config.max_packet_bytes,
            )
            return None
        self._sink.add(
            WarningCode.UNSUPPORTED_BLOCK_TYPE,
            f"Packet {packet_number} came from a Simple Packet Block, which carries no "
            "timestamp; a timestamp of 0 is recorded and must not be treated as observed.",
            severity=Severity.WARNING,
            block_type=BT_SPB,
        )
        return RawFrame(
            packet_number=packet_number,
            timestamp_ns=0,
            data=data,
            original_length=int(original_len) if original_len >= len(data) else len(data),
            link_type_code=iface.link_type_code,
            link_type=iface.link_type,
            interface_id=iface.interface_id,
        )
