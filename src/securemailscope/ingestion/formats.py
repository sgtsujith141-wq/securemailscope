"""Capture container format detection.

Detection is driven entirely by file *contents*.  The extension is never
consulted: a hostile or simply mislabelled ``.pcap`` that is actually a ZIP
must be rejected, and a correct pcapng named ``.dump`` must be accepted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from ..models.capture import CaptureFormat

__all__ = [
    "MAGIC_LENGTH",
    "detect_format_from_bytes",
    "detect_format",
    "PCAP_MAGICS",
    "PCAPNG_BLOCK_TYPE_SHB",
]

#: Bytes that must be available to classify a file.
MAGIC_LENGTH: Final = 12

# libpcap variants.  The two "swapped" magics mean the file was written by a
# host with the opposite endianness; the two 0xa1b2*3c4d* variants distinguish
# microsecond from nanosecond timestamp resolution.
PCAP_MAGICS: Final[dict[bytes, tuple[CaptureFormat, str]]] = {
    b"\xa1\xb2\xc3\xd4": (CaptureFormat.PCAP, "big"),
    b"\xd4\xc3\xb2\xa1": (CaptureFormat.PCAP, "little"),
    b"\xa1\xb2\x3c\x4d": (CaptureFormat.PCAP_NS, "big"),
    b"\x4d\x3c\xb2\xa1": (CaptureFormat.PCAP_NS, "little"),
}

PCAPNG_BLOCK_TYPE_SHB: Final = 0x0A0D0D0A
#: The pcapng byte-order magic that appears at offset 8 of a Section Header Block.
_PCAPNG_BOM_LE: Final = b"\x4d\x3c\x2b\x1a"
_PCAPNG_BOM_BE: Final = b"\x1a\x2b\x3c\x4d"


def detect_format_from_bytes(head: bytes) -> tuple[CaptureFormat, str | None]:
    """Classify a capture from its leading bytes.

    Returns ``(format, byte_order)``.  ``byte_order`` is ``None`` for formats
    where it is not yet determined or not applicable.
    """
    if len(head) < 4:
        return CaptureFormat.UNKNOWN, None

    magic = head[:4]
    if magic in PCAP_MAGICS:
        fmt, order = PCAP_MAGICS[magic]
        return fmt, order

    # pcapng: SHB type is byte-order independent (palindromic), the real
    # endianness comes from the byte-order magic inside the block.
    if magic == b"\x0a\x0d\x0d\x0a":
        if len(head) >= 12:
            bom = head[8:12]
            if bom == _PCAPNG_BOM_LE:
                return CaptureFormat.PCAPNG, "little"
            if bom == _PCAPNG_BOM_BE:
                return CaptureFormat.PCAPNG, "big"
            return CaptureFormat.UNKNOWN, None
        return CaptureFormat.UNKNOWN, None

    return CaptureFormat.UNKNOWN, None


def detect_format(path: Path) -> tuple[CaptureFormat, str | None]:
    """Read only the header bytes of ``path`` and classify it."""
    with path.open("rb") as handle:
        head = handle.read(MAGIC_LENGTH)
    return detect_format_from_bytes(head)
