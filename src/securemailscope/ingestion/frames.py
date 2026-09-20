"""The container-level record produced by a capture reader.

A :class:`RawFrame` is deliberately *not* a dissected packet: it is the link
layer bytes exactly as stored, plus the metadata the container provided.
Dissection happens later (``ingestion/dissect.py``) so a link-layer parsing
failure can never be confused with a container parsing failure.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models.capture import LinkType

__all__ = ["RawFrame"]


@dataclass(frozen=True, slots=True)
class RawFrame:
    #: 1-based position in capture file order. Stable across runs.
    packet_number: int
    #: Capture timestamp in epoch nanoseconds, at the file's full precision.
    timestamp_ns: int
    #: Link layer bytes as stored in the file (possibly snapshot-truncated).
    data: bytes
    #: Length of the frame on the wire, which may exceed ``len(data)``.
    original_length: int
    link_type_code: int
    link_type: LinkType
    interface_id: int = 0

    @property
    def snapshot_truncated(self) -> bool:
        """True when the file stored fewer bytes than were on the wire."""
        return self.original_length > len(self.data)
