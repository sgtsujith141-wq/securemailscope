"""Bounded reader for TLS wire structures.

Every length in a TLS message is attacker-controlled.  This reader makes it
impossible to read past the buffer by accident: each accessor either returns
the requested bytes or raises :class:`TLSParseError`, and callers turn that
into a structured diagnostic rather than a traceback.
"""

from __future__ import annotations

__all__ = ["TLSParseError", "ByteReader"]


class TLSParseError(ValueError):
    """A TLS structure was truncated or structurally invalid."""


class ByteReader:
    """Sequential reader over a bytes buffer with explicit bounds."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, count: int) -> bytes:
        if count < 0:
            raise TLSParseError(f"negative length {count}")
        if count > self.remaining:
            raise TLSParseError(
                f"need {count} bytes at offset {self._pos}, only {self.remaining} remain"
            )
        chunk = self._data[self._pos : self._pos + count]
        self._pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        raw = self.take(2)
        return (raw[0] << 8) | raw[1]

    def u24(self) -> int:
        raw = self.take(3)
        return (raw[0] << 16) | (raw[1] << 8) | raw[2]

    def u32(self) -> int:
        raw = self.take(4)
        return int.from_bytes(raw, "big")

    def vector8(self) -> bytes:
        """A vector whose length is carried in one byte."""
        return self.take(self.u8())

    def vector16(self) -> bytes:
        """A vector whose length is carried in two bytes."""
        return self.take(self.u16())

    def vector24(self) -> bytes:
        """A vector whose length is carried in three bytes."""
        return self.take(self.u24())

    def u16_list(self, data: bytes) -> tuple[int, ...]:
        """Decode a byte string as a sequence of 16-bit code points."""
        if len(data) % 2:
            raise TLSParseError("16-bit code point list has an odd length")
        return tuple(
            (data[index] << 8) | data[index + 1] for index in range(0, len(data), 2)
        )
