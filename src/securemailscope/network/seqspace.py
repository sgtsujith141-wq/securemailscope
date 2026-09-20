"""32-bit TCP sequence numbers projected into a monotonic 64-bit space.

TCP sequence numbers are modulo 2**32 and a busy connection wraps.  Comparing
raw 32-bit values with ``<`` is therefore wrong, and a reassembler that does it
either drops a whole window of data or reorders it catastrophically.

Every sequence number this direction has shown us is projected relative to the
highest value seen so far, using the standard "shorter arc wins" rule: a value
is taken to be *ahead* of the high-water mark when the forward distance is no
greater than the backward distance.  That is exact for any sequence number
within 2**31 of the high-water mark, which TCP's own window rules guarantee.
"""

from __future__ import annotations

from typing import Final

__all__ = ["SequenceSpace", "SEQ_MODULUS"]

SEQ_MODULUS: Final = 1 << 32
_HALF: Final = 1 << 31


class SequenceSpace:
    """Projects 32-bit sequence numbers of one direction into 64-bit offsets.

    The projection is anchored at ``base``, which maps to extended value 0.
    Extended values may legitimately be negative when a sequence number older
    than the anchor shows up (a retransmission of data from before the capture
    started, for example).
    """

    __slots__ = ("_base32", "_hi32", "_hi_ext", "wraparounds")

    def __init__(self, base: int) -> None:
        self._base32 = base & 0xFFFFFFFF
        self._hi32 = self._base32
        self._hi_ext = 0
        self.wraparounds = 0

    @property
    def base(self) -> int:
        """The 32-bit sequence number that maps to extended value 0."""
        return self._base32

    def project(self, seq32: int) -> int:
        """Extended value for ``seq32`` without advancing the high-water mark."""
        seq32 &= 0xFFFFFFFF
        forward = (seq32 - self._hi32) % SEQ_MODULUS
        backward = (self._hi32 - seq32) % SEQ_MODULUS
        if forward <= backward:
            return self._hi_ext + forward
        return self._hi_ext - backward

    def extend(self, seq32: int) -> int:
        """Extended value for ``seq32``, advancing the high-water mark.

        Only forward movement advances the mark, so a burst of retransmissions
        cannot drag the projection backwards.
        """
        seq32 &= 0xFFFFFFFF
        forward = (seq32 - self._hi32) % SEQ_MODULUS
        backward = (self._hi32 - seq32) % SEQ_MODULUS
        if forward <= backward:
            extended = self._hi_ext + forward
            if seq32 < self._hi32 and forward > 0:
                self.wraparounds += 1
            self._hi32 = seq32
            self._hi_ext = extended
            return extended
        return self._hi_ext - backward

    def to_sequence(self, extended: int) -> int:
        """Inverse projection: the 32-bit sequence number for an extended value."""
        return (self._base32 + extended) % SEQ_MODULUS
