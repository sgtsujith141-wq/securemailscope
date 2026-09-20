"""Byte budgets used to bound reconstructed payload memory."""

from __future__ import annotations

__all__ = ["ByteBudget"]


class ByteBudget:
    """A simple non-refundable allowance.

    :meth:`take` grants as much as remains, so a stream that hits the ceiling
    keeps the prefix it already reconstructed instead of being discarded.
    """

    __slots__ = ("limit", "used", "exceeded")

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        self.limit = limit
        self.used = 0
        self.exceeded = False

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def take(self, amount: int) -> int:
        """Grant up to ``amount`` bytes; returns how many were actually granted."""
        if amount <= 0:
            return 0
        granted = min(amount, self.remaining)
        self.used += granted
        if granted < amount:
            self.exceeded = True
        return granted
