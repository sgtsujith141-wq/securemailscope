"""Bounded collector for structured diagnostics.

A hostile capture can trivially generate millions of identical warnings.  The
sink therefore caps emissions *per code* and replaces the overflow with a
single explicit ``WARNINGS_SUPPRESSED`` record, so the output stays bounded
without ever pretending the extra events did not happen.
"""

from __future__ import annotations

from collections import Counter

from .models.evidence import AnalysisWarning, PacketReference, Severity, WarningCode

__all__ = ["WarningSink"]


class WarningSink:
    def __init__(self, *, capture_id: str | None = None, max_per_code: int = 100) -> None:
        if max_per_code < 1:
            raise ValueError("max_per_code must be >= 1")
        self._capture_id = capture_id
        self._max_per_code = max_per_code
        self._warnings: list[AnalysisWarning] = []
        self._counts: Counter[WarningCode] = Counter()

    def bind_capture(self, capture_id: str) -> None:
        """Attach a capture id once it is known (the hash is computed first)."""
        self._capture_id = capture_id
        for warning in self._warnings:
            if warning.capture_id is None:
                warning.capture_id = capture_id

    def add(
        self,
        code: WarningCode,
        message: str,
        *,
        severity: Severity = Severity.WARNING,
        session_id: str | None = None,
        packet_refs: tuple[PacketReference, ...] = (),
        **details: str | int | bool,
    ) -> None:
        self._counts[code] += 1
        if self._counts[code] > self._max_per_code:
            return
        self._warnings.append(
            AnalysisWarning(
                code=code,
                severity=severity,
                message=message,
                capture_id=self._capture_id,
                session_id=session_id,
                packet_refs=packet_refs,
                details=dict(details),
            )
        )

    def count(self, code: WarningCode) -> int:
        """Total occurrences of ``code``, including suppressed ones."""
        return self._counts[code]

    def collect(self) -> tuple[AnalysisWarning, ...]:
        """Return the recorded warnings plus one summary per suppressed code."""
        result = list(self._warnings)
        for code, total in sorted(self._counts.items()):
            if total > self._max_per_code:
                result.append(
                    AnalysisWarning(
                        code=WarningCode.WARNINGS_SUPPRESSED,
                        severity=Severity.INFO,
                        message=(
                            f"{total - self._max_per_code} further '{code.value}' diagnostics "
                            f"were suppressed (cap: {self._max_per_code})."
                        ),
                        capture_id=self._capture_id,
                        details={
                            "suppressed_code": code.value,
                            "total_occurrences": total,
                            "emitted": self._max_per_code,
                        },
                    )
                )
        return tuple(result)
