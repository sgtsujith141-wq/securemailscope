"""Deterministic finding prioritisation.

Priority is an *ordering*, produced from inputs that are all visible in the
output. It is not a risk probability, and severity is never multiplied by a
confidence percentage to manufacture one -- that would present a judgement
about evidence quality as though it were a measured likelihood of exploitation.

The priority band comes from a fixed matrix of (severity, confidence). A
CRITICAL condition seen with LOW confidence stays worth looking at, but it
does not outrank a CRITICAL condition that was confirmed.

Asset criticality participates **only when the operator supplied it** for a
specific endpoint. Nothing is inferred about what matters to a business, and
no infrastructure is invented.

Ordering is total and stable: every tie is broken by values that exist in the
data, ending with the finding id, so two runs over the same capture produce
the same list in the same order.
"""

from __future__ import annotations

from typing import Final

from ..models.assessment import (
    Confidence,
    FindingSeverity,
    PrioritisedFinding,
    PriorityBand,
    SecurityFinding,
)
from ..models.tcp import TCPSession
from .policy import AssessmentPolicy

__all__ = ["prioritise", "PRIORITY_MATRIX"]

_SEVERITY_RANK: Final[dict[FindingSeverity, int]] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
_CONFIDENCE_RANK: Final[dict[Confidence, int]] = {
    Confidence.CONFIRMED: 0,
    Confidence.PROBABLE: 1,
    Confidence.LOW: 2,
}

#: (severity, confidence) -> band. A matrix, not a product: the mapping is
#: readable, auditable and carries no implied arithmetic.
PRIORITY_MATRIX: Final[dict[tuple[FindingSeverity, Confidence], PriorityBand]] = {
    (FindingSeverity.CRITICAL, Confidence.CONFIRMED): PriorityBand.P1,
    (FindingSeverity.CRITICAL, Confidence.PROBABLE): PriorityBand.P1,
    (FindingSeverity.CRITICAL, Confidence.LOW): PriorityBand.P2,
    (FindingSeverity.HIGH, Confidence.CONFIRMED): PriorityBand.P1,
    (FindingSeverity.HIGH, Confidence.PROBABLE): PriorityBand.P2,
    (FindingSeverity.HIGH, Confidence.LOW): PriorityBand.P3,
    (FindingSeverity.MEDIUM, Confidence.CONFIRMED): PriorityBand.P2,
    (FindingSeverity.MEDIUM, Confidence.PROBABLE): PriorityBand.P3,
    (FindingSeverity.MEDIUM, Confidence.LOW): PriorityBand.P3,
    (FindingSeverity.LOW, Confidence.CONFIRMED): PriorityBand.P3,
    (FindingSeverity.LOW, Confidence.PROBABLE): PriorityBand.P4,
    (FindingSeverity.LOW, Confidence.LOW): PriorityBand.P4,
    (FindingSeverity.INFO, Confidence.CONFIRMED): PriorityBand.P4,
    (FindingSeverity.INFO, Confidence.PROBABLE): PriorityBand.P4,
    (FindingSeverity.INFO, Confidence.LOW): PriorityBand.P4,
}

#: Ordering of operator-supplied criticality labels. Unlabelled endpoints sort
#: last, because "not stated" is not "not important" -- it is simply unknown,
#: and the engine refuses to guess either way.
_CRITICALITY_RANK: Final[dict[str, int]] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _endpoint(session: TCPSession) -> str:
    return f"{session.flow.server.ip}:{session.flow.server.port}"


def prioritise(
    findings: tuple[SecurityFinding, ...],
    sessions: dict[str, TCPSession],
    policy: AssessmentPolicy,
) -> tuple[PrioritisedFinding, ...]:
    """Order findings deterministically and explain each position."""
    scope: dict[str, int] = {}
    for finding in findings:
        scope[finding.rule_id] = scope.get(finding.rule_id, 0) + 1

    entries: list[tuple[tuple[int, int, int, int, str, str], PrioritisedFinding]] = []
    for finding in findings:
        session = sessions.get(finding.session_id)
        criticality = (
            policy.criticality_for(_endpoint(session)) if session is not None else None
        )
        severity_rank = _SEVERITY_RANK[finding.severity]
        confidence_rank = _CONFIDENCE_RANK[finding.confidence]
        criticality_rank = _CRITICALITY_RANK.get(
            (criticality or "").upper(), len(_CRITICALITY_RANK)
        )
        observed = scope.get(finding.rule_id, 1)
        band = PRIORITY_MATRIX[(finding.severity, finding.confidence)]

        # Scope is negated so that a rule failing in more sessions sorts first.
        sort_key = (
            severity_rank,
            confidence_rank,
            criticality_rank,
            -observed,
            finding.rule_id,
            finding.finding_id,
        )
        explanation_parts = [
            f"severity {finding.severity.value}",
            f"confidence {finding.confidence.value}",
        ]
        if criticality:
            explanation_parts.append(
                f"operator-supplied asset criticality {criticality.upper()} for "
                f"{_endpoint(session) if session else 'this endpoint'}"
            )
        else:
            explanation_parts.append("no asset criticality was supplied")
        explanation_parts.append(
            f"observed in {observed} session(s) in this capture"
        )
        entries.append(
            (
                sort_key,
                PrioritisedFinding(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    rank=1,
                    priority=band,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    observed_session_count=observed,
                    asset_criticality=criticality.upper() if criticality else None,
                    explanation=(
                        f"{band.value} from "
                        + ", ".join(explanation_parts)
                        + ". Severity, confidence and priority are reported separately "
                        "and are never combined into a risk probability."
                    ),
                    sort_key=sort_key,
                ),
            )
        )

    entries.sort(key=lambda item: item[0])
    return tuple(
        entry.model_copy(update={"rank": index})
        for index, (_, entry) in enumerate(entries, start=1)
    )
