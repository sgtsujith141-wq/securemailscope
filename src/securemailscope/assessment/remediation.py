"""Remediation selection.

Advice is only emitted for conditions that were actually found. The catalogue
in :mod:`securemailscope.assessment.catalog` maps rules to remediations, and
this module walks the findings that were produced -- never the rules that
might have been. That is what stops a report recommending certificate renewal
for a session whose certificate was never visible, or recommending that TLS 1.2
be disabled because some other session negotiated TLS 1.3.
"""

from __future__ import annotations

from ..models.assessment import Remediation, SecurityFinding
from .catalog import REMEDIATIONS, RULES

__all__ = ["select_remediations"]


def select_remediations(
    findings: tuple[SecurityFinding, ...],
) -> tuple[Remediation, ...]:
    """Return the remediations mapped to the rules that actually failed.

    Ordered by the severity of the most severe finding that called for each,
    so the list reads in the order the work should be considered.
    """
    from .prioritization import _SEVERITY_RANK

    best_rank: dict[str, int] = {}
    for finding in findings:
        definition = RULES[finding.rule_id]
        for remediation_id in definition.remediation_ids:
            rank = _SEVERITY_RANK[finding.severity]
            if remediation_id not in best_rank or rank < best_rank[remediation_id]:
                best_rank[remediation_id] = rank

    selected = [
        REMEDIATIONS[remediation_id]
        for remediation_id in sorted(
            best_rank, key=lambda rid: (best_rank[rid], rid)
        )
    ]
    return tuple(selected)
