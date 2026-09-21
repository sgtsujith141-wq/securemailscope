"""The posture score: a deterministic, documented, project-defined metric.

Formalisation
-------------

Rules are grouped into **scoring units** by ``dedup_group``, so one underlying
weakness contributes once.  For a unit *g*:

* its **outcome** is ``FAIL`` if any member failed, else ``PASS`` if any
  member passed, else ``UNKNOWN`` if any member was unknown, else
  ``NOT_APPLICABLE``;
* its **representative** is the most severe member that produced that outcome,
  and the unit's weight *w(g)* is that rule's policy weight.

Weighting a unit by the rule that actually determined it -- rather than by the
most severe rule it *could* contain -- keeps the arithmetic honest: a session
that merely negotiated a non-preferred cipher is not weighted as though it had
negotiated NULL encryption.

Let ``A`` be the units with outcome in {FAIL, PASS, UNKNOWN}, ``E`` those in
{FAIL, PASS}, and ``F`` those that failed.
With ``W(S)`` meaning the sum of ``w(g)`` over the units in ``S``:

    coverage = W(E) / W(A)
    score    = 100 * (W(E) - W(F)) / W(E)

``NOT_APPLICABLE`` units are excluded entirely -- a rule that does not apply is
not a control this session was measured against.  ``INFO`` rules weigh zero and
so participate in neither score nor coverage: they are context, not controls.

Properties, each covered by a test
----------------------------------

1. *An UNKNOWN cannot improve the score.*  UNKNOWN units are in ``A`` but not
   ``E``, so they appear in neither side of the score fraction. Adding one
   leaves the score identical and lowers coverage.
2. *An UNKNOWN cannot reduce the score as though it were a violation.*  It
   contributes nothing to ``W(F)``.
3. *PASS/FAIL are distinguished from UNKNOWN/NOT_APPLICABLE* by set
   membership, never by a default value.
4. *Coverage is always disclosed*, and is a separate measurement from posture.
5. *Insufficient evidence yields ``SCORE_UNAVAILABLE``* rather than a number,
   when nothing is evaluable or coverage is below the policy floor.
6. *No double counting*: units, not rules.
7. *More independent violations never raise the score.*  A unit flipping to
   FAIL adds its weight to ``W(F)`` and at most adds it to ``W(E)``, so the
   fraction strictly decreases whenever the score was above zero.
8. *Adding an UNKNOWN never raises the score* -- see 1.
9. *A policy change may move the score*, and the policy version is recorded in
   the same object.
10. *No model is involved.*  The computation is closed-form arithmetic over
    typed inputs.

The score describes **the analysed evidence under a named policy version**. It
is a transparent project-defined analytical metric, not a validated measure of
an organisation's security.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models.assessment import (
    AssessmentCoverage,
    ControlTally,
    FindingSeverity,
    PostureScore,
    RuleOutcome,
    RuleResult,
    ScoreBand,
    ScoreStatus,
)
from .catalog import RULES
from .policy import AssessmentPolicy

__all__ = ["ScoringUnit", "build_units", "compute_score", "SCORE_FORMULA"]

SCORE_FORMULA = "score = 100 * (W(evaluated) - W(failed)) / W(evaluated)"

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
_OUTCOME_PRIORITY: dict[RuleOutcome, int] = {
    RuleOutcome.FAIL: 0,
    RuleOutcome.PASS: 1,
    RuleOutcome.UNKNOWN: 2,
    RuleOutcome.NOT_APPLICABLE: 3,
}

#: Project-defined reading aids. Not an industry classification.
_BANDS: tuple[tuple[int, ScoreBand], ...] = (
    (90, ScoreBand.STRONG),
    (70, ScoreBand.ADEQUATE),
    (40, ScoreBand.WEAK),
    (0, ScoreBand.CRITICAL),
)


@dataclass(frozen=True, slots=True)
class ScoringUnit:
    """One weakness-level control, derived from a dedup group."""

    group: str
    session_id: str
    outcome: RuleOutcome
    weight: float
    representative_rule_id: str
    severity: FindingSeverity
    member_rule_ids: tuple[str, ...]


def build_units(
    results: tuple[RuleResult, ...], policy: AssessmentPolicy
) -> tuple[ScoringUnit, ...]:
    """Collapse rule results into scoring units, one per dedup group."""
    grouped: dict[tuple[str, str], list[RuleResult]] = {}
    for result in results:
        grouped.setdefault((result.session_id, result.dedup_group), []).append(result)

    units: list[ScoringUnit] = []
    for (session_id, group), members in sorted(grouped.items()):
        outcome = min(
            (member.outcome for member in members), key=lambda o: _OUTCOME_PRIORITY[o]
        )
        if outcome is RuleOutcome.NOT_APPLICABLE:
            units.append(
                ScoringUnit(
                    group=group,
                    session_id=session_id,
                    outcome=outcome,
                    weight=0.0,
                    representative_rule_id=sorted(m.rule_id for m in members)[0],
                    severity=FindingSeverity.INFO,
                    member_rule_ids=tuple(sorted(m.rule_id for m in members)),
                )
            )
            continue
        deciding = [member for member in members if member.outcome is outcome]
        representative = min(
            deciding, key=lambda m: (_SEVERITY_ORDER[m.severity], m.rule_id)
        )
        weight = policy.weight_for(representative.rule_id, representative.severity)
        units.append(
            ScoringUnit(
                group=group,
                session_id=session_id,
                outcome=outcome,
                weight=weight,
                representative_rule_id=representative.rule_id,
                severity=representative.severity,
                member_rule_ids=tuple(sorted(m.rule_id for m in members)),
            )
        )
    return tuple(units)


def _band(score: int) -> ScoreBand:
    for threshold, band in _BANDS:
        if score >= threshold:
            return band
    return ScoreBand.CRITICAL  # pragma: no cover - the table ends at 0


def compute_score(
    units: tuple[ScoringUnit, ...], policy: AssessmentPolicy, *, scope: str
) -> PostureScore:
    """Apply the documented formula to a set of scoring units."""
    scored = [unit for unit in units if unit.weight > 0.0]
    evaluated = [
        unit for unit in scored if unit.outcome in {RuleOutcome.FAIL, RuleOutcome.PASS}
    ]
    unknown = [unit for unit in scored if unit.outcome is RuleOutcome.UNKNOWN]
    failed = [unit for unit in evaluated if unit.outcome is RuleOutcome.FAIL]
    passed = [unit for unit in evaluated if unit.outcome is RuleOutcome.PASS]
    not_applicable = [unit for unit in units if unit.outcome is RuleOutcome.NOT_APPLICABLE]

    weighted_evaluated = sum(unit.weight for unit in evaluated)
    weighted_unknown = sum(unit.weight for unit in unknown)
    weighted_applicable = weighted_evaluated + weighted_unknown
    weighted_deductions = sum(unit.weight for unit in failed)

    coverage_ratio = (
        weighted_evaluated / weighted_applicable if weighted_applicable > 0 else 0.0
    )
    sufficient = (
        weighted_evaluated > 0 and coverage_ratio >= policy.minimum_coverage_for_score
    )
    coverage = AssessmentCoverage(
        weighted_applicable=round(weighted_applicable, 4),
        weighted_evaluated=round(weighted_evaluated, 4),
        coverage_ratio=round(coverage_ratio, 4),
        minimum_required=policy.minimum_coverage_for_score,
        sufficient=sufficient,
        explanation=(
            f"{len(evaluated)} of {len(evaluated) + len(unknown)} applicable scoring "
            f"units could be evaluated, carrying {weighted_evaluated:g} of "
            f"{weighted_applicable:g} applicable weight. Coverage measures how much of "
            "the policy the evidence let us check; it is a separate measurement from "
            "the posture score itself."
        ),
    )

    tally = ControlTally(
        total_applicable=len(evaluated) + len(unknown),
        evaluated=len(evaluated),
        passed=len(passed),
        failed=len(failed),
        unknown=len(unknown),
        not_applicable=len(not_applicable),
        suppressed_duplicates=0,
    )

    deduction_detail = tuple(
        f"{unit.group}: -{unit.weight:g} ({unit.representative_rule_id}, "
        f"{unit.severity.value})"
        for unit in sorted(failed, key=lambda u: (-u.weight, u.group))
    )

    limitations = (
        "This score describes the analysed evidence under the named policy version "
        "and nothing wider. It is a transparent project-defined analytical metric, "
        "not a validated measure of an organisation's security posture.",
        "Coverage and posture are separate measurements. A high score over low "
        "coverage is a statement about very little.",
        "Rules that could not be evaluated are excluded from both sides of the "
        "fraction, so missing evidence neither earns credit nor counts as a violation.",
    )

    if not sufficient:
        reason = (
            "No control could be evaluated from the available evidence."
            if weighted_evaluated == 0
            else (
                f"Coverage {coverage_ratio:.0%} is below the policy floor of "
                f"{policy.minimum_coverage_for_score:.0%}."
            )
        )
        return PostureScore(
            status=ScoreStatus.SCORE_UNAVAILABLE,
            score=None,
            band=ScoreBand.NOT_AVAILABLE,
            tally=tally,
            coverage=coverage,
            weighted_evaluated=round(weighted_evaluated, 4),
            weighted_deductions=round(weighted_deductions, 4),
            deduction_detail=deduction_detail,
            formula=SCORE_FORMULA,
            explanation=(
                f"SCORE_UNAVAILABLE. {reason} Reporting a number here would imply an "
                "assessment the evidence does not support."
            ),
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            scope=scope,
            limitations=limitations,
        )

    raw = 100.0 * (weighted_evaluated - weighted_deductions) / weighted_evaluated
    score = max(0, min(100, round(raw)))
    return PostureScore(
        status=ScoreStatus.AVAILABLE,
        score=score,
        band=_band(score),
        tally=tally,
        coverage=coverage,
        weighted_evaluated=round(weighted_evaluated, 4),
        weighted_deductions=round(weighted_deductions, 4),
        deduction_detail=deduction_detail,
        formula=SCORE_FORMULA,
        explanation=(
            f"{len(evaluated)} scoring unit(s) were evaluable, carrying "
            f"{weighted_evaluated:g} weight. {len(failed)} failed, deducting "
            f"{weighted_deductions:g}. "
            f"100 x ({weighted_evaluated:g} - {weighted_deductions:g}) / "
            f"{weighted_evaluated:g} = {raw:.1f}, rounded to {score}. "
            f"{len(unknown)} unit(s) could not be evaluated and are excluded from both "
            "sides of the fraction."
        ),
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        scope=scope,
        limitations=limitations,
    )


def suppressed_count(results: tuple[RuleResult, ...]) -> int:
    """How many FAIL results were merged into another unit."""
    return sum(
        1
        for result in results
        if result.outcome is RuleOutcome.FAIL and not result.counts_toward_score
    )


def rule_weight(rule_id: str, policy: AssessmentPolicy) -> float:
    """The weight one rule would contribute, for documentation and tests."""
    definition = RULES[rule_id]
    severity = policy.severity_for(rule_id, definition.severity)
    return policy.weight_for(rule_id, severity)
