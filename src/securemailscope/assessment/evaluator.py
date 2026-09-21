"""Runs the rule catalogue over a session and produces results and findings.

Two responsibilities beyond simply calling each evaluator:

**Deduplication.**  Several rules can describe one underlying weakness -- a
NULL-encryption suite trips both "provides no encryption" and "not on the
approved list".  Every result is still reported, but within a ``dedup_group``
only the most severe FAIL becomes a finding and counts toward the score, so a
single weakness is not punished repeatedly.

**Stable identity.**  A finding id is a digest of the canonical assessment
inputs -- policy, rule, capture, session and the evidence positions -- so the
same capture assessed under the same policy always yields the same ids and two
reports can be diffed.  Nothing here is random.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from ..models.assessment import (
    Confidence,
    FindingSeverity,
    RuleCategory,
    RuleOutcome,
    RuleResult,
    SecurityFinding,
)
from .catalog import RULES
from .policy import AssessmentPolicy
from .rules import RULE_EVALUATORS, SessionContext, Verdict

__all__ = ["evaluate_session", "build_findings", "finding_id_for"]

_SEVERITY_ORDER: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def _default_confidence(category: RuleCategory, ctx: SessionContext) -> Confidence:
    if category is RuleCategory.EMAIL_TRANSPORT:
        return ctx.mail_confidence()
    return ctx.tls_confidence()


def evaluate_session(ctx: SessionContext) -> tuple[RuleResult, ...]:
    """Evaluate every enabled rule against one session, then deduplicate."""
    results: list[RuleResult] = []
    for rule_id in sorted(RULES):
        definition = RULES[rule_id]
        if not ctx.policy.enabled(rule_id):
            continue
        verdict: Verdict = RULE_EVALUATORS[rule_id](ctx)
        severity = ctx.policy.severity_for(rule_id, definition.severity)
        confidence = verdict.confidence or _default_confidence(definition.category, ctx)
        results.append(
            RuleResult(
                rule_id=rule_id,
                outcome=verdict.outcome,
                severity=severity,
                confidence=confidence,
                category=definition.category,
                capture_id=ctx.capture_id,
                session_id=ctx.session.session_id,
                policy_id=ctx.policy.policy_id,
                policy_version=ctx.policy.policy_version,
                rationale=verdict.rationale,
                observed_values=verdict.observed,
                evidence_refs=verdict.evidence,
                stream_offsets=verdict.offsets,
                limitations=verdict.limitations,
                dedup_group=definition.dedup_group,
            )
        )
    return _deduplicate(tuple(results))


def _deduplicate(results: tuple[RuleResult, ...]) -> tuple[RuleResult, ...]:
    """Mark all but the most severe FAIL in each dedup group as non-counting.

    Nothing is removed: every result stays visible in ``rule_results``. Only
    ``counts_toward_score`` changes, so a reader can see both the full picture
    and which entry carried the weight.
    """
    representatives: dict[str, str] = {}
    for result in results:
        if result.outcome is not RuleOutcome.FAIL:
            continue
        current = representatives.get(result.dedup_group)
        if current is None:
            representatives[result.dedup_group] = result.rule_id
            continue
        incumbent = next(r for r in results if r.rule_id == current)
        if _SEVERITY_ORDER[result.severity] < _SEVERITY_ORDER[incumbent.severity] or (
            result.severity is incumbent.severity and result.rule_id < incumbent.rule_id
        ):
            representatives[result.dedup_group] = result.rule_id

    updated: list[RuleResult] = []
    for result in results:
        if result.outcome is RuleOutcome.FAIL:
            keep = representatives.get(result.dedup_group) == result.rule_id
            updated.append(result.model_copy(update={"counts_toward_score": keep}))
        else:
            updated.append(result)
    return tuple(updated)


def finding_id_for(result: RuleResult, policy: AssessmentPolicy) -> str:
    """A deterministic identifier derived from the canonical inputs.

    The policy fingerprint, not just its version, is part of the material: a
    finding reached under changed thresholds is a different finding, and must
    not share an identifier with one reached under the published defaults.
    """
    positions = ",".join(str(offset) for offset in result.stream_offsets)
    packets = ",".join(str(ref.packet_number) for ref in result.evidence_refs)
    material = "|".join(
        (
            result.policy_id,
            policy.fingerprint,
            result.rule_id,
            result.capture_id,
            result.session_id,
            positions,
            packets,
        )
    )
    return "find-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def build_findings(
    results: tuple[RuleResult, ...], policy: AssessmentPolicy
) -> tuple[SecurityFinding, ...]:
    """Promote the counting FAIL results to findings.

    Only FAIL becomes a finding. PASS, UNKNOWN and NOT_APPLICABLE stay in
    ``rule_results``, which is what lets a report show what was checked rather
    than only what went wrong.
    """
    findings: list[SecurityFinding] = []
    for result in results:
        if result.outcome is not RuleOutcome.FAIL or not result.counts_toward_score:
            continue
        definition = RULES[result.rule_id]
        timestamps = [ref.timestamp for ref in result.evidence_refs]
        findings.append(
            SecurityFinding(
                finding_id=finding_id_for(result, policy),
                rule_id=result.rule_id,
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_fingerprint=policy.fingerprint,
                title=definition.name,
                description=result.rationale,
                severity=result.severity,
                evaluation_status=result.outcome,
                confidence=result.confidence,
                category=result.category,
                capture_id=result.capture_id,
                session_id=result.session_id,
                evidence_refs=result.evidence_refs,
                stream_offsets=result.stream_offsets,
                observed_values=result.observed_values,
                first_observed=min(timestamps) if timestamps else None,
                last_observed=max(timestamps) if timestamps else None,
                technical_impact=definition.technical_impact,
                standards_references=definition.standards_references,
                limitations=result.limitations,
                remediation_ids=definition.remediation_ids,
            )
        )
    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.rule_id, f.finding_id))
    return tuple(findings)


def session_window(results: tuple[RuleResult, ...]) -> tuple[datetime | None, datetime | None]:
    """First and last evidence timestamps across a session's results."""
    stamps = [ref.timestamp for result in results for ref in result.evidence_refs]
    return (min(stamps), max(stamps)) if stamps else (None, None)
