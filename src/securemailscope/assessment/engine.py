"""The assessment engine: observations in, judgements out.

The engine consumes the typed M1-M3 result models and produces rule results,
findings, a score, a priority ordering and the remediations those findings
call for. It reads no files, parses no packets, and makes no network request;
it is a pure function of ``(AnalysisResult, AssessmentPolicy)``.

The forensic observations it consumes are reported unchanged alongside the
assessment. A different policy produces a different judgement about the same
evidence, which is exactly the separation the evidence model requires.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..models.analysis import AnalysisResult
from ..models.assessment import (
    AssessmentMode,
    AssessmentResult,
    RuleOutcome,
    SecurityFinding,
    SessionAssessment,
)
from ..models.tcp import TCPSession
from .evaluator import build_findings, evaluate_session
from .policy import DEFAULT_POLICY, AssessmentPolicy
from .prioritization import prioritise
from .remediation import select_remediations
from .rules import SessionContext
from .scoring import ScoringUnit, build_units, compute_score, suppressed_count

__all__ = ["assess_capture"]

_ENGINE_LIMITATIONS: tuple[str, ...] = (
    "This assessment judges the evidence in one capture under one named policy "
    "version. It does not describe an organisation's wider security posture.",
    "Revocation status is never established: the engine makes no network requests, "
    "so no OCSP or CRL check is performed and none is claimed. Unknown revocation is "
    "neither 'revoked' nor 'not revoked'.",
    "No finding asserts that an attack occurred. A weak configuration, a refused "
    "upgrade or an absent advertisement are configuration observations; a capture "
    "cannot establish intent or exploitation.",
    "Cross-session correlation and blast-radius analysis are not performed (planned "
    "for M5), so the observed scope of a finding is the scope within this capture only.",
)


def assess_capture(
    result: AnalysisResult,
    *,
    policy: AssessmentPolicy = DEFAULT_POLICY,
    now: datetime | None = None,
) -> AssessmentResult:
    """Assess one analysed capture under one policy."""
    reference_time = (
        (now or datetime.now(tz=UTC))
        if policy.assessment_mode is AssessmentMode.CURRENT_TIME
        else None
    )

    protocols = {analysis.session_id: analysis for analysis in result.protocols}
    tls_by_session = {analysis.session_id: analysis for analysis in result.tls}
    sessions: dict[str, TCPSession] = {
        session.session_id: session for session in result.sessions
    }

    assessments: list[SessionAssessment] = []
    all_findings: list[SecurityFinding] = []
    all_units: list[ScoringUnit] = []
    total_results = 0
    total_suppressed = 0

    for session in result.sessions:
        context = SessionContext(
            capture_id=result.capture.capture_id,
            session=session,
            protocol=protocols.get(session.session_id),
            tls=tls_by_session.get(session.session_id),
            policy=policy,
            reference_time=reference_time,
        )
        results = evaluate_session(context)
        findings = build_findings(results, policy)
        units = build_units(results, policy)
        total_results += len(results)
        session_suppressed = suppressed_count(results)
        total_suppressed += session_suppressed

        session_score = compute_score(
            units, policy, scope=f"session {session.session_id}"
        )
        # A session assessment is read on its own, so its tally must account
        # for its own suppressed duplicates rather than leaving that only in
        # the capture-wide total.
        session_score = session_score.model_copy(
            update={
                "tally": session_score.tally.model_copy(
                    update={"suppressed_duplicates": session_suppressed}
                )
            }
        )

        assessments.append(
            SessionAssessment(
                session_id=session.session_id,
                capture_id=result.capture.capture_id,
                rule_results=results,
                findings=findings,
                posture_score=session_score,
                limitations=(
                    "Scoped to one TCP session. A session that carried no TLS and no "
                    "identified email protocol has few applicable controls, which is "
                    "why its coverage may be low.",
                ),
            )
        )
        all_findings.extend(findings)
        all_units.extend(units)

    capture_score = compute_score(
        tuple(all_units),
        policy,
        scope=f"capture {result.capture.source_name}",
    )
    findings = tuple(all_findings)
    prioritised = prioritise(findings, sessions, policy)
    remediations = select_remediations(findings)

    tally = capture_score.tally.model_copy(
        update={"suppressed_duplicates": total_suppressed}
    )

    return AssessmentResult(
        policy=policy.info(reference_time),
        sessions=tuple(assessments),
        findings=findings,
        prioritised_findings=prioritised,
        remediations=remediations,
        posture_score=capture_score.model_copy(update={"tally": tally}),
        coverage=capture_score.coverage,
        tally=tally,
        rules_evaluated=total_results,
        sessions_assessed=len(assessments),
        limitations=_ENGINE_LIMITATIONS,
    )


def outcome_counts(assessment: AssessmentResult) -> dict[str, int]:
    """Rule outcomes across the capture, for summaries and tests."""
    counts = {outcome.value: 0 for outcome in RuleOutcome}
    for session in assessment.sessions:
        for item in session.rule_results:
            counts[item.outcome.value] += 1
    return counts
