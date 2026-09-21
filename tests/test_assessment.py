"""M4: security rules, scoring, prioritisation and remediation.

These tests are written against the *committed manifests*, whose expected
scores were computed by hand from the policy weights (see
``securemailscope.testing.assessment_fixtures``). Nothing here recomputes an
expectation using the code under test, so a change in the scoring
implementation fails a test instead of redefining the answer.

A large part of the file asserts that findings are **absent**. Asserting that
an expected finding exists proves the rule fires; only asserting that an
unsupported finding does not exist proves it does not fire on evidence that
never established the weakness. Both are needed, and the second is the one
that catches false positives.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from securemailscope.assessment.catalog import REMEDIATIONS, RULES
from securemailscope.assessment.policy import (
    DEFAULT_POLICY,
    SEVERITY_WEIGHTS,
)
from securemailscope.assessment.prioritization import PRIORITY_MATRIX
from securemailscope.assessment.scoring import SCORE_FORMULA
from securemailscope.config import AnalysisConfig
from securemailscope.models.analysis import REPORT_SCHEMA_VERSION, AnalysisResult
from securemailscope.models.assessment import (
    FindingSeverity,
    RuleOutcome,
    ScoreStatus,
)
from securemailscope.pipeline import analyze_capture
from securemailscope.reporting.json_report import result_to_dict

from .conftest import Fixture

#: Fixtures carrying hand-computed assessment manifests.
ASSESSMENT_FIXTURES = [
    "AA_tls10_static_rsa_multiple_findings",
    "AB_null_cipher_duplicate_evidence",
    "AC_rc4_weak_cipher",
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def assess(path: Path, **overrides: Any) -> AnalysisResult:
    config = AnalysisConfig(**overrides)
    result = analyze_capture(path, config=config)
    assert result.assessment is not None, "assessment block missing"
    return result


def rule_outcomes(result: AnalysisResult, index: int = 0) -> dict[str, Any]:
    session = result.assessment.sessions[index]
    return {item.rule_id: item for item in session.rule_results}


def finding_rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.assessment.findings}


def expected_for(fixture: Fixture, index: int) -> dict[str, Any]:
    for entry in fixture.expected_assessment:
        if entry["session_index"] == index:
            return entry
    raise AssertionError(f"{fixture.name} has no expectation for session {index}")


# ---------------------------------------------------------------------------
# 11. Fixture matrix -- manifests drive the assertions
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ASSESSMENT_FIXTURES, indirect=True)
def test_rule_outcomes_match_the_manifest(fixture: Fixture) -> None:
    result = assess(fixture.path)
    for entry in fixture.expected_assessment:
        actual = rule_outcomes(result, entry["session_index"])
        for expected in entry["rule_outcomes"]:
            rule_id = expected["rule_id"]
            assert rule_id in actual, f"{rule_id} produced no result"
            item = actual[rule_id]
            assert item.outcome.value == expected["outcome"], (
                f"{rule_id}: expected {expected['outcome']}, got {item.outcome.value}"
            )
            if expected.get("severity") is not None:
                assert item.severity.value == expected["severity"]
            if expected.get("counts_toward_score") is not None:
                assert item.counts_toward_score == expected["counts_toward_score"], (
                    f"{rule_id}: expected counts_toward_score="
                    f"{expected['counts_toward_score']}"
                )


@pytest.mark.parametrize("fixture", ASSESSMENT_FIXTURES, indirect=True)
def test_findings_match_the_manifest(fixture: Fixture) -> None:
    result = assess(fixture.path)
    prioritised = result.assessment.prioritised_findings
    for entry in fixture.expected_assessment:
        expected = entry["findings"]
        assert len(prioritised) == len(expected), (
            f"expected {len(expected)} findings, got "
            f"{[f.rule_id for f in prioritised]}"
        )
        for item, want in zip(prioritised, expected, strict=True):
            assert item.rule_id == want["rule_id"]
            assert item.severity.value == want["severity"]
            assert item.confidence.value == want["confidence"]
            assert item.priority.value == want["priority"]
            assert item.rank == want["rank"]


@pytest.mark.parametrize("fixture", ASSESSMENT_FIXTURES, indirect=True)
def test_unsupported_findings_are_absent(fixture: Fixture) -> None:
    """The manifest names every rule that must *not* produce a finding."""
    result = assess(fixture.path)
    raised = finding_rule_ids(result)
    for entry in fixture.expected_assessment:
        for rule_id in entry["forbidden_finding_rule_ids"]:
            assert rule_id not in raised, (
                f"{rule_id} raised a finding the evidence does not support"
            )


@pytest.mark.parametrize("fixture", ASSESSMENT_FIXTURES, indirect=True)
def test_score_arithmetic_matches_the_manifest(fixture: Fixture) -> None:
    result = assess(fixture.path)
    for entry in fixture.expected_assessment:
        score = result.assessment.sessions[entry["session_index"]].posture_score
        want = entry["score"]
        assert score.status.value == want["status"]
        assert score.score == want["score"]
        assert score.band.value == want["band"]
        assert score.tally.evaluated == want["evaluated_units"]
        assert score.tally.passed == want["passed_units"]
        assert score.tally.failed == want["failed_units"]
        assert score.tally.unknown == want["unknown_units"]
        assert score.weighted_evaluated == pytest.approx(want["weighted_evaluated"])
        assert score.weighted_deductions == pytest.approx(want["weighted_deductions"])
        assert score.coverage.weighted_applicable == pytest.approx(
            want["weighted_applicable"]
        )
        assert score.coverage.coverage_ratio == pytest.approx(
            want["coverage_ratio"], abs=5e-5
        )


@pytest.mark.parametrize("fixture", ASSESSMENT_FIXTURES, indirect=True)
def test_remediations_match_the_manifest(fixture: Fixture) -> None:
    result = assess(fixture.path)
    actual = [item.remediation_id for item in result.assessment.remediations]
    for entry in fixture.expected_assessment:
        assert actual == entry["remediation_ids"]


# ---------------------------------------------------------------------------
# 13. Rule correctness and evidence linkage
# ---------------------------------------------------------------------------
ALL_FIXTURE_NAMES = [
    *ASSESSMENT_FIXTURES,
    "T_A_tls12_complete_handshake",
    "T_C_tls12_static_rsa",
    "T_D_tls13_negotiation",
    "T_E_tls13_encrypted_certificate",
    "T_G_client_hello_only",
    "T_O_expired_certificate",
    "T_P_not_yet_valid_certificate",
    "P_B_smtp_starttls_rejected",
    "P_M_auth_before_tls",
    "A_complete_connection",
]


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_every_finding_cites_a_real_packet(fixture: Fixture) -> None:
    """No fabricated packet references.

    Every reference must fall inside the capture and carry the timestamp the
    capture actually recorded for that frame -- not a plausible-looking one.
    """
    result = assess(fixture.path)
    # The committed manifest recorded the timestamp of every frame when the
    # capture was generated. Checking against that, rather than against
    # anything the pipeline produced, is what makes this an independent test.
    recorded = fixture.manifest["expected_timestamps_ns"]
    packet_count = fixture.manifest["expected_packet_count"]
    for finding in result.assessment.findings:
        assert finding.evidence_refs, (
            f"{finding.rule_id} was promoted to a finding with no evidence"
        )
        for reference in finding.evidence_refs:
            assert 1 <= reference.packet_number <= packet_count, (
                f"{finding.rule_id} cites packet {reference.packet_number} in a "
                f"{packet_count}-packet capture"
            )
            assert reference.timestamp_ns == recorded[reference.packet_number - 1], (
                f"{finding.rule_id} cites packet {reference.packet_number} with a "
                "timestamp the capture does not record"
            )


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_every_rule_result_is_explained(fixture: Fixture) -> None:
    result = assess(fixture.path)
    for session in result.assessment.sessions:
        for item in session.rule_results:
            assert item.outcome in set(RuleOutcome), item.outcome
            assert item.rationale.strip(), f"{item.rule_id} has no rationale"
            definition = RULES[item.rule_id]
            assert definition.standards_references, (
                f"{item.rule_id} cites no standard"
            )
            if item.outcome is RuleOutcome.FAIL:
                assert item.evidence_refs, (
                    f"{item.rule_id} failed without citing evidence"
                )


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_only_failures_become_findings(fixture: Fixture) -> None:
    """A finding is a failed control, never an unavailable observation."""
    result = assess(fixture.path)
    outcomes = {
        (session.session_id, item.rule_id): item
        for session in result.assessment.sessions
        for item in session.rule_results
    }
    for finding in result.assessment.findings:
        item = outcomes[(finding.session_id, finding.rule_id)]
        assert item.outcome is RuleOutcome.FAIL
        assert item.counts_toward_score, (
            f"{finding.rule_id} was reported although it was de-duplicated away"
        )
        assert finding.evaluation_status is RuleOutcome.FAIL


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_finding_ids_are_stable_and_distinct(fixture: Fixture) -> None:
    first = assess(fixture.path)
    second = assess(fixture.path)
    ids_first = [finding.finding_id for finding in first.assessment.findings]
    ids_second = [finding.finding_id for finding in second.assessment.findings]
    assert ids_first == ids_second, "finding IDs changed between identical runs"
    assert len(set(ids_first)) == len(ids_first), "duplicate finding IDs"


def test_finding_ids_differ_across_captures(fixtures: dict[str, Fixture]) -> None:
    a = assess(fixtures["AB_null_cipher_duplicate_evidence"].path)
    b = assess(fixtures["AC_rc4_weak_cipher"].path)
    shared = finding_rule_ids(a) & finding_rule_ids(b)
    assert "TLS-KEX-001" in shared, "precondition: both fail the same rule"
    ids_a = {f.rule_id: f.finding_id for f in a.assessment.findings}
    ids_b = {f.rule_id: f.finding_id for f in b.assessment.findings}
    assert ids_a["TLS-KEX-001"] != ids_b["TLS-KEX-001"], (
        "the same rule in two different captures must not share a finding ID"
    )


def test_finding_id_changes_with_the_policy_version(fixtures: dict[str, Fixture]) -> None:
    path = fixtures["AC_rc4_weak_cipher"].path
    baseline = assess(path)
    # A policy whose minimum RSA size differs is a different policy, and its
    # findings must not be mistaken for the default policy's.
    shifted = DEFAULT_POLICY.with_overrides(minimum_rsa_bits=3072)
    from securemailscope.assessment.engine import assess_capture

    raw = analyze_capture(path, config=AnalysisConfig(assess_security=False))
    other = assess_capture(raw, policy=shifted)
    before = {f.rule_id: f.finding_id for f in baseline.assessment.findings}
    after = {f.rule_id: f.finding_id for f in other.findings}
    assert before.keys() == after.keys()
    for rule_id in before:
        assert before[rule_id] != after[rule_id], (
            "a finding ID must change when the policy that produced it changes"
        )


# ---------------------------------------------------------------------------
# 13. Scoring arithmetic and coverage
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_score_follows_the_published_formula(fixture: Fixture) -> None:
    """Recompute the score from the reported weights, independently."""
    result = assess(fixture.path)
    for scope in (
        result.assessment.posture_score,
        *(session.posture_score for session in result.assessment.sessions),
    ):
        assert scope.formula == SCORE_FORMULA
        if scope.status is ScoreStatus.SCORE_UNAVAILABLE:
            assert scope.score is None
            continue
        assert scope.weighted_evaluated > 0.0
        expected = round(
            100.0
            * (scope.weighted_evaluated - scope.weighted_deductions)
            / scope.weighted_evaluated
        )
        assert scope.score == expected, (
            f"{scope.scope}: reported {scope.score}, formula gives {expected}"
        )
        assert 0 <= scope.score <= 100


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_coverage_arithmetic_is_consistent(fixture: Fixture) -> None:
    result = assess(fixture.path)
    for scope in (
        result.assessment.posture_score,
        *(session.posture_score for session in result.assessment.sessions),
    ):
        coverage = scope.coverage
        assert coverage.weighted_evaluated <= coverage.weighted_applicable
        if coverage.weighted_applicable == 0.0:
            assert coverage.coverage_ratio == 0.0
        else:
            # Reported values are rounded to four decimal places for display;
            # the tolerance here is exactly that rounding and no more.
            assert coverage.coverage_ratio == pytest.approx(
                coverage.weighted_evaluated / coverage.weighted_applicable,
                abs=5e-5,
            )
        assert coverage.sufficient == (
            coverage.coverage_ratio >= coverage.minimum_required
        )
        # The evaluated weight the coverage reports must be the same number
        # the score divided by. Two different denominators would make the
        # score and the coverage describe different populations.
        assert coverage.weighted_evaluated == pytest.approx(scope.weighted_evaluated)


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_deductions_never_exceed_the_evaluated_weight(fixture: Fixture) -> None:
    """The floor of the score is 0, and it is reached by arithmetic, not clamping."""
    result = assess(fixture.path)
    for scope in (
        result.assessment.posture_score,
        *(session.posture_score for session in result.assessment.sessions),
    ):
        assert scope.weighted_deductions <= scope.weighted_evaluated + 1e-9


def test_unknown_evidence_cannot_improve_the_score(fixtures: dict[str, Fixture]) -> None:
    """Acceptance gate 8: an unavailable observation is not a pass.

    T_R presents a chain that verifies against the synthetic root. Running it
    without a trust store turns CERT-005 and CERT-006 from PASS into UNKNOWN.
    The score must not rise: gaining evidence that something is fine can only
    help, and losing it must never help.
    """
    path = fixtures["T_R_valid_trusted_chain"].path
    import tempfile

    from securemailscope.testing.tls_fixtures import _ca

    with tempfile.TemporaryDirectory() as directory:
        store = Path(directory) / "root.pem"
        store.write_bytes(_ca().root_pem)
        informed = assess(
            path,
            trust_store_path=store,
            expected_server_identity="mail.example.invalid",
        )
    blind = assess(path)

    informed_outcomes = rule_outcomes(informed)
    blind_outcomes = rule_outcomes(blind)
    assert informed_outcomes["CERT-005"].outcome is RuleOutcome.PASS
    assert blind_outcomes["CERT-005"].outcome is RuleOutcome.UNKNOWN

    informed_score = informed.assessment.posture_score
    blind_score = blind.assessment.posture_score
    assert blind_score.coverage.coverage_ratio < informed_score.coverage.coverage_ratio
    if blind_score.score is not None and informed_score.score is not None:
        assert blind_score.score <= informed_score.score, (
            "removing evidence that a control passed raised the score"
        )


def test_insufficient_evidence_produces_no_score(fixtures: dict[str, Fixture]) -> None:
    """Acceptance gate 9: below the coverage floor, refuse to score."""
    result = assess(fixtures["T_G_client_hello_only"].path)
    score = result.assessment.posture_score
    assert score.status is ScoreStatus.SCORE_UNAVAILABLE
    assert score.score is None
    assert not score.coverage.sufficient
    assert score.explanation.strip()


def test_a_session_with_nothing_to_assess_is_not_scored(
    fixtures: dict[str, Fixture],
) -> None:
    """A plain TCP session has no applicable controls, and no score."""
    result = assess(fixtures["A_complete_connection"].path)
    score = result.assessment.posture_score
    assert score.status is ScoreStatus.SCORE_UNAVAILABLE
    assert score.score is None
    assert result.assessment.findings == ()


def test_more_failures_never_raise_the_score(fixtures: dict[str, Fixture]) -> None:
    """Monotonicity, checked across two fixtures that differ by one failure.

    AC (RC4) and AB (NULL) have identical control populations; AB's cipher
    failure is the more severe of the two. The more severe failure must not
    produce the higher score.
    """
    rc4 = assess(fixtures["AC_rc4_weak_cipher"].path).assessment.posture_score
    null = assess(fixtures["AB_null_cipher_duplicate_evidence"].path).assessment.posture_score
    assert rc4.score is not None and null.score is not None
    assert null.weighted_deductions > rc4.weighted_deductions
    assert null.score < rc4.score


def test_disabling_a_rule_removes_it_from_both_sides(
    fixtures: dict[str, Fixture],
) -> None:
    """A disabled rule leaves the population entirely, not just the numerator."""
    path = fixtures["AC_rc4_weak_cipher"].path
    baseline = assess(path).assessment.posture_score
    without = assess(path, disabled_rules="TLS-KEX-001").assessment.posture_score
    assert "TLS-KEX-001" not in {
        item.rule_id
        for session in assess(path, disabled_rules="TLS-KEX-001").assessment.sessions
        for item in session.rule_results
    }
    assert without.weighted_evaluated < baseline.weighted_evaluated
    assert without.weighted_deductions < baseline.weighted_deductions


def test_severity_weights_are_reported_not_hidden(
    fixtures: dict[str, Fixture],
) -> None:
    """Every deduction names its group, weight and rule, so it can be checked."""
    result = assess(fixtures["AA_tls10_static_rsa_multiple_findings"].path)
    score = result.assessment.posture_score
    assert len(score.deduction_detail) == score.tally.failed
    total = 0.0
    for line in score.deduction_detail:
        assert ": -" in line, line
        total += float(line.split(": -", 1)[1].split(" ", 1)[0])
    assert total == pytest.approx(score.weighted_deductions)


# ---------------------------------------------------------------------------
# 13. Duplicate suppression
# ---------------------------------------------------------------------------
def test_one_weakness_is_counted_once(fixtures: dict[str, Fixture]) -> None:
    """AB fails two cipher rules for one setting, and is charged for one."""
    result = assess(fixtures["AB_null_cipher_duplicate_evidence"].path)
    session = result.assessment.sessions[0]
    failed = [
        item for item in session.rule_results if item.outcome is RuleOutcome.FAIL
    ]
    cipher_failures = [
        item for item in failed if item.dedup_group == "NEGOTIATED_CIPHER_SUITE"
    ]
    assert len(cipher_failures) == 2, [item.rule_id for item in cipher_failures]
    counting = [item for item in cipher_failures if item.counts_toward_score]
    assert len(counting) == 1
    assert counting[0].rule_id == "TLS-CIPHER-001", "the most severe must carry it"
    assert counting[0].severity is FindingSeverity.CRITICAL
    assert session.posture_score.tally.suppressed_duplicates == 1
    assert finding_rule_ids(result) & {"TLS-CIPHER-005"} == set()


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_each_dedup_group_contributes_at_most_one_deduction(
    fixture: Fixture,
) -> None:
    result = assess(fixture.path)
    for session in result.assessment.sessions:
        charged: list[str] = [
            item.dedup_group
            for item in session.rule_results
            if item.outcome is RuleOutcome.FAIL and item.counts_toward_score
        ]
        assert len(charged) == len(set(charged)), (
            f"a de-duplication group was charged twice: {charged}"
        )


# ---------------------------------------------------------------------------
# 13. Deterministic prioritisation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_prioritisation_is_a_total_order(fixture: Fixture) -> None:
    result = assess(fixture.path)
    prioritised = result.assessment.prioritised_findings
    assert [item.rank for item in prioritised] == list(
        range(1, len(prioritised) + 1)
    ), "ranks must be dense and start at 1"
    assert len({item.finding_id for item in prioritised}) == len(prioritised)
    assert {item.finding_id for item in prioritised} == {
        finding.finding_id for finding in result.assessment.findings
    }, "every finding must be prioritised exactly once"


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_prioritisation_is_stable_across_runs(fixture: Fixture) -> None:
    runs = [
        [
            (item.rank, item.finding_id)
            for item in assess(fixture.path).assessment.prioritised_findings
        ]
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_priority_comes_from_the_matrix_not_a_product(fixture: Fixture) -> None:
    """Severity and confidence are looked up, never multiplied.

    A percentage confidence multiplied into a severity would make a CRITICAL
    finding seen with LOW confidence look like a MEDIUM one. The matrix keeps
    the two axes separate and the lookup checkable.
    """
    result = assess(fixture.path)
    for item in result.assessment.prioritised_findings:
        assert item.priority is PRIORITY_MATRIX[(item.severity, item.confidence)]


@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_more_severe_findings_are_never_ranked_lower(fixture: Fixture) -> None:
    order = list(FindingSeverity)
    prioritised = assess(fixture.path).assessment.prioritised_findings
    ranks = [order.index(item.severity) for item in prioritised]
    assert ranks == sorted(ranks), (
        f"severity order violated: {[(i.rule_id, i.severity.value) for i in prioritised]}"
    )


def test_asset_criticality_is_never_invented(fixtures: dict[str, Fixture]) -> None:
    """Criticality is operator-supplied. Absent, it stays absent."""
    result = assess(fixtures["AA_tls10_static_rsa_multiple_findings"].path)
    assert DEFAULT_POLICY.asset_criticality == {}
    for item in result.assessment.prioritised_findings:
        assert item.asset_criticality is None


# ---------------------------------------------------------------------------
# 13. Remediation mapping
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fixture", ALL_FIXTURE_NAMES, indirect=True)
def test_remediations_answer_findings_that_exist(fixture: Fixture) -> None:
    """Advice is produced for what failed, never for what might have."""
    result = assess(fixture.path)
    raised = finding_rule_ids(result)
    offered = {item.remediation_id for item in result.assessment.remediations}
    expected: set[str] = set()
    for rule_id in raised:
        expected.update(RULES[rule_id].remediation_ids)
    assert offered == expected, (
        f"offered {sorted(offered)} for findings {sorted(raised)}"
    )
    for item in result.assessment.remediations:
        assert item.remediation_id in REMEDIATIONS
        assert item.recommended_action.strip()
        assert item.validation_steps, f"{item.remediation_id} has no validation steps"


def test_no_remediation_without_a_finding(fixtures: dict[str, Fixture]) -> None:
    result = assess(fixtures["T_R_valid_trusted_chain"].path)
    if not result.assessment.findings:
        assert result.assessment.remediations == ()


def test_the_catalogue_has_no_dangling_references() -> None:
    for rule in RULES.values():
        for remediation_id in rule.remediation_ids:
            assert remediation_id in REMEDIATIONS, (
                f"{rule.rule_id} points at unknown remediation {remediation_id}"
            )
    reachable = {r for rule in RULES.values() for r in rule.remediation_ids}
    assert set(REMEDIATIONS) == reachable, (
        f"unreachable remediations: {sorted(set(REMEDIATIONS) - reachable)}"
    )


def test_every_rule_severity_has_a_weight() -> None:
    for rule in RULES.values():
        assert rule.severity in SEVERITY_WEIGHTS
        assert DEFAULT_POLICY.weight_for(rule.rule_id, rule.severity) == (
            SEVERITY_WEIGHTS[rule.severity]
        )


# ---------------------------------------------------------------------------
# 10. False-positive prevention
#
# Each case below asserts that findings the evidence does not support are
# ABSENT. They exist because the dangerous failure mode of an assessment tool
# is not missing a weakness -- it is inventing one, which costs an operator
# real time chasing a configuration that was never wrong.
# ---------------------------------------------------------------------------
def outcome_of(result: AnalysisResult, rule_id: str, index: int = 0) -> RuleOutcome:
    return rule_outcomes(result, index)[rule_id].outcome


def test_tls13_encrypted_certificate_is_not_a_certificate_failure(
    fixtures: dict[str, Fixture],
) -> None:
    """TLS 1.3 encrypts the Certificate message. Not seeing it is not a fault."""
    result = assess(fixtures["T_E_tls13_encrypted_certificate"].path)
    raised = finding_rule_ids(result)
    for rule_id in ("CERT-001", "CERT-002", "CERT-003", "CERT-004", "CERT-005",
                    "CERT-006", "CERT-007"):
        assert rule_id not in raised, (
            f"{rule_id} fired on a certificate that was never visible"
        )
        assert outcome_of(result, rule_id) in {
            RuleOutcome.UNKNOWN,
            RuleOutcome.NOT_APPLICABLE,
        }
    # And the version it did observe is correctly assessed as modern.
    assert outcome_of(result, "TLS-PROTO-001") is RuleOutcome.PASS


def test_missing_client_hello_yields_unknown_not_findings(
    fixtures: dict[str, Fixture],
) -> None:
    result = assess(fixtures["T_H_server_hello_only"].path)
    assert outcome_of(result, "TLS-PROTO-002") is RuleOutcome.UNKNOWN
    assert "TLS-PROTO-002" not in finding_rule_ids(result)


def test_missing_server_hello_never_judges_the_negotiation(
    fixtures: dict[str, Fixture],
) -> None:
    """Offered suites are capability. Nothing was negotiated, so nothing failed."""
    result = assess(fixtures["T_G_client_hello_only"].path)
    raised = finding_rule_ids(result)
    for rule_id in ("TLS-PROTO-001", "TLS-CIPHER-001", "TLS-CIPHER-003",
                    "TLS-CIPHER-005", "TLS-KEX-001"):
        assert rule_id not in raised, f"{rule_id} judged a negotiation that never happened"
        assert outcome_of(result, rule_id) is RuleOutcome.UNKNOWN


def test_truncated_capture_does_not_manufacture_findings(
    fixtures: dict[str, Fixture],
) -> None:
    for name in ("T_L_truncated_record", "I1_truncated_capture", "O_snapshot_truncated"):
        result = assess(fixtures[name].path)
        for finding in result.assessment.findings:
            assert finding.evidence_refs, (
                f"{name}: {finding.rule_id} has no evidence behind it"
            )
            assert finding.rule_id not in {"TLS-CIPHER-001", "TLS-CIPHER-003"}, (
                f"{name}: a cipher verdict was reached from truncated bytes"
            )


def test_unknown_cipher_suite_is_not_assumed_weak(
    fixtures: dict[str, Fixture],
) -> None:
    """A suite this build does not recognise may be strong. UNKNOWN, not FAIL."""
    from securemailscope.testing.assessment_fixtures import _handshake
    from securemailscope.testing.writers import write_pcap

    # 0xFAFA is not assigned in the IANA registry this build carries.
    dialogue, _ = _handshake(legacy_version=0x0303, cipher_suite=0xFAFA, serial=900)
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "unknown_suite.pcap"
        path.write_bytes(write_pcap(dialogue.packets))
        result = assess(path)

    raised = finding_rule_ids(result)
    for rule_id in ("TLS-CIPHER-001", "TLS-CIPHER-002", "TLS-CIPHER-003",
                    "TLS-CIPHER-004", "TLS-CIPHER-005"):
        assert outcome_of(result, rule_id) is RuleOutcome.UNKNOWN, (
            f"{rule_id} reached a verdict about an unrecognised suite"
        )
        assert rule_id not in raised
    # Not being in *our* registry is a gap in this build, not a property of
    # the transport, so it is UNKNOWN and produces no finding at all.
    assert outcome_of(result, "TLS-CIPHER-006") is RuleOutcome.UNKNOWN
    assert "TLS-CIPHER-006" not in raised
    item = rule_outcomes(result)["TLS-CIPHER-006"]
    assert item.limitations, "an unrecognised suite must carry a stated limitation"
    # Nothing at all should be reported about this session's cipher.
    assert not any(f.rule_id.startswith("TLS-CIPHER") for f in result.assessment.findings)


def test_unknown_key_exchange_group_is_not_a_forward_secrecy_failure(
    fixtures: dict[str, Fixture],
) -> None:
    """T_HRR carries a group we may not name. That is not 'no forward secrecy'."""
    result = assess(fixtures["T_HRR_hello_retry_request"].path)
    assert "TLS-KEX-001" not in finding_rule_ids(result)
    assert outcome_of(result, "TLS-KEX-001") in {
        RuleOutcome.PASS,
        RuleOutcome.UNKNOWN,
    }


def test_incomplete_chain_without_a_trust_store_is_unknown(
    fixtures: dict[str, Fixture],
) -> None:
    """Seeing one certificate is not seeing a broken chain."""
    result = assess(fixtures["T_S_incomplete_chain"].path)
    assert outcome_of(result, "CERT-005") is RuleOutcome.UNKNOWN
    assert "CERT-005" not in finding_rule_ids(result)


def test_missing_trust_store_is_never_a_chain_failure(
    fixtures: dict[str, Fixture],
) -> None:
    for name in ("T_R_valid_trusted_chain", "T_Q_self_signed_certificate",
                 "T_A_tls12_complete_handshake"):
        result = assess(fixtures[name].path)
        assert outcome_of(result, "CERT-005") is RuleOutcome.UNKNOWN, name
        assert "CERT-005" not in finding_rule_ids(result), name


def test_missing_reference_hostname_is_never_a_mismatch(
    fixtures: dict[str, Fixture],
) -> None:
    """No expected identity was supplied, so no identity can be wrong."""
    for name in ("T_T_hostname_scenarios", "T_U_unknown_reference_identity",
                 "T_A_tls12_complete_handshake"):
        result = assess(fixtures[name].path)
        for index in range(len(result.assessment.sessions)):
            assert outcome_of(result, "CERT-006", index) is RuleOutcome.UNKNOWN, name
        assert "CERT-006" not in finding_rule_ids(result), name


def test_tls13_psk_resumption_is_not_a_forward_secrecy_failure(
    fixtures: dict[str, Fixture],
) -> None:
    """A resumed session's key schedule is not visible as a missing key share."""
    result = assess(fixtures["T_F_tls13_resumption"].path)
    assert "TLS-KEX-001" not in finding_rule_ids(result)
    assert outcome_of(result, "TLS-KEX-001") in {
        RuleOutcome.PASS,
        RuleOutcome.UNKNOWN,
    }
    assert outcome_of(result, "TLS-PROTO-001") is RuleOutcome.PASS


def test_rejected_starttls_is_reported_as_configuration_not_attack(
    fixtures: dict[str, Fixture],
) -> None:
    """A refused upgrade is a server that does not offer TLS, not a stripping attack."""
    for name in ("P_B_smtp_starttls_rejected", "P_G_pop3_stls_rejected"):
        result = assess(fixtures[name].path)
        assert "MAIL-003" in finding_rule_ids(result), name
        finding = next(f for f in result.assessment.findings if f.rule_id == "MAIL-003")
        combined = " ".join(
            (finding.description, finding.technical_impact, *finding.limitations)
        ).lower()
        # No accusation: the capture shows a refusal, which is equally what a
        # server with no TLS configured does.
        for phrase in (
            "an attacker",
            "is under attack",
            "indicates an attack",
            "suggests an attack",
            "stripping attack",
            "downgrade attack",
            "was intercepted",
            "malicious",
            "adversary",
        ):
            assert phrase not in combined, (
                f"{name}: a refused upgrade was described using {phrase!r}"
            )
        # And the alternative explanation is stated, not left to the reader.
        assert "not evidence of an attack" in combined or "no attack is inferred" in combined, (
            f"{name}: the finding does not state that no attack is inferred"
        )


def test_authentication_is_detected_without_disclosing_credentials(
    fixtures: dict[str, Fixture],
) -> None:
    """MAIL-001 fires on plaintext AUTH, and carries no credential material."""
    fixture = fixtures["P_M_auth_before_tls"]
    result = assess(fixture.path)
    assert "MAIL-001" in finding_rule_ids(result)
    serialised = json.dumps(result_to_dict(result))
    for secret in fixture.manifest.get("forbidden_strings", []):
        assert secret not in serialised, (
            f"credential material {secret!r} reached the assessment output"
        )


def test_port_hints_never_produce_email_transport_findings(
    fixtures: dict[str, Fixture],
) -> None:
    """Implicit TLS on port 993 is a hint. The mail rules must stand down."""
    for name in ("T_V_implicit_tls_on_email_port", "AB_null_cipher_duplicate_evidence"):
        result = assess(fixtures[name].path)
        raised = finding_rule_ids(result)
        for rule_id in ("MAIL-001", "MAIL-002", "MAIL-003", "MAIL-004",
                        "MAIL-005", "MAIL-006"):
            assert outcome_of(result, rule_id) is RuleOutcome.NOT_APPLICABLE, (
                f"{name}: {rule_id} was evaluated on a port hint"
            )
            assert rule_id not in raised, name


# ---------------------------------------------------------------------------
# 13. Schema compatibility, redaction, CLI and determinism
# ---------------------------------------------------------------------------
def test_schema_is_additive_over_m1_to_m3(fixtures: dict[str, Fixture]) -> None:
    """M4 adds blocks; it never replaces forensic evidence with a label."""
    result = assess(fixtures["AA_tls10_static_rsa_multiple_findings"].path)
    document = result_to_dict(result)
    assert document["tool"]["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert REPORT_SCHEMA_VERSION == "1.3.0"
    # M1-M3 blocks survive untouched.
    for key in ("capture", "sessions", "protocols", "tls", "inventory"):
        assert key in document, f"M1-M3 block {key} disappeared"
    session = document["sessions"][0]
    for key in ("client_to_server", "server_to_client", "flow", "handshake"):
        assert key in session
    assert document["tls"][0]["cipher_suite"]["selected"] is not None
    # M4 additions.
    assessment = document["assessment"]
    for key in (
        "policy",
        "sessions",
        "findings",
        "prioritised_findings",
        "remediations",
        "posture_score",
        "coverage",
        "tally",
    ):
        assert key in assessment, f"M4 block {key} missing"
    assert assessment["sessions"][0]["rule_results"]


def test_assessment_can_be_omitted_without_losing_forensics(
    fixtures: dict[str, Fixture],
) -> None:
    path = fixtures["AA_tls10_static_rsa_multiple_findings"].path
    result = analyze_capture(path, config=AnalysisConfig(assess_security=False))
    assert result.assessment is None
    document = result_to_dict(result)
    assert document["tls"][0]["cipher_suite"]["selected"] is not None
    assert document["tool"]["report_schema_version"] == REPORT_SCHEMA_VERSION


def test_rule_results_can_be_dropped_while_findings_remain(
    fixtures: dict[str, Fixture],
) -> None:
    result = assess(fixtures["AA_tls10_static_rsa_multiple_findings"].path)
    document = result_to_dict(result, include_rule_results=False)
    assert "rule_results" not in document["assessment"]["sessions"][0]
    assert document["assessment"]["findings"], "findings must survive"
    assert document["assessment"]["posture_score"]["score"] == 59


@pytest.mark.parametrize(
    "fixture",
    [
        "P_M_auth_before_tls",
        "P_N_no_plaintext_after_upgrade",
        "P_P_data_body_fake_starttls",
        "P_Q_imap_literal_fake_commands",
        "P_R_pop3_message_fake_stls",
    ],
    indirect=True,
)
def test_no_credential_material_reaches_the_assessment(fixture: Fixture) -> None:
    """Redaction must hold through the new layer, not only the old ones."""
    result = assess(fixture.path)
    assert result.assessment is not None
    serialised = json.dumps(
        result_to_dict(result)["assessment"], ensure_ascii=False
    )
    forbidden = fixture.manifest.get("forbidden_strings", [])
    assert forbidden, f"{fixture.name} declares nothing to redact"
    for secret in forbidden:
        assert secret not in serialised, (
            f"{secret!r} appears in the assessment output"
        )


def test_the_policy_is_reported_with_its_own_caveats(
    fixtures: dict[str, Fixture],
) -> None:
    """The score must never be presented as an industry-validated measure."""
    result = assess(fixtures["AC_rc4_weak_cipher"].path)
    policy = result.assessment.policy
    assert policy.policy_id and policy.policy_version and policy.policy_fingerprint
    joined = " ".join(policy.limitations).lower()
    assert "not validated industry benchmarks" in joined or "project-defined" in joined
    score = result.assessment.posture_score
    assert score.policy_id == policy.policy_id
    assert score.policy_version == policy.policy_version
    assert score.limitations, "the score must carry its limitations"


def test_overrides_are_recorded_and_change_the_fingerprint(
    fixtures: dict[str, Fixture],
) -> None:
    path = fixtures["AC_rc4_weak_cipher"].path
    baseline = assess(path).assessment.policy
    changed = assess(path, minimum_score_coverage_percent=80).assessment.policy
    assert baseline.overrides_applied == ()
    assert changed.overrides_applied, "an override must be recorded in the report"
    assert changed.policy_fingerprint != baseline.policy_fingerprint


def test_repeated_analysis_is_byte_identical(fixtures: dict[str, Fixture]) -> None:
    """Same capture, same policy, same bytes -- excluding run metadata.

    ``tool.analysis_started_at`` and the run duration are the documented
    nondeterministic fields; everything else must match exactly.
    """
    path = fixtures["AA_tls10_static_rsa_multiple_findings"].path
    documents = []
    for _ in range(3):
        document = result_to_dict(assess(path))
        document.pop("tool", None)
        document.pop("run", None)
        documents.append(json.dumps(document, sort_keys=True, default=str))
    assert documents[0] == documents[1] == documents[2]


def test_cli_reports_the_assessment_end_to_end(
    fixtures: dict[str, Fixture], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real generated capture, through the real entry point."""
    from securemailscope.cli import main

    destination = tmp_path / "report.json"
    exit_code = main(
        [
            "analyze",
            str(fixtures["AA_tls10_static_rsa_multiple_findings"].path),
            "-o",
            str(destination),
        ]
    )
    assert exit_code == 0
    document = json.loads(destination.read_text(encoding="utf-8"))
    assessment = document["assessment"]
    assert assessment["posture_score"]["score"] == 59
    assert assessment["posture_score"]["band"] == "WEAK"
    assert [f["rule_id"] for f in assessment["prioritised_findings"]] == [
        "TLS-KEX-001",
        "TLS-PROTO-001",
        "TLS-CIPHER-005",
        "TLS-PROTO-002",
    ]
    assert [r["remediation_id"] for r in assessment["remediations"]] == [
        "REM-TLS-FS",
        "REM-TLS-VERSION",
        "REM-TLS-CIPHER",
    ]
    # The human-readable summary goes to stderr; the report goes to the file.
    printed = capsys.readouterr().err
    assert "TLS-KEX-001" in printed
    assert "59" in printed


def test_cli_can_suppress_the_assessment(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    from securemailscope.cli import main

    destination = tmp_path / "forensics-only.json"
    exit_code = main(
        [
            "analyze",
            str(fixtures["AA_tls10_static_rsa_multiple_findings"].path),
            "-o",
            str(destination),
            "--no-assessment",
        ]
    )
    assert exit_code == 0
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document.get("assessment") is None
    assert document["tls"], "forensic output must survive"


def test_the_generated_policy_documents_are_current() -> None:
    """A policy document that disagrees with the engine is worse than none.

    The reader would check the wrong thresholds and conclude the wrong thing,
    so the committed files are asserted to match what the generator produces.
    """
    import subprocess
    import sys

    repository = Path(__file__).resolve().parent.parent
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(repository / "scripts" / "generate_policy_docs.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_the_requirements_matrix_summary_is_arithmetically_correct() -> None:
    """A status table that miscounts itself is the easiest doc bug to ship."""
    import re

    text = (Path(__file__).resolve().parent.parent / "docs" / "requirements-matrix.md").read_text(
        encoding="utf-8"
    )
    body, summary = text.split("## Summary", 1)
    counted = {"IMPLEMENTED": 0, "PARTIAL": 0, "NOT IMPLEMENTED": 0}
    for line in body.splitlines():
        if not line.startswith("| ") or "|---" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 7:
            continue
        match = re.search(r"\*\*(NOT IMPLEMENTED|IMPLEMENTED|PARTIAL)\*\*", cells[-1])
        if match:
            counted[match.group(1)] += 1

    for status, number in counted.items():
        pattern = rf"\|\s*{re.escape(status)}\s*\|\s*(\d+)\s*\|"
        found = re.search(pattern, summary)
        assert found, f"summary does not report a count for {status}"
        assert int(found.group(1)) == number, (
            f"summary claims {found.group(1)} {status} rows; the table has {number}"
        )
    total = re.search(r"Total requirements tracked\*\*\s*\|\s*\*\*(\d+)\*\*", summary)
    assert total and int(total.group(1)) == sum(counted.values())
