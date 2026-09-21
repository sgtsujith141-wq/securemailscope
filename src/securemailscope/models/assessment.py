"""Security assessment contracts (M4).

The assessment layer turns forensic *observations* into *judgements*. That is
a different kind of statement, and these models keep the difference visible:

* **A rule outcome is not a finding.**  Every applicable rule produces a
  :class:`RuleResult` -- including the ones that passed and the ones that
  could not be evaluated -- so a report shows what was checked, not only what
  went wrong.  Only ``FAIL`` results become :class:`SecurityFinding` entries.
* **UNKNOWN is never PASS.**  A rule that could not be evaluated says so, and
  the score arithmetic excludes it from both sides of the fraction rather
  than treating absence as either compliance or violation.
* **Severity, confidence and priority are three separate axes.**  Severity is
  how bad the condition is under the policy; confidence is how sure we are the
  condition was observed; priority is the ordering that follows from both plus
  any operator-supplied asset criticality.  They are never multiplied into a
  single number and presented as a probability.
* **The score is a project-defined metric.**  It describes the evidence that
  was analysed, under a named policy version, and nothing wider.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import PacketReference

__all__ = [
    "RuleOutcome",
    "FindingSeverity",
    "Confidence",
    "RuleCategory",
    "AssessmentMode",
    "StandardsReference",
    "RuleDefinition",
    "ObservedValue",
    "RuleResult",
    "SecurityFinding",
    "Remediation",
    "PrioritisedFinding",
    "PriorityBand",
    "ScoreStatus",
    "ScoreBand",
    "ControlTally",
    "AssessmentCoverage",
    "PostureScore",
    "PolicyInfo",
    "SessionAssessment",
    "AssessmentResult",
]


class RuleOutcome(StrEnum):
    """What a rule concluded for one session.

    ``UNKNOWN`` is load-bearing: it is the honest answer whenever the capture
    does not contain what the rule needs, and it is never silently promoted to
    ``PASS``.
    """

    #: The condition the rule tests for was observed.
    FAIL = "FAIL"
    #: Enough evidence was present to evaluate the condition, and it held.
    PASS = "PASS"  # noqa: S105 - an outcome name, not a secret
    #: The rule applies, but the available evidence cannot establish a result.
    UNKNOWN = "UNKNOWN"
    #: The rule does not apply to this session at all.
    NOT_APPLICABLE = "NOT_APPLICABLE"


class FindingSeverity(StrEnum):
    """How serious the condition is *under the active policy*.

    Named ``FindingSeverity`` to keep it distinct from
    :class:`securemailscope.models.evidence.Severity`, which grades parser
    diagnostics rather than security conditions.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(StrEnum):
    """How sure we are that the condition was actually observed.

    This grades the *evidence*, not the seriousness. A CRITICAL finding with
    LOW confidence stays CRITICAL; the two are reported side by side and are
    never combined into a single number.
    """

    #: Every supporting observation was OBSERVED, from a complete record.
    CONFIRMED = "CONFIRMED"
    #: At least one supporting observation was INFERRED.
    PROBABLE = "PROBABLE"
    #: The session was partial, indeterminate, or identified only by port.
    LOW = "LOW"


class RuleCategory(StrEnum):
    TLS_PROTOCOL = "TLS_PROTOCOL"
    CIPHER_SUITE = "CIPHER_SUITE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CERTIFICATE = "CERTIFICATE"
    EMAIL_TRANSPORT = "EMAIL_TRANSPORT"


class AssessmentMode(StrEnum):
    #: Certificate validity judged at the capture's own timestamp. Default.
    HISTORICAL = "HISTORICAL"
    #: Judged against the clock at analysis time. Must be requested.
    CURRENT_TIME = "CURRENT_TIME"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class StandardsReference(_Frozen):
    """A citation a reader can look up and check."""

    document: str = Field(description="e.g. 'RFC 9325' or 'NIST SP 800-52 Rev. 2'.")
    section: str | None = None
    title: str
    published: str = Field(description="Publication date of the cited document.")
    #: Whether the cited text is a protocol requirement, a recommendation, or
    #: this project's own policy choice. Conflating the three is how "NIST
    #: says you must" claims get made about things NIST merely recommends.
    kind: str = Field(
        description="'PROTOCOL_REQUIREMENT', 'STANDARDS_RECOMMENDATION', "
        "'PROJECT_POLICY' or 'ENVIRONMENT_CHOICE'."
    )


class RuleDefinition(_Frozen):
    """Static metadata for one security rule."""

    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: FindingSeverity
    #: What must be present for the rule to produce anything but UNKNOWN.
    required_evidence: tuple[str, ...]
    #: When the rule applies at all.
    applicable_when: str
    standards_references: tuple[StandardsReference, ...] = ()
    remediation_ids: tuple[str, ...] = ()
    #: Rules sharing a group describe one underlying weakness. Scoring counts
    #: the group once, so a NULL-cipher session is not penalised twice for
    #: also being off the approved list.
    dedup_group: str
    technical_impact: str = Field(
        description="What an attacker gains, stated without asserting intent."
    )


class ObservedValue(_Frozen):
    """A concrete value the rule read out of the forensic observations."""

    name: str
    value: str
    source: str = Field(description="Which observation field this came from.")


class RuleResult(_Frozen):
    """One rule's conclusion for one session, with its evidence."""

    rule_id: str
    outcome: RuleOutcome
    severity: FindingSeverity
    confidence: Confidence
    category: RuleCategory
    capture_id: str
    session_id: str
    policy_id: str
    policy_version: str
    rationale: str = Field(description="Engine-authored; why this outcome was reached.")
    observed_values: tuple[ObservedValue, ...] = ()
    evidence_refs: tuple[PacketReference, ...] = ()
    stream_offsets: tuple[int, ...] = ()
    limitations: tuple[str, ...] = ()
    dedup_group: str
    #: False when another rule in the same dedup group carried the finding.
    counts_toward_score: bool = True


class SecurityFinding(_Frozen):
    """A FAIL rule result promoted to a reportable finding.

    ``finding_id`` is derived from the canonical assessment inputs, so the
    same capture assessed under the same policy always produces the same
    identifiers and two reports can be diffed. The policy fingerprint is one
    of those inputs: a run under changed criteria produces different
    identifiers rather than colliding with the published policy's.
    """

    finding_id: str
    rule_id: str
    policy_id: str
    policy_version: str
    #: The exact criteria this finding was reached under; part of finding_id.
    policy_fingerprint: str
    title: str
    description: str
    severity: FindingSeverity
    evaluation_status: RuleOutcome
    confidence: Confidence
    category: RuleCategory
    capture_id: str
    session_id: str
    evidence_refs: tuple[PacketReference, ...] = ()
    stream_offsets: tuple[int, ...] = ()
    observed_values: tuple[ObservedValue, ...] = ()
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    technical_impact: str
    standards_references: tuple[StandardsReference, ...] = ()
    limitations: tuple[str, ...] = ()
    remediation_ids: tuple[str, ...] = ()


class Remediation(_Frozen):
    """A vendor-neutral corrective action tied to specific rules."""

    remediation_id: str
    related_rule_ids: tuple[str, ...]
    title: str
    technical_explanation: str
    recommended_action: str
    expected_security_effect: str
    operational_considerations: str
    validation_steps: tuple[str, ...]
    standards_references: tuple[StandardsReference, ...] = ()


class PriorityBand(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class PrioritisedFinding(_Frozen):
    """A finding with its ordering position and the reason for it."""

    finding_id: str
    rule_id: str
    rank: int = Field(ge=1)
    priority: PriorityBand
    severity: FindingSeverity
    confidence: Confidence
    #: Distinct sessions in which this rule failed.
    observed_session_count: int = Field(ge=1)
    asset_criticality: str | None = Field(
        default=None,
        description="Only set when the operator explicitly supplied one for this "
        "endpoint. Never inferred.",
    )
    explanation: str
    sort_key: tuple[int, int, int, int, str, str] = Field(
        description="The exact tuple used to order this entry, so the ordering is "
        "reproducible and auditable."
    )


class ScoreStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    #: Not enough evaluable evidence to produce a number honestly.
    SCORE_UNAVAILABLE = "SCORE_UNAVAILABLE"


class ScoreBand(StrEnum):
    """Qualitative band. Project-defined thresholds, not an industry standard."""

    STRONG = "STRONG"
    ADEQUATE = "ADEQUATE"
    WEAK = "WEAK"
    CRITICAL = "CRITICAL"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ControlTally(_Frozen):
    """Counts of scoring units by outcome. Units, not raw rules."""

    total_applicable: int = Field(default=0, ge=0)
    evaluated: int = Field(default=0, ge=0)
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)
    not_applicable: int = Field(default=0, ge=0)
    suppressed_duplicates: int = Field(
        default=0, ge=0, description="Rule results merged into another unit."
    )


class AssessmentCoverage(_Frozen):
    """How much of the applicable policy the evidence actually let us check.

    Coverage and posture are separate measurements: a perfect score over 20%
    coverage is a statement about very little.
    """

    weighted_applicable: float = Field(ge=0.0)
    weighted_evaluated: float = Field(ge=0.0)
    coverage_ratio: float = Field(ge=0.0, le=1.0)
    minimum_required: float = Field(ge=0.0, le=1.0)
    sufficient: bool
    explanation: str


class PostureScore(_Frozen):
    """The deterministic posture score and the arithmetic behind it."""

    status: ScoreStatus
    score: int | None = Field(default=None, ge=0, le=100)
    band: ScoreBand = ScoreBand.NOT_AVAILABLE
    tally: ControlTally
    coverage: AssessmentCoverage
    weighted_evaluated: float = Field(default=0.0, ge=0.0)
    weighted_deductions: float = Field(default=0.0, ge=0.0)
    deduction_detail: tuple[str, ...] = Field(
        default=(), description="One line per failed unit: group, weight, rule."
    )
    formula: str = Field(description="The exact formula applied.")
    explanation: str
    policy_id: str
    policy_version: str
    scope: str = Field(description="What this score covers: one session, or the capture.")
    limitations: tuple[str, ...] = ()


class PolicyInfo(_Frozen):
    """Identity and provenance of the active assessment policy."""

    policy_id: str
    policy_version: str
    #: Digest of the version plus any applied overrides. Finding identifiers
    #: are derived from this, so a report carries what is needed to recompute
    #: them.
    policy_fingerprint: str
    title: str
    description: str
    published: str
    minimum_tls_version: str
    minimum_rsa_bits: int
    minimum_ec_bits: int
    minimum_coverage_for_score: float
    assessment_mode: AssessmentMode
    reference_time: datetime | None = None
    standards_references: tuple[StandardsReference, ...] = ()
    overrides_applied: tuple[str, ...] = Field(
        default=(), description="Named settings the operator changed from the default."
    )
    limitations: tuple[str, ...] = ()


class SessionAssessment(_Frozen):
    """Every rule result and finding for one session."""

    session_id: str
    capture_id: str
    rule_results: tuple[RuleResult, ...] = ()
    findings: tuple[SecurityFinding, ...] = ()
    posture_score: PostureScore
    limitations: tuple[str, ...] = ()


class AssessmentResult(_Frozen):
    """The capture-wide assessment block added to a report."""

    policy: PolicyInfo
    sessions: tuple[SessionAssessment, ...] = ()
    findings: tuple[SecurityFinding, ...] = ()
    prioritised_findings: tuple[PrioritisedFinding, ...] = ()
    remediations: tuple[Remediation, ...] = ()
    posture_score: PostureScore
    coverage: AssessmentCoverage
    tally: ControlTally
    rules_evaluated: int = Field(default=0, ge=0)
    sessions_assessed: int = Field(default=0, ge=0)
    limitations: tuple[str, ...] = ()
