"""The versioned cryptographic assessment policy.

A policy answers "what counts as acceptable?".  That is a *choice*, not a
forensic fact, so it is versioned, named in every assessment, and separated
into four kinds of statement:

``PROTOCOL_REQUIREMENT``
    The protocol itself forbids or mandates it. Not negotiable.
``STANDARDS_RECOMMENDATION``
    A standards body recommends it. RFC 9325 and NIST SP 800-52r2 are
    recommendations for general use; neither is universally mandatory, and
    this project does not claim otherwise.
``PROJECT_POLICY``
    SecureMailScope's own default, chosen and justified here.
``ENVIRONMENT_CHOICE``
    Something only the operator can decide, such as which endpoints are
    business-critical.

Every threshold below carries its rationale in :data:`THRESHOLD_RATIONALE`.
The weights are **project-defined initial values**, not validated industry
benchmarks; they are configurable and their effect on the score is fully
disclosed in the scoring output.

Changing a policy changes the *judgement*. It never changes the underlying
forensic observations, which are produced before this layer runs and are
reported unmodified alongside it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Final

from ..models.assessment import (
    AssessmentMode,
    FindingSeverity,
    PolicyInfo,
    StandardsReference,
)

__all__ = [
    "POLICY_ID",
    "POLICY_VERSION",
    "POLICY_PUBLISHED",
    "AssessmentPolicy",
    "DEFAULT_POLICY",
    "SEVERITY_WEIGHTS",
    "THRESHOLD_RATIONALE",
    "REFERENCES",
]

POLICY_ID: Final = "securemailscope-default"
POLICY_VERSION: Final = "1.0.0"
POLICY_PUBLISHED: Final = "2026-09-21"

# ---------------------------------------------------------------------------
# Standards the default policy draws on
# ---------------------------------------------------------------------------
REFERENCES: Final[dict[str, StandardsReference]] = {
    "RFC9325": StandardsReference(
        document="RFC 9325",
        title="Recommendations for Secure Use of Transport Layer Security (TLS) "
        "and Datagram Transport Layer Security (DTLS)",
        published="2022-11",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC9325-3.1": StandardsReference(
        document="RFC 9325",
        section="3.1.1",
        title="SSL/TLS Protocol Versions -- TLS 1.0 and 1.1 MUST NOT be used",
        published="2022-11",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC9325-4.1": StandardsReference(
        document="RFC 9325",
        section="4.1",
        title="General Guidelines on cipher suites",
        published="2022-11",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC9325-4.2": StandardsReference(
        document="RFC 9325",
        section="4.2",
        title="Cipher Suites for TLS 1.2 -- forward secrecy required",
        published="2022-11",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC9325-3.2": StandardsReference(
        document="RFC 9325",
        section="3.2",
        title="Strict TLS -- use of TLS for mail submission and access",
        published="2022-11",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC8446": StandardsReference(
        document="RFC 8446",
        title="The Transport Layer Security (TLS) Protocol Version 1.3",
        published="2018-08",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC8446-B.4": StandardsReference(
        document="RFC 8446",
        section="B.4",
        title="Cipher Suites -- TLS 1.3 suites encode only an AEAD and a hash",
        published="2018-08",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC8446-2.2": StandardsReference(
        document="RFC 8446",
        section="2.2",
        title="Resumption and Pre-Shared Key -- psk_ke vs psk_dhe_ke",
        published="2018-08",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC5246": StandardsReference(
        document="RFC 5246",
        title="The Transport Layer Security (TLS) Protocol Version 1.2",
        published="2008-08",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC5246-7.4.7.1": StandardsReference(
        document="RFC 5246",
        section="7.4.7.1",
        title="RSA-Encrypted Premaster Secret Message -- static RSA key transport",
        published="2008-08",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC5280": StandardsReference(
        document="RFC 5280",
        title="Internet X.509 Public Key Infrastructure Certificate and CRL Profile",
        published="2008-05",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC5280-4.1.2.5": StandardsReference(
        document="RFC 5280",
        section="4.1.2.5",
        title="Validity -- notBefore and notAfter",
        published="2008-05",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC5280-6": StandardsReference(
        document="RFC 5280",
        section="6",
        title="Certification Path Validation",
        published="2008-05",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC6125": StandardsReference(
        document="RFC 6125",
        section="6",
        title="Representation and Verification of Application Service Identity",
        published="2011-03",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "RFC9155": StandardsReference(
        document="RFC 9155",
        title="Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2 and DTLS 1.2",
        published="2021-12",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "NIST80052R2": StandardsReference(
        document="NIST SP 800-52 Rev. 2",
        title="Guidelines for the Selection, Configuration, and Use of TLS "
        "Implementations",
        published="2019-08",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "NIST80052R2-3.1": StandardsReference(
        document="NIST SP 800-52 Rev. 2",
        section="3.1",
        title="Protocol Version Support -- TLS 1.2 required, TLS 1.3 recommended",
        published="2019-08",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC8314": StandardsReference(
        document="RFC 8314",
        section="3",
        title="Cleartext Considered Obsolete: Use of TLS for Email Submission and Access",
        published="2018-01",
        kind="STANDARDS_RECOMMENDATION",
    ),
    "RFC3207": StandardsReference(
        document="RFC 3207",
        title="SMTP Service Extension for Secure SMTP over Transport Layer Security",
        published="2002-02",
        kind="PROTOCOL_REQUIREMENT",
    ),
    "PROJECT": StandardsReference(
        document="SecureMailScope assessment policy",
        title="Project-defined default weighting and thresholds",
        published=POLICY_PUBLISHED,
        kind="PROJECT_POLICY",
    ),
}


# ---------------------------------------------------------------------------
# Weights
# ---------------------------------------------------------------------------
#: Weight contributed by one scoring unit, by the severity of its rule.
#:
#: These are **project-defined initial values**. They were chosen so that one
#: CRITICAL control outweighs three MEDIUM ones and a LOW control cannot by
#: itself move a score band -- an ordering judgement, not a measurement. They
#: are configurable, and every score discloses the weights it applied.
#: INFO rules weigh nothing: they are context, not controls, so they neither
#: earn credit nor consume coverage.
SEVERITY_WEIGHTS: Final[dict[FindingSeverity, float]] = {
    FindingSeverity.CRITICAL: 10.0,
    FindingSeverity.HIGH: 6.0,
    FindingSeverity.MEDIUM: 3.0,
    FindingSeverity.LOW: 1.0,
    FindingSeverity.INFO: 0.0,
}

#: Why each threshold has the value it has. Quoted in the documentation and
#: in the policy block of every assessment, so no number is presented as
#: self-evidently correct.
THRESHOLD_RATIONALE: Final[dict[str, str]] = {
    "minimum_tls_version": (
        "TLS 1.2 (0x0303). RFC 9325 §3.1.1 states TLS 1.0 and TLS 1.1 MUST NOT be "
        "used, and NIST SP 800-52r2 §3.1 requires TLS 1.2 support. TLS 1.2 is NOT "
        "treated as a failure merely because TLS 1.3 exists: both are acceptable "
        "under this policy, and the rule assesses the negotiated configuration."
    ),
    "minimum_rsa_bits": (
        "2048 bits. RFC 9325 §3.2 and NIST SP 800-52r2 both place the floor for "
        "general-purpose RSA at 2048 bits, corresponding to roughly 112-bit "
        "security in NIST SP 800-57 Part 1 Rev. 5."
    ),
    "minimum_ec_bits": (
        "224 bits. NIST SP 800-57 Part 1 Rev. 5 places the minimum curve size for "
        "112-bit security at 224 bits; secp256r1 and larger satisfy it."
    ),
    "deprecated_signature_hashes": (
        "MD5 and SHA-1. RFC 9155 deprecates both for TLS signatures because "
        "practical collisions exist."
    ),
    "minimum_coverage_for_score": (
        "0.50. A score computed from less than half the applicable policy weight "
        "describes too little to be useful, so below this the engine reports "
        "SCORE_UNAVAILABLE rather than a number that looks authoritative. The "
        "value is a project judgement about readability, not a measured threshold."
    ),
    "score_bands": (
        "STRONG >= 90, ADEQUATE >= 70, WEAK >= 40, CRITICAL below 40. Project-"
        "defined reading aids for the numeric score; they are not an industry "
        "classification and carry no external meaning."
    ),
    "severity_weights": (
        "CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, INFO 0. Chosen so one CRITICAL "
        "control outweighs three MEDIUM ones. An ordering judgement, not a "
        "measurement, and fully configurable."
    ),
}

#: Encryption algorithms the default policy will not accept: the reason, and
#: the single rule that owns each one.
#:
#: Ownership is what keeps one misconfigured setting from being reported three
#: times at three severities. A NULL cipher is not additionally reported as
#: "prohibited" and "unapproved"; it is reported once, by TLS-CIPHER-001, at
#: the severity that fits it. The rules module derives its sets from this
#: table rather than keeping its own copy, so the published policy and the
#: implemented behaviour cannot drift apart.
PROHIBITED_ENCRYPTION: Final[dict[str, tuple[str, str]]] = {
    "NULL": (
        "provides no confidentiality at all",
        "TLS-CIPHER-001",
    ),
    "RC4_128": (
        "RFC 7465 prohibits RC4 in TLS; practical keystream biases break it",
        "TLS-CIPHER-003",
    ),
    "RC4_40": (
        "export-grade RC4: a 40-bit key is brute-forceable",
        "TLS-CIPHER-003",
    ),
    "DES_CBC": (
        "single DES has a 56-bit key and is brute-forceable",
        "TLS-CIPHER-003",
    ),
    "DES40_CBC": (
        "export-grade DES: a 40-bit key is brute-forceable",
        "TLS-CIPHER-003",
    ),
    "RC2_CBC_40": (
        "export-grade RC2: a 40-bit key is brute-forceable",
        "TLS-CIPHER-003",
    ),
    "3DES_EDE_CBC": (
        "64-bit block cipher vulnerable to birthday attacks (Sweet32)",
        "TLS-CIPHER-004",
    ),
}


def prohibited_for(rule_id: str) -> frozenset[str]:
    """The encryption algorithms one rule is responsible for reporting."""
    return frozenset(
        name for name, (_, owner) in PROHIBITED_ENCRYPTION.items() if owner == rule_id
    )

#: Encryption algorithms the default policy approves for TLS 1.2 and TLS 1.3.
APPROVED_ENCRYPTION: Final[frozenset[str]] = frozenset(
    {
        "AES_128_GCM",
        "AES_256_GCM",
        "AES_128_CCM",
        "AES_128_CCM_8",
        "CHACHA20_POLY1305",
    }
)

#: CBC-mode suites are not prohibited but are not preferred: RFC 9325 §4.2
#: recommends AEAD. Flagged at MEDIUM under "not on the approved list".
CBC_NOTE: Final = (
    "CBC-mode suites are not prohibited by this policy, but RFC 9325 §4.2 "
    "recommends AEAD suites; they are reported as not policy-approved."
)


@dataclass(frozen=True, slots=True)
class AssessmentPolicy:
    """A named, versioned set of assessment choices."""

    policy_id: str = POLICY_ID
    policy_version: str = POLICY_VERSION
    published: str = POLICY_PUBLISHED
    title: str = "SecureMailScope default cryptographic assessment policy"
    description: str = (
        "Evaluates observed TLS and email-transport configuration against RFC 9325, "
        "RFC 8446, RFC 5280 and NIST SP 800-52 Rev. 2, with project-defined weights "
        "and thresholds that are documented and configurable."
    )

    #: Lowest acceptable negotiated protocol version, as a wire code point.
    minimum_tls_version: int = 0x0303
    minimum_rsa_bits: int = 2048
    minimum_ec_bits: int = 224
    deprecated_signature_hashes: frozenset[str] = frozenset({"md5", "sha1"})
    minimum_coverage_for_score: float = 0.50

    severity_weights: dict[FindingSeverity, float] = field(
        default_factory=lambda: dict(SEVERITY_WEIGHTS)
    )
    #: Per-rule weight overrides, keyed by rule id.
    rule_weight_overrides: dict[str, float] = field(default_factory=dict)
    #: Per-rule severity overrides, keyed by rule id.
    rule_severity_overrides: dict[str, FindingSeverity] = field(default_factory=dict)
    disabled_rules: frozenset[str] = frozenset()

    assessment_mode: AssessmentMode = AssessmentMode.HISTORICAL
    #: Operator-supplied endpoint criticality, keyed by "ip:port". Never
    #: inferred: an empty mapping means no criticality is known, and the
    #: prioritiser treats it as such rather than inventing one.
    asset_criticality: dict[str, str] = field(default_factory=dict)

    #: Names of settings the operator changed, recorded in the report.
    overrides_applied: tuple[str, ...] = ()

    # -- derived -----------------------------------------------------------
    def weight_for(self, rule_id: str, severity: FindingSeverity) -> float:
        override = self.rule_weight_overrides.get(rule_id)
        if override is not None:
            return override
        return self.severity_weights.get(severity, 0.0)

    def severity_for(self, rule_id: str, default: FindingSeverity) -> FindingSeverity:
        return self.rule_severity_overrides.get(rule_id, default)

    def enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rules

    def criticality_for(self, endpoint: str) -> str | None:
        """Only ever returns what the operator explicitly supplied."""
        return self.asset_criticality.get(endpoint)

    def with_overrides(
        self,
        *,
        assessment_mode: AssessmentMode | None = None,
        minimum_tls_version: int | None = None,
        minimum_rsa_bits: int | None = None,
        minimum_coverage_for_score: float | None = None,
        disabled_rules: frozenset[str] | None = None,
        rule_weight_overrides: dict[str, float] | None = None,
        asset_criticality: dict[str, str] | None = None,
    ) -> AssessmentPolicy:
        """Return a policy with explicit overrides, recording what changed."""
        changes: list[str] = []
        updates: dict[str, object] = {}
        if assessment_mode is not None and assessment_mode is not self.assessment_mode:
            updates["assessment_mode"] = assessment_mode
            changes.append(f"assessment_mode={assessment_mode.value}")
        if minimum_tls_version is not None and minimum_tls_version != self.minimum_tls_version:
            updates["minimum_tls_version"] = minimum_tls_version
            changes.append(f"minimum_tls_version=0x{minimum_tls_version:04x}")
        if minimum_rsa_bits is not None and minimum_rsa_bits != self.minimum_rsa_bits:
            updates["minimum_rsa_bits"] = minimum_rsa_bits
            changes.append(f"minimum_rsa_bits={minimum_rsa_bits}")
        if (
            minimum_coverage_for_score is not None
            and minimum_coverage_for_score != self.minimum_coverage_for_score
        ):
            updates["minimum_coverage_for_score"] = minimum_coverage_for_score
            changes.append(f"minimum_coverage_for_score={minimum_coverage_for_score}")
        if disabled_rules:
            updates["disabled_rules"] = frozenset(disabled_rules)
            changes.append(f"disabled_rules={','.join(sorted(disabled_rules))}")
        if rule_weight_overrides:
            updates["rule_weight_overrides"] = dict(rule_weight_overrides)
            changes.append(
                "rule_weight_overrides="
                + ",".join(f"{k}:{v}" for k, v in sorted(rule_weight_overrides.items()))
            )
        if asset_criticality:
            updates["asset_criticality"] = dict(asset_criticality)
            changes.append(f"asset_criticality={len(asset_criticality)} endpoint(s)")
        if not updates:
            return self
        updates["overrides_applied"] = (*self.overrides_applied, *changes)
        return replace(self, **updates)  # type: ignore[arg-type]

    @property
    def fingerprint(self) -> str:
        """A short digest of everything that changes a rule's verdict.

        A policy version alone is not enough to identify the criteria a
        finding was reached under: an operator who raises ``minimum_rsa_bits``
        on the command line is evaluating a different standard while still
        running policy 1.0.0. Two reports produced under different criteria
        must not share finding identifiers, or a diff between them would
        silently compare unlike things. The fingerprint therefore covers the
        applied overrides as well as the published version, and is carried in
        the report so a reader can recompute any finding ID by hand.
        """
        material = "|".join(
            (self.policy_id, self.policy_version, *sorted(self.overrides_applied))
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]

    def info(self, reference_time: datetime | None) -> PolicyInfo:
        """The policy block embedded in every assessment."""
        return PolicyInfo(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            policy_fingerprint=self.fingerprint,
            title=self.title,
            description=self.description,
            published=self.published,
            minimum_tls_version=f"0x{self.minimum_tls_version:04x}",
            minimum_rsa_bits=self.minimum_rsa_bits,
            minimum_ec_bits=self.minimum_ec_bits,
            minimum_coverage_for_score=self.minimum_coverage_for_score,
            assessment_mode=self.assessment_mode,
            reference_time=reference_time,
            standards_references=tuple(
                REFERENCES[key]
                for key in ("RFC9325", "RFC8446", "RFC5246", "RFC5280", "NIST80052R2")
            ),
            overrides_applied=self.overrides_applied,
            limitations=(
                "This policy encodes choices, not forensic facts. Changing it changes "
                "the judgement and never the underlying observations, which are "
                "reported unmodified alongside it.",
                "RFC 9325 and NIST SP 800-52 Rev. 2 are recommendations for general "
                "use. This project does not claim every recommendation in them is "
                "universally mandatory.",
                "The weights and score bands are project-defined initial values, not "
                "validated industry benchmarks.",
            ),
        )


DEFAULT_POLICY: Final = AssessmentPolicy()
