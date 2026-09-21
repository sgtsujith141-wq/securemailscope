"""Rule evaluation against structured forensic observations.

Every evaluator here reads *typed model fields* produced by M1-M3. Nothing in
this module reparses a capture, inspects a JSON string, or applies a regular
expression to evidence. If an observation is absent, the rule says ``UNKNOWN``
-- it never fills the gap and never converts absence into either compliance or
violation.

Three habits run through all of them:

* **Negotiated, not offered.**  A rule about what happened reads the
  ServerHello. What the client was willing to accept is a separate,
  informational rule.
* **Verified, not merely unverified.**  ``CERT-005`` fires on a chain
  validation that ran and failed, never on one that could not run.
* **No intent.**  A refused upgrade, an absent advertisement and a weak suite
  are reported as configuration observations. This tool cannot establish that
  anyone attacked anything, and none of these texts claims otherwise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from ..models.assessment import Confidence, ObservedValue, RuleOutcome
from ..models.certificates import (
    CertificateObservation,
    CertificateValidation,
    CertificateVisibility,
    ValidationStatus,
)
from ..models.evidence import PacketReference
from ..models.protocol import (
    DetectionStatus,
    ProtocolEventType,
    ProtocolSessionAnalysis,
    UpgradeState,
)
from ..models.tcp import Direction, TCPSession
from ..models.tls import (
    ForwardSecrecyStatus,
    HandshakeState,
    RecordParseState,
    TLSSessionAnalysis,
)
from ..tls.registry import CipherSuiteInfo, lookup_cipher_suite, lookup_named_group
from .policy import APPROVED_ENCRYPTION, AssessmentPolicy, prohibited_for

__all__ = ["SessionContext", "Verdict", "RULE_EVALUATORS", "evaluate_rule"]

#: The algorithms each cipher rule owns, derived from the policy table so the
#: published policy is the only place this is decided. NULL belongs to
#: TLS-CIPHER-001 and 3DES to TLS-CIPHER-004, because their weaknesses and
#: their remedies differ from a plain prohibition.
_BROKEN_ENCRYPTION: Final[frozenset[str]] = prohibited_for("TLS-CIPHER-003")
_SIXTY_FOUR_BIT_BLOCK: Final[frozenset[str]] = prohibited_for("TLS-CIPHER-004")

_DEGRADED_RECORDS: Final[frozenset[RecordParseState]] = frozenset(
    {
        RecordParseState.ALIGNMENT_LOST_AT_GAP,
        RecordParseState.MALFORMED_RECORD,
        RecordParseState.AMBIGUOUS_BYTES,
        RecordParseState.TRUNCATED_RECORD,
        RecordParseState.LIMIT_REACHED,
    }
)
_UPGRADE_SUCCEEDED: Final[frozenset[UpgradeState]] = frozenset(
    {UpgradeState.UPGRADE_ACCEPTED, UpgradeState.TLS_BYTES_OBSERVED}
)
_IDENTIFIED: Final[frozenset[DetectionStatus]] = frozenset(
    {DetectionStatus.CONFIRMED, DetectionStatus.PROBABLE}
)


@dataclass(frozen=True, slots=True)
class SessionContext:
    """Everything a rule may read about one session."""

    capture_id: str
    session: TCPSession
    protocol: ProtocolSessionAnalysis | None
    tls: TLSSessionAnalysis | None
    policy: AssessmentPolicy
    reference_time: datetime | None

    # -- convenience -------------------------------------------------------
    @property
    def suite(self) -> CipherSuiteInfo | None:
        if self.tls is None or self.tls.cipher_suite.selected is None:
            return None
        return lookup_cipher_suite(self.tls.cipher_suite.selected.value)

    @property
    def selected_version(self) -> int | None:
        if self.tls is None or self.tls.version.selected_version is None:
            return None
        return self.tls.version.selected_version.value

    @property
    def leaf(self) -> CertificateObservation | None:
        if self.tls is None or not self.tls.certificates.certificates:
            return None
        return self.tls.certificates.certificates[0]

    @property
    def validation(self) -> CertificateValidation | None:
        return self.tls.certificates.validation if self.tls else None

    def tls_confidence(self) -> Confidence:
        """How much the TLS evidence for this session can be relied on."""
        if self.tls is None:
            return Confidence.LOW
        if self.tls.handshake_state is HandshakeState.INDETERMINATE:
            return Confidence.LOW
        if (
            self.tls.client_record_parse_state in _DEGRADED_RECORDS
            or self.tls.server_record_parse_state in _DEGRADED_RECORDS
        ):
            return Confidence.LOW
        if self.tls.version.negotiation_status.value == "OBSERVED":
            return Confidence.CONFIRMED
        return Confidence.PROBABLE

    def mail_confidence(self) -> Confidence:
        """Confidence in an email-transport conclusion.

        A protocol identified only from a port number can never support a
        confident finding, which is why PORT_HINT lands on ``LOW``.
        """
        if self.protocol is None:
            return Confidence.LOW
        status = self.protocol.detection.status
        if status is DetectionStatus.CONFIRMED:
            return Confidence.CONFIRMED
        if status is DetectionStatus.PROBABLE:
            return Confidence.PROBABLE
        return Confidence.LOW

    @property
    def email_identified(self) -> bool:
        return (
            self.protocol is not None
            and self.protocol.detection.status in _IDENTIFIED
        )


@dataclass(frozen=True, slots=True)
class Verdict:
    """One rule's conclusion, before it becomes a result or a finding."""

    outcome: RuleOutcome
    rationale: str
    observed: tuple[ObservedValue, ...] = ()
    evidence: tuple[PacketReference, ...] = ()
    offsets: tuple[int, ...] = ()
    limitations: tuple[str, ...] = ()
    confidence: Confidence | None = None


def _value(name: str, value: object, source: str) -> ObservedValue:
    return ObservedValue(name=name, value=str(value), source=source)


def _na(reason: str) -> Verdict:
    return Verdict(outcome=RuleOutcome.NOT_APPLICABLE, rationale=reason)


def _unknown(reason: str, *, limitations: tuple[str, ...] = ()) -> Verdict:
    return Verdict(
        outcome=RuleOutcome.UNKNOWN, rationale=reason, limitations=limitations
    )


# ---------------------------------------------------------------------------
# A. TLS protocol
# ---------------------------------------------------------------------------
def _tls_proto_001(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    version = ctx.tls.version.selected_version
    if version is None:
        return _unknown(
            "No ServerHello was observed, so no version was negotiated. The client's "
            "offered versions describe capability only and are assessed separately.",
            limitations=(
                "A capture that begins after the ServerHello, or one that ends before "
                "it, cannot establish the negotiated version.",
            ),
        )
    minimum = ctx.policy.minimum_tls_version
    observed = (
        _value(
            "negotiated_version",
            version.name or version.hex_value,
            "tls.version.selected_version",
        ),
        _value("policy_minimum", f"0x{minimum:04x}", "policy.minimum_tls_version"),
        _value(
            "version_source",
            ctx.tls.version.selected_source or "",
            "tls.version.selected_source",
        ),
    )
    refs = ctx.tls.version.evidence_refs
    if version.value < minimum:
        return Verdict(
            RuleOutcome.FAIL,
            f"The server selected {version.name or version.hex_value}, which is below "
            f"the policy minimum of 0x{minimum:04x}.",
            observed,
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The server selected {version.name or version.hex_value}, which meets the "
        f"policy minimum. TLS 1.2 is acceptable under this policy; it is not treated "
        "as a failure merely because TLS 1.3 exists.",
        observed,
        refs,
    )


def _tls_proto_002(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    offered = [ref for ref in ctx.tls.version.offered_versions if not ref.grease]
    if not offered:
        return _unknown("No ClientHello was observed, so no offered versions are known.")
    minimum = ctx.policy.minimum_tls_version
    obsolete = [ref for ref in offered if ref.known and ref.value < minimum]
    observed = (
        _value(
            "offered_versions",
            ", ".join(ref.name or ref.hex_value for ref in offered),
            "tls.version.offered_versions",
        ),
    )
    refs = ctx.tls.version.evidence_refs
    if obsolete:
        names = ", ".join(ref.name or ref.hex_value for ref in obsolete)
        return Verdict(
            RuleOutcome.FAIL,
            f"The client offered {names}, below the policy minimum. This describes the "
            "client only: it says nothing about what was negotiated, and a server that "
            "declines the obsolete version is behaving correctly.",
            observed,
            refs,
            limitations=(
                "Informational. A finding here is not a statement about the server.",
            ),
        )
    return Verdict(
        RuleOutcome.PASS,
        "Every protocol version the client offered meets the policy minimum.",
        observed,
        refs,
    )


def _tls_proto_003(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    fatal = [
        alert
        for alert in ctx.tls.alerts
        if not alert.encrypted and alert.level_name == "fatal"
    ]
    if fatal:
        alert = fatal[0]
        return Verdict(
            RuleOutcome.FAIL,
            f"A fatal TLS alert ({alert.description_name or alert.description}) ended "
            "the negotiation before it completed. The alert states the cause; no "
            "intent is inferred from it.",
            (
                _value(
                    "alert",
                    alert.description_name or str(alert.description),
                    "tls.alerts",
                ),
            ),
            alert.packet_refs,
            (alert.stream_offset,),
        )
    if ctx.tls.handshake_state in {
        HandshakeState.NOT_OBSERVED,
        HandshakeState.INDETERMINATE,
    }:
        return _unknown(
            "The handshake was not observed well enough to say whether it completed.",
            limitations=(
                "Encrypted alerts are framed but not readable, so a failure after the "
                "encryption boundary would not be visible here.",
            ),
        )
    return Verdict(
        RuleOutcome.PASS,
        "No fatal alert was observed in the plaintext portion of this handshake.",
        (),
        ctx.tls.version.evidence_refs,
        limitations=(
            "Only plaintext alerts are readable; a failure after the encryption "
            "boundary would not appear here.",
        ),
    )


# ---------------------------------------------------------------------------
# B. Cipher suite
# ---------------------------------------------------------------------------
def _cipher_guard(ctx: SessionContext) -> Verdict | None:
    """Shared preconditions for the negotiated-suite rules."""
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    selected = ctx.tls.cipher_suite.selected
    if selected is None:
        return _unknown(
            "No ServerHello was observed, so no cipher suite was negotiated. Offered "
            "suites are capability only and are never assessed as negotiated."
        )
    if ctx.suite is None:
        return _unknown(
            f"The negotiated suite {selected.hex_value} is not in this build's "
            "registry, so its cryptographic properties cannot be assessed. Nothing is "
            "inferred from the numeric value.",
            limitations=(
                "An unknown suite may be strong or unacceptable; this capture does not "
                "establish which.",
            ),
        )
    return None


def _suite_values(ctx: SessionContext) -> tuple[ObservedValue, ...]:
    selected = ctx.tls.cipher_suite.selected if ctx.tls else None
    suite = ctx.suite
    assert selected is not None and suite is not None
    return (
        _value("cipher_suite", suite.name, "tls.cipher_suite.selected"),
        _value("code_point", selected.hex_value, "tls.cipher_suite.selected"),
        _value("encryption", suite.encryption, "registry"),
        _value("aead", suite.aead, "registry"),
    )


def _tls_cipher_001(ctx: SessionContext) -> Verdict:
    guard = _cipher_guard(ctx)
    if guard is not None:
        return guard
    suite = ctx.suite
    assert suite is not None
    refs = ctx.tls.cipher_suite.evidence_refs if ctx.tls else ()
    if suite.encryption == "NULL":
        return Verdict(
            RuleOutcome.FAIL,
            f"The negotiated suite {suite.name} uses NULL encryption, so application "
            "data is not confidentiality-protected despite the handshake.",
            _suite_values(ctx),
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite {suite.name} encrypts application data.",
        _suite_values(ctx),
        refs,
    )


def _tls_cipher_002(ctx: SessionContext) -> Verdict:
    guard = _cipher_guard(ctx)
    if guard is not None:
        return guard
    suite = ctx.suite
    assert suite is not None
    if suite.tls13_only:
        return _na(
            "TLS 1.3 cipher suites do not encode an authentication method "
            "(RFC 8446 §B.4); server authentication comes from the certificate and "
            "signature_algorithms instead."
        )
    refs = ctx.tls.cipher_suite.evidence_refs if ctx.tls else ()
    if suite.authentication.value == "ANONYMOUS":
        return Verdict(
            RuleOutcome.FAIL,
            f"The negotiated suite {suite.name} is anonymous, so the server presented "
            "no certificate and its identity was never established.",
            _suite_values(ctx),
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite {suite.name} authenticates the server using "
        f"{suite.authentication.value}.",
        _suite_values(ctx),
        refs,
    )


def _tls_cipher_003(ctx: SessionContext) -> Verdict:
    guard = _cipher_guard(ctx)
    if guard is not None:
        return guard
    suite = ctx.suite
    assert suite is not None
    refs = ctx.tls.cipher_suite.evidence_refs if ctx.tls else ()
    if suite.encryption in _BROKEN_ENCRYPTION:
        return Verdict(
            RuleOutcome.FAIL,
            f"The negotiated suite {suite.name} uses {suite.encryption}, which the "
            "policy prohibits outright because practical attacks exist against it.",
            _suite_values(ctx),
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite {suite.name} does not use a prohibited cipher.",
        _suite_values(ctx),
        refs,
    )


def _tls_cipher_004(ctx: SessionContext) -> Verdict:
    guard = _cipher_guard(ctx)
    if guard is not None:
        return guard
    suite = ctx.suite
    assert suite is not None
    refs = ctx.tls.cipher_suite.evidence_refs if ctx.tls else ()
    if suite.encryption in _SIXTY_FOUR_BIT_BLOCK:
        return Verdict(
            RuleOutcome.FAIL,
            f"The negotiated suite {suite.name} uses {suite.encryption}, a 64-bit "
            "block cipher, which is vulnerable to birthday-bound collision attacks on "
            "long-lived connections.",
            _suite_values(ctx),
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite {suite.name} does not use a 64-bit block cipher.",
        _suite_values(ctx),
        refs,
    )


def _tls_cipher_005(ctx: SessionContext) -> Verdict:
    guard = _cipher_guard(ctx)
    if guard is not None:
        return guard
    suite = ctx.suite
    assert suite is not None
    refs = ctx.tls.cipher_suite.evidence_refs if ctx.tls else ()
    if suite.encryption not in APPROVED_ENCRYPTION:
        return Verdict(
            RuleOutcome.FAIL,
            f"The negotiated suite {suite.name} uses {suite.encryption}, which is not "
            "on the policy-approved list. RFC 9325 §4.2 recommends AEAD suites.",
            _suite_values(ctx),
            refs,
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite {suite.name} uses {suite.encryption}, which the policy "
        "approves.",
        _suite_values(ctx),
        refs,
    )


def _tls_cipher_006(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    selected = ctx.tls.cipher_suite.selected
    if selected is None:
        return _na("No cipher suite was negotiated, so there is nothing to look up.")
    if ctx.suite is None:
        return _unknown(
            f"The negotiated suite {selected.hex_value} is not in the registry this "
            "build carries, so its properties are not assessed.",
            limitations=(
                "Reported by its numeric identifier only. Nothing is guessed from the "
                "shape of a name.",
            ),
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated suite is registered as {ctx.suite.name}.",
        (_value("cipher_suite", ctx.suite.name, "registry"),),
        ctx.tls.cipher_suite.evidence_refs,
    )


# ---------------------------------------------------------------------------
# C. Key exchange
# ---------------------------------------------------------------------------
_FS_FAIL: Final[frozenset[ForwardSecrecyStatus]] = frozenset(
    {
        ForwardSecrecyStatus.STATIC_RSA_KEY_EXCHANGE,
        ForwardSecrecyStatus.PSK_ONLY,
        ForwardSecrecyStatus.NOT_FORWARD_SECRET,
    }
)
_FS_PASS: Final[frozenset[ForwardSecrecyStatus]] = frozenset(
    {
        ForwardSecrecyStatus.EPHEMERAL_OBSERVED,
        ForwardSecrecyStatus.CAPABLE_NEGOTIATED,
    }
)


def _tls_kex_001(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    assessment = ctx.tls.forward_secrecy
    observed = (
        _value("forward_secrecy_status", assessment.status.value, "tls.forward_secrecy"),
        _value("key_exchange_method", ctx.tls.key_exchange.method, "tls.key_exchange"),
        _value(
            "method_source", ctx.tls.key_exchange.method_source or "", "tls.key_exchange"
        ),
    )
    refs = assessment.evidence_refs
    limitations = (
        "Forward secrecy here is a property of the negotiated key exchange. Handshake "
        "completion is not verifiable from a passive capture, so this is not a "
        "statement that the exchange finished successfully.",
    )
    if assessment.status in _FS_FAIL:
        return Verdict(
            RuleOutcome.FAIL,
            assessment.criteria,
            observed,
            refs,
            limitations=limitations,
        )
    if assessment.status in _FS_PASS:
        note = (
            "The ephemeral key material itself was observed."
            if assessment.status is ForwardSecrecyStatus.EPHEMERAL_OBSERVED
            else "An ephemeral method was negotiated, though the key material was not "
            "captured."
        )
        return Verdict(
            RuleOutcome.PASS,
            f"The negotiated key exchange provides forward secrecy. {note}",
            observed,
            refs,
            limitations=limitations,
        )
    return _unknown(
        assessment.criteria,
        limitations=(
            "An unknown key exchange is an evidence gap. It is not penalised as though "
            "static RSA had been observed.",
        ),
    )


def _tls_kex_002(ctx: SessionContext) -> Verdict:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    group = ctx.tls.key_exchange.selected_group
    if group is None:
        return _na("No key-exchange group was observed.")
    info = lookup_named_group(group.value)
    if info is None or info.family != "HYBRID":
        return _na(
            f"The negotiated group {group.name or group.hex_value} is not a hybrid "
            "post-quantum group."
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The negotiated group {info.name} combines a classical and a post-quantum "
        "algorithm. This is recorded as an observation: the post-quantum component's "
        "properties are not verified here and no claim is made about them.",
        (_value("named_group", info.name, "tls.key_exchange.selected_group"),),
        ctx.tls.key_exchange.evidence_refs,
        limitations=(
            "Observing a hybrid group does not establish post-quantum security for "
            "this session.",
        ),
    )


# ---------------------------------------------------------------------------
# D. Certificate
# ---------------------------------------------------------------------------
def _certificate_guard(ctx: SessionContext) -> Verdict | None:
    if ctx.tls is None:
        return _na("The session does not carry TLS.")
    inventory = ctx.tls.certificates
    if inventory.visibility is CertificateVisibility.ENCRYPTED_TLS13:
        return _na(
            "TLS 1.3 encrypts the Certificate message under handshake traffic keys "
            "(RFC 8446 §2), so no certificate is available to assess. This is a limit "
            "of passive analysis, not a certificate problem."
        )
    if inventory.visibility is CertificateVisibility.NOT_APPLICABLE_ANONYMOUS:
        return _na("An anonymous suite was negotiated, so no certificate is sent.")
    if inventory.visibility is not CertificateVisibility.OBSERVED or ctx.leaf is None:
        return _na(
            f"No certificate was available to assess ({inventory.visibility.value}): "
            f"{inventory.visibility_explanation}"
        )
    return None


def _reference_time(ctx: SessionContext) -> datetime | None:
    """The instant certificate validity is judged against."""
    if ctx.policy.assessment_mode.value == "CURRENT_TIME":
        return ctx.reference_time
    validation = ctx.validation
    if validation is not None and validation.validity_dates_checked.reference_time:
        return validation.validity_dates_checked.reference_time
    return ctx.session.first_packet.timestamp


def _cert_dates(ctx: SessionContext, *, expired: bool) -> Verdict:
    guard = _certificate_guard(ctx)
    if guard is not None:
        return guard
    leaf = ctx.leaf
    assert leaf is not None
    reference = _reference_time(ctx)
    if reference is None:
        return _unknown(
            "No reference timestamp is available, so validity cannot be judged. The "
            "analysis clock is deliberately not substituted for the capture's."
        )
    mode = ctx.policy.assessment_mode.value
    observed = (
        _value("not_valid_before", leaf.not_valid_before.isoformat(), "certificate"),
        _value("not_valid_after", leaf.not_valid_after.isoformat(), "certificate"),
        _value("reference_time", reference.isoformat(), f"assessment_mode={mode}"),
        _value("sha256_fingerprint", leaf.sha256_fingerprint, "certificate"),
    )
    limitations = (
        f"Judged in {mode} mode against {reference.isoformat()}.",
    )
    if expired:
        failed = reference > leaf.not_valid_after
        message = (
            f"The certificate expired at {leaf.not_valid_after.isoformat()}, before "
            f"the reference time {reference.isoformat()}."
            if failed
            else "The certificate had not expired at the reference time."
        )
    else:
        failed = reference < leaf.not_valid_before
        message = (
            f"The certificate was not valid until {leaf.not_valid_before.isoformat()}, "
            f"after the reference time {reference.isoformat()}."
            if failed
            else "The certificate was already valid at the reference time."
        )
    return Verdict(
        RuleOutcome.FAIL if failed else RuleOutcome.PASS,
        message,
        observed,
        leaf.packet_refs,
        (leaf.stream_offset,),
        limitations,
    )


def _cert_001(ctx: SessionContext) -> Verdict:
    return _cert_dates(ctx, expired=True)


def _cert_002(ctx: SessionContext) -> Verdict:
    return _cert_dates(ctx, expired=False)


def _cert_003(ctx: SessionContext) -> Verdict:
    guard = _certificate_guard(ctx)
    if guard is not None:
        return guard
    leaf = ctx.leaf
    assert leaf is not None
    key = leaf.public_key
    if not key.supported:
        return _unknown(
            "The installed library could not describe this public key, so its strength "
            "is not assessed."
        )
    if key.size_bits is None:
        return _na(
            f"{key.algorithm} keys have fixed parameters, so a minimum bit length is "
            "not a meaningful test for them."
        )
    minimum = (
        ctx.policy.minimum_rsa_bits
        if key.algorithm in {"RSA", "DSA"}
        else ctx.policy.minimum_ec_bits
    )
    observed = (
        _value("public_key_algorithm", key.algorithm, "certificate.public_key"),
        _value("public_key_size_bits", key.size_bits, "certificate.public_key"),
        _value("policy_minimum_bits", minimum, "policy"),
    )
    if key.size_bits < minimum:
        return Verdict(
            RuleOutcome.FAIL,
            f"The certificate's {key.algorithm} key is {key.size_bits} bits, below the "
            f"policy minimum of {minimum}.",
            observed,
            leaf.packet_refs,
            (leaf.stream_offset,),
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The certificate's {key.algorithm} key is {key.size_bits} bits, meeting the "
        f"policy minimum of {minimum}.",
        observed,
        leaf.packet_refs,
        (leaf.stream_offset,),
    )


def _cert_004(ctx: SessionContext) -> Verdict:
    guard = _certificate_guard(ctx)
    if guard is not None:
        return guard
    leaf = ctx.leaf
    assert leaf is not None
    hash_name = leaf.signature_hash_algorithm
    if hash_name is None:
        return _unknown(
            "The certificate's signature algorithm does not expose a separate hash "
            "(Edwards-curve signatures, for example), so this test does not apply "
            "cleanly and no conclusion is drawn."
        )
    observed = (
        _value("signature_algorithm", leaf.signature_algorithm, "certificate"),
        _value("signature_hash", hash_name, "certificate"),
    )
    if hash_name.lower() in ctx.policy.deprecated_signature_hashes:
        return Verdict(
            RuleOutcome.FAIL,
            f"The certificate is signed with {hash_name.upper()}, which RFC 9155 "
            "deprecates because practical collisions exist.",
            observed,
            leaf.packet_refs,
            (leaf.stream_offset,),
        )
    return Verdict(
        RuleOutcome.PASS,
        f"The certificate is signed with {hash_name.upper()}, which the policy accepts.",
        observed,
        leaf.packet_refs,
        (leaf.stream_offset,),
    )


def _validation_backed(
    ctx: SessionContext,
    field_name: str,
    fail_message: str,
    pass_message: str,
    unknown_limitation: str,
) -> Verdict:
    guard = _certificate_guard(ctx)
    if guard is not None:
        return guard
    validation = ctx.validation
    leaf = ctx.leaf
    assert leaf is not None
    if validation is None:
        return _unknown("No validation was performed for this session.")
    check = getattr(validation, field_name)
    observed = (
        _value(f"{field_name}_status", check.status.value, "certificates.validation"),
    )
    if check.status is ValidationStatus.FAILED:
        return Verdict(
            RuleOutcome.FAIL,
            f"{fail_message} {check.explanation}",
            observed,
            leaf.packet_refs,
            (leaf.stream_offset,),
            tuple(check.limitations),
        )
    if check.status is ValidationStatus.PASSED:
        return Verdict(
            RuleOutcome.PASS,
            f"{pass_message} {check.explanation}",
            observed,
            leaf.packet_refs,
            (leaf.stream_offset,),
            tuple(check.limitations),
        )
    return _unknown(
        f"{check.explanation}",
        limitations=(unknown_limitation, *check.limitations),
    )


def _cert_005(ctx: SessionContext) -> Verdict:
    return _validation_backed(
        ctx,
        "chain_verified",
        "Path validation ran against the configured trust anchors and failed.",
        "The certificate chains to a configured trust anchor.",
        "An unverified chain is NOT an invalid chain. Configure a trust store to "
        "turn this into an answer.",
    )


def _cert_006(ctx: SessionContext) -> Verdict:
    return _validation_backed(
        ctx,
        "hostname_verified",
        "The certificate does not name the expected identity.",
        "The certificate names the expected identity.",
        "A missing reference identity is NOT a hostname mismatch. Supply an expected "
        "identity to turn this into an answer.",
    )


def _cert_007(ctx: SessionContext) -> Verdict:
    guard = _certificate_guard(ctx)
    if guard is not None:
        return guard
    leaf = ctx.leaf
    assert leaf is not None
    if not leaf.extended_key_usage:
        return _unknown(
            "The certificate declares no extendedKeyUsage. RFC 5280 leaves such a "
            "certificate unconstrained, so its absence is not a violation.",
            limitations=(
                "Some deployments require an explicit EKU; that is an environment "
                "choice this default policy does not impose.",
            ),
        )
    observed = (
        _value(
            "extended_key_usage",
            ", ".join(leaf.extended_key_usage),
            "certificate.extended_key_usage",
        ),
    )
    if "serverAuth" not in leaf.extended_key_usage:
        return Verdict(
            RuleOutcome.FAIL,
            "The certificate declares an extendedKeyUsage that does not include "
            "serverAuth, so it is being used outside its stated purpose.",
            observed,
            leaf.packet_refs,
            (leaf.stream_offset,),
        )
    return Verdict(
        RuleOutcome.PASS,
        "The certificate's extendedKeyUsage permits server authentication.",
        observed,
        leaf.packet_refs,
        (leaf.stream_offset,),
    )


# ---------------------------------------------------------------------------
# E. Email transport
# ---------------------------------------------------------------------------
def _mail_guard(ctx: SessionContext) -> Verdict | None:
    if ctx.protocol is None:
        return _na("No application-protocol analysis exists for this session.")
    if not ctx.email_identified:
        return _na(
            "No email protocol was identified from payload. A port number alone is a "
            f"hint, not an identification ({ctx.protocol.detection.status.value})."
        )
    return None


def _upgrade_succeeded(ctx: SessionContext) -> bool:
    upgrade = ctx.protocol.upgrade if ctx.protocol else None
    return upgrade is not None and upgrade.state in _UPGRADE_SUCCEEDED


def _mail_001(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    attempts = ctx.protocol.authentication
    if not attempts:
        if ctx.protocol.parse_state.value in {"COMPLETE", "HANDED_OFF_TO_TLS"}:
            return Verdict(
                RuleOutcome.PASS,
                "No authentication command was observed on this session.",
                (),
                (ctx.session.first_packet,),
            )
        return _unknown(
            "The dialogue was not parsed far enough to say whether authentication "
            "occurred.",
            limitations=(
                "A truncated or interrupted capture cannot establish the absence of an "
                "authentication attempt.",
            ),
        )
    if _upgrade_succeeded(ctx):
        return Verdict(
            RuleOutcome.PASS,
            "Authentication was observed, but an opportunistic TLS upgrade was "
            "accepted on this session, so this rule does not apply to it. Whether the "
            "credentials preceded the upgrade is assessed separately.",
            (),
            (ctx.session.first_packet,),
        )
    first = attempts[0]
    return Verdict(
        RuleOutcome.FAIL,
        f"An authentication command ({first.command_verb}) was observed with no "
        "accepted TLS upgrade in effect, so the credentials travelled in the clear. "
        "The credential itself was never recorded.",
        (
            _value("command_verb", first.command_verb, "protocol.authentication"),
            _value("mechanism", first.mechanism or "unrecognised", "protocol.authentication"),
            _value("attempt_count", len(attempts), "protocol.authentication"),
        ),
        first.packet_refs,
        tuple(attempt.stream_offset for attempt in attempts),
        (
            "No credential material is recorded anywhere in this finding.",
            "That the credentials were exposed is an observation; whether anyone "
            "captured them is not something this capture can establish.",
        ),
        ctx.mail_confidence(),
    )


def _mail_002(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    if not _upgrade_succeeded(ctx):
        return _na("No TLS upgrade was accepted on this session.")
    early = [a for a in ctx.protocol.authentication if a.occurred_before_tls_upgrade]
    if not early:
        return Verdict(
            RuleOutcome.PASS,
            "No authentication was observed before the upgrade was accepted.",
            (),
            (ctx.session.first_packet,),
        )
    first = early[0]
    return Verdict(
        RuleOutcome.FAIL,
        f"An authentication command ({first.command_verb}) was observed before the "
        "accepted upgrade took effect, so those credentials were exposed even though "
        "the session was later protected.",
        (
            _value("command_verb", first.command_verb, "protocol.authentication"),
            _value("attempt_count", len(early), "protocol.authentication"),
        ),
        first.packet_refs,
        tuple(a.stream_offset for a in early),
        ("No credential material is recorded anywhere in this finding.",),
        ctx.mail_confidence(),
    )


def _mail_003(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    upgrade = ctx.protocol.upgrade
    if upgrade is None or upgrade.requested is None:
        return _na("No opportunistic TLS upgrade was requested on this session.")
    observed = (
        _value("mechanism", upgrade.mechanism.value, "protocol.upgrade"),
        _value("state", upgrade.state.value, "protocol.upgrade"),
        _value("response_code", upgrade.response_code or "none", "protocol.upgrade"),
    )
    refs = upgrade.response.packet_refs if upgrade.response else upgrade.requested.packet_refs
    if upgrade.state is UpgradeState.UPGRADE_REJECTED:
        return Verdict(
            RuleOutcome.FAIL,
            f"The client requested {upgrade.mechanism.value} and the server refused it "
            f"({upgrade.response_code}). The session continued without transport "
            "protection. A refusal is also what a server with no TLS configured does, "
            "so no attack is inferred from it.",
            observed,
            refs,
            (upgrade.response.stream_offset,) if upgrade.response else (),
            (
                "A refused upgrade is an observation about configuration, not evidence "
                "of an attack.",
            ),
            ctx.mail_confidence(),
        )
    if upgrade.state in _UPGRADE_SUCCEEDED:
        return Verdict(
            RuleOutcome.PASS,
            f"The server accepted the {upgrade.mechanism.value} request.",
            observed,
            refs,
        )
    return _unknown(
        f"The {upgrade.mechanism.value} request has no determinable outcome in this "
        f"capture ({upgrade.state.value}).",
        limitations=(
            "An interrupted or truncated capture cannot establish whether the upgrade "
            "succeeded.",
        ),
    )


def _mail_004(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    upgrade = ctx.protocol.upgrade
    if upgrade is None or upgrade.state not in _UPGRADE_SUCCEEDED:
        return _na("No upgrade was accepted on this session.")
    observed = (_value("state", upgrade.state.value, "protocol.upgrade"),)
    refs = upgrade.response.packet_refs if upgrade.response else ()
    if upgrade.state is UpgradeState.UPGRADE_ACCEPTED:
        return Verdict(
            RuleOutcome.FAIL,
            "The server accepted the upgrade but no TLS record framing follows in this "
            "capture, so the protected channel was not observed being established.",
            observed,
            refs,
            (),
            (
                "This is most often a capture artefact: the capture may simply end "
                "here. It is not evidence that TLS failed.",
            ),
            Confidence.LOW,
        )
    return Verdict(
        RuleOutcome.PASS,
        "TLS record framing follows the accepted upgrade, so the transition to a "
        "protected channel was observed.",
        observed,
        refs,
    )


def _mail_005(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    upgrade = ctx.protocol.upgrade
    if upgrade is None or upgrade.state is not UpgradeState.UPGRADE_REJECTED:
        return _na("No upgrade was refused on this session.")
    assert upgrade.response is not None
    boundary = upgrade.response.end_offset
    after = [
        event
        for event in ctx.protocol.events
        if event.direction is Direction.CLIENT_TO_SERVER
        and event.stream_offset >= boundary
        and event.event_type
        in {
            ProtocolEventType.CLIENT_COMMAND,
            ProtocolEventType.AUTHENTICATION_COMMAND,
            ProtocolEventType.UPGRADE_REQUESTED,
        }
    ]
    if not after:
        return Verdict(
            RuleOutcome.PASS,
            "After the refusal the client issued no further plaintext protocol "
            "commands.",
            (),
            upgrade.response.packet_refs,
        )
    return Verdict(
        RuleOutcome.FAIL,
        f"After the server refused the upgrade the client issued {len(after)} further "
        "plaintext command(s), so the session continued unprotected.",
        (
            _value("commands_after_refusal", len(after), "protocol.events"),
            _value(
                "first_command",
                after[0].command_verb or after[0].event_type.value,
                "protocol.events",
            ),
        ),
        after[0].packet_refs,
        tuple(event.stream_offset for event in after[:8]),
        (),
        ctx.mail_confidence(),
    )


def _mail_006(ctx: SessionContext) -> Verdict:
    guard = _mail_guard(ctx)
    if guard is not None:
        return guard
    assert ctx.protocol is not None
    if ctx.protocol.implicit_tls is not None and ctx.protocol.implicit_tls.observed:
        return _na(
            "The session is TLS-framed from its first byte, so there is no plaintext "
            "phase in which an upgrade would be advertised."
        )
    advertisements = [
        event
        for event in ctx.protocol.events
        if event.event_type is ProtocolEventType.CAPABILITY_ADVERTISEMENT
    ]
    if not advertisements:
        return _unknown(
            "No server capability advertisement was parsed, so whether an upgrade "
            "mechanism is offered cannot be determined.",
            limitations=(
                "In a midstream capture the command a capability response answers is "
                "not observable, so the response is not read as an advertisement.",
            ),
        )
    upgrade = ctx.protocol.upgrade
    if upgrade is not None and upgrade.advertised is not None:
        return Verdict(
            RuleOutcome.PASS,
            f"The server advertised {upgrade.mechanism.value} in its capability "
            "response.",
            (_value("mechanism", upgrade.mechanism.value, "protocol.upgrade.advertised"),),
            upgrade.advertised.packet_refs,
        )
    first = advertisements[0]
    return Verdict(
        RuleOutcome.FAIL,
        "The server's capability response offered no opportunistic TLS mechanism, so "
        "a client willing to upgrade has no way to do so. This describes the "
        "advertised configuration; it is not evidence that an advertisement was "
        "stripped, which this tool cannot establish.",
        (
            _value(
                "advertised_capabilities",
                ", ".join(first.capabilities) or "none recorded",
                "protocol.events",
            ),
        ),
        first.packet_refs,
        (first.stream_offset,),
        (
            "An absent advertisement is not evidence of a downgrade attack.",
        ),
        ctx.mail_confidence(),
    )


def _mail_007(ctx: SessionContext) -> Verdict:
    if ctx.protocol is None:
        return _na("No application-protocol analysis exists for this session.")
    implicit = ctx.protocol.implicit_tls
    if implicit is None or not implicit.observed:
        return _na("The session is not implicit TLS.")
    if ctx.tls is not None and ctx.tls.version.selected_version is not None:
        return Verdict(
            RuleOutcome.PASS,
            "The implicit-TLS handshake was observed well enough to assess the "
            "negotiated parameters.",
            (),
            ctx.tls.version.evidence_refs,
        )
    return _unknown(
        "The session is TLS-framed from its first byte but the handshake was not "
        "observed well enough to assess what was negotiated.",
        limitations=(
            "An evidence gap, not a weakness. The transport may be perfectly "
            "configured; this capture does not say.",
        ),
    )


RULE_EVALUATORS: Final[dict[str, Callable[[SessionContext], Verdict]]] = {
    "TLS-PROTO-001": _tls_proto_001,
    "TLS-PROTO-002": _tls_proto_002,
    "TLS-PROTO-003": _tls_proto_003,
    "TLS-CIPHER-001": _tls_cipher_001,
    "TLS-CIPHER-002": _tls_cipher_002,
    "TLS-CIPHER-003": _tls_cipher_003,
    "TLS-CIPHER-004": _tls_cipher_004,
    "TLS-CIPHER-005": _tls_cipher_005,
    "TLS-CIPHER-006": _tls_cipher_006,
    "TLS-KEX-001": _tls_kex_001,
    "TLS-KEX-002": _tls_kex_002,
    "CERT-001": _cert_001,
    "CERT-002": _cert_002,
    "CERT-003": _cert_003,
    "CERT-004": _cert_004,
    "CERT-005": _cert_005,
    "CERT-006": _cert_006,
    "CERT-007": _cert_007,
    "MAIL-001": _mail_001,
    "MAIL-002": _mail_002,
    "MAIL-003": _mail_003,
    "MAIL-004": _mail_004,
    "MAIL-005": _mail_005,
    "MAIL-006": _mail_006,
    "MAIL-007": _mail_007,
}


def evaluate_rule(rule_id: str, ctx: SessionContext) -> Verdict:
    """Run one rule. Unknown rule ids are a programming error, not input."""
    return RULE_EVALUATORS[rule_id](ctx)
