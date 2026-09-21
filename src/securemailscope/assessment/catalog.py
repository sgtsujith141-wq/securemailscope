"""The rule and remediation catalogues.

This module is data: what each rule *is*, not how it is evaluated. Keeping
the definitions separate from the logic means a reader can audit the policy
surface -- every rule id, severity, citation and remediation mapping -- in one
place, and the evaluator in :mod:`securemailscope.assessment.rules` cannot
quietly introduce a rule that is not documented here.

``dedup_group`` is the mechanism that stops one underlying weakness being
counted several times. A NULL-encryption suite trips both "provides no
encryption" and "not on the approved list"; both are reported, but they share
a group, so scoring counts the group once at its most severe member's weight.
"""

from __future__ import annotations

from typing import Final

from ..models.assessment import (
    FindingSeverity,
    Remediation,
    RuleCategory,
    RuleDefinition,
)
from .policy import REFERENCES as R

__all__ = ["RULES", "REMEDIATIONS", "rule", "remediation", "rules_for_category"]

S = FindingSeverity
C = RuleCategory


def _rule(
    rule_id: str,
    name: str,
    description: str,
    category: RuleCategory,
    severity: FindingSeverity,
    *,
    required_evidence: tuple[str, ...],
    applicable_when: str,
    references: tuple[str, ...],
    remediation_ids: tuple[str, ...],
    dedup_group: str,
    technical_impact: str,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        name=name,
        description=description,
        category=category,
        severity=severity,
        required_evidence=required_evidence,
        applicable_when=applicable_when,
        standards_references=tuple(R[key] for key in references),
        remediation_ids=remediation_ids,
        dedup_group=dedup_group,
        technical_impact=technical_impact,
    )


_DEFINITIONS: Final[tuple[RuleDefinition, ...]] = (
    # -- A. TLS protocol ---------------------------------------------------
    _rule(
        "TLS-PROTO-001",
        "Negotiated TLS version below the policy minimum",
        "The version the server actually selected is older than the policy allows. "
        "Evaluated on the negotiated version only: a client offering an obsolete "
        "version that the server did not select is a separate, informational rule.",
        C.TLS_PROTOCOL,
        S.HIGH,
        required_evidence=("A ServerHello establishing the negotiated version",),
        applicable_when="The session carries TLS and a version was negotiated.",
        references=("RFC9325-3.1", "NIST80052R2-3.1"),
        remediation_ids=("REM-TLS-VERSION",),
        dedup_group="NEGOTIATED_PROTOCOL_VERSION",
        technical_impact=(
            "Obsolete protocol versions lack modern AEAD constructions and carry known "
            "weaknesses in their record and handshake design, so traffic protected by "
            "them is easier to attack than traffic protected by TLS 1.2 or 1.3."
        ),
    ),
    _rule(
        "TLS-PROTO-002",
        "Client offered a protocol version below the policy minimum",
        "The client advertised an obsolete version in its ClientHello. This is "
        "informational: it says nothing about what was negotiated, and a server that "
        "correctly refuses the obsolete version is behaving properly.",
        C.TLS_PROTOCOL,
        S.INFO,
        required_evidence=("A ClientHello listing offered versions",),
        applicable_when="A ClientHello was observed.",
        references=("RFC9325-3.1",),
        remediation_ids=("REM-TLS-VERSION",),
        dedup_group="OFFERED_PROTOCOL_VERSION",
        technical_impact=(
            "A client willing to use an obsolete version may be downgraded by an "
            "attacker able to influence negotiation, if the server also accepts it."
        ),
    ),
    _rule(
        "TLS-PROTO-003",
        "TLS negotiation ended in a fatal alert",
        "A fatal alert was observed in plaintext, so the handshake did not complete. "
        "The cause is recorded from the alert description; no intent is inferred.",
        C.TLS_PROTOCOL,
        S.LOW,
        required_evidence=("A plaintext alert record",),
        applicable_when="The session carries TLS.",
        references=("RFC5246",),
        remediation_ids=(),
        dedup_group="NEGOTIATION_OUTCOME",
        technical_impact=(
            "A failed negotiation means no protected channel was established for this "
            "session. Whether the client then fell back to plaintext is a separate "
            "observation."
        ),
    ),
    # -- B. Cipher suite ---------------------------------------------------
    _rule(
        "TLS-CIPHER-001",
        "Negotiated cipher suite provides no encryption",
        "The negotiated suite uses NULL encryption, so application data travels in "
        "the clear despite a TLS handshake having taken place.",
        C.CIPHER_SUITE,
        S.CRITICAL,
        required_evidence=("A ServerHello naming the selected cipher suite",),
        applicable_when="A cipher suite was negotiated and is in the registry.",
        references=("RFC9325-4.1",),
        remediation_ids=("REM-TLS-CIPHER",),
        dedup_group="NEGOTIATED_CIPHER_SUITE",
        technical_impact=(
            "Anyone able to capture the traffic can read it. The handshake provides "
            "integrity and authentication at best, and no confidentiality."
        ),
    ),
    _rule(
        "TLS-CIPHER-002",
        "Negotiated cipher suite provides no server authentication",
        "An anonymous suite was negotiated, so the server presented no certificate "
        "and its identity was never established.",
        C.CIPHER_SUITE,
        S.CRITICAL,
        required_evidence=("A ServerHello naming the selected cipher suite",),
        applicable_when="A cipher suite was negotiated and is in the registry.",
        references=("RFC9325-4.1",),
        remediation_ids=("REM-TLS-CIPHER",),
        dedup_group="NEGOTIATED_CIPHER_SUITE",
        technical_impact=(
            "Without server authentication the channel can be terminated by any party "
            "in the network path, so encryption alone does not establish who the peer is."
        ),
    ),
    _rule(
        "TLS-CIPHER-003",
        "Negotiated cipher suite uses a prohibited cipher",
        "The policy prohibits the negotiated encryption algorithm outright: RC4, "
        "export-grade ciphers and single DES all have practical attacks.",
        C.CIPHER_SUITE,
        S.HIGH,
        required_evidence=("A ServerHello naming the selected cipher suite",),
        applicable_when="A cipher suite was negotiated and is in the registry.",
        references=("RFC9325-4.1",),
        remediation_ids=("REM-TLS-CIPHER",),
        dedup_group="NEGOTIATED_CIPHER_SUITE",
        technical_impact=(
            "The encryption can be broken with resources well within reach of a "
            "motivated attacker who has recorded the traffic."
        ),
    ),
    _rule(
        "TLS-CIPHER-004",
        "Negotiated cipher suite uses a 64-bit block cipher",
        "3DES has a 64-bit block size, which makes long-lived connections vulnerable "
        "to birthday-bound collision attacks (Sweet32).",
        C.CIPHER_SUITE,
        S.MEDIUM,
        required_evidence=("A ServerHello naming the selected cipher suite",),
        applicable_when="A cipher suite was negotiated and is in the registry.",
        references=("RFC9325-4.1",),
        remediation_ids=("REM-TLS-CIPHER",),
        dedup_group="NEGOTIATED_CIPHER_SUITE",
        technical_impact=(
            "An attacker who can observe a very large volume of traffic on one "
            "connection can recover repeated plaintext blocks."
        ),
    ),
    _rule(
        "TLS-CIPHER-005",
        "Negotiated cipher suite is not on the policy-approved list",
        "The suite is not prohibited, but its encryption algorithm is not among those "
        "the policy approves. RFC 9325 §4.2 recommends AEAD suites; CBC-mode suites "
        "reach this rule rather than a prohibition rule.",
        C.CIPHER_SUITE,
        S.MEDIUM,
        required_evidence=("A ServerHello naming the selected cipher suite",),
        applicable_when="A cipher suite was negotiated and is in the registry.",
        references=("RFC9325-4.2",),
        remediation_ids=("REM-TLS-CIPHER",),
        dedup_group="NEGOTIATED_CIPHER_SUITE",
        technical_impact=(
            "Non-AEAD constructions have historically required careful implementation "
            "to avoid padding-oracle and timing attacks; AEAD removes that class."
        ),
    ),
    _rule(
        "TLS-CIPHER-006",
        "Negotiated cipher suite is not in the code-point registry",
        "The selected suite's numeric identifier is not one this build knows, so its "
        "cryptographic properties cannot be assessed. Reported UNKNOWN, never guessed "
        "from the shape of a name.",
        C.CIPHER_SUITE,
        S.INFO,
        required_evidence=("A registry entry for the selected cipher suite",),
        applicable_when="A cipher suite was negotiated.",
        references=("PROJECT",),
        remediation_ids=(),
        dedup_group="UNKNOWN_CIPHER_SUITE",
        technical_impact=(
            "An unassessable suite is an evidence gap, not a weakness. It may be "
            "perfectly strong or unacceptable; this capture does not say."
        ),
    ),
    # -- C. Key exchange ---------------------------------------------------
    _rule(
        "TLS-KEX-001",
        "Negotiated key exchange does not provide forward secrecy",
        "The key establishment method the session negotiated has no ephemeral "
        "contribution, so a later compromise of the long-term key decrypts this "
        "recorded session. Covers static RSA key transport, static DH/ECDH and "
        "TLS 1.3 PSK-only resumption.",
        C.KEY_EXCHANGE,
        S.HIGH,
        required_evidence=(
            "A negotiated key exchange method, from the cipher suite (TLS 1.2) or "
            "the key_share and PSK extensions (TLS 1.3)",
        ),
        applicable_when="A key exchange method was established.",
        references=("RFC9325-4.2", "RFC5246-7.4.7.1", "RFC8446-2.2"),
        remediation_ids=("REM-TLS-FS",),
        dedup_group="FORWARD_SECRECY",
        technical_impact=(
            "An attacker who records the traffic now and obtains the server's "
            "long-term key later -- by compromise, legal compulsion or key reuse -- "
            "can decrypt the recorded session retrospectively."
        ),
    ),
    _rule(
        "TLS-KEX-002",
        "Hybrid post-quantum key-exchange group negotiated",
        "The negotiated group combines a classical and a post-quantum algorithm. "
        "Recorded as an observation only: this assessment does not verify the "
        "post-quantum component's security properties and makes no claim about them.",
        C.KEY_EXCHANGE,
        S.INFO,
        required_evidence=("A server key_share naming a hybrid group",),
        applicable_when="TLS 1.3 was negotiated with an observable key_share.",
        references=("RFC8446", "PROJECT"),
        remediation_ids=(),
        dedup_group="HYBRID_GROUP",
        technical_impact=(
            "Informational. A hybrid group is intended to remain secure if either "
            "component holds, but this tool observes only that one was selected."
        ),
    ),
    # -- D. Certificate ----------------------------------------------------
    _rule(
        "CERT-001",
        "Certificate had expired at the assessment reference time",
        "The end-entity certificate's notAfter had passed. Judged at the capture "
        "timestamp in historical mode, which is the only way to say what was true "
        "when the traffic happened.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=("A decoded certificate and a reference timestamp",),
        applicable_when="A certificate was observed in plaintext.",
        references=("RFC5280-4.1.2.5",),
        remediation_ids=("REM-CERT-RENEW",),
        dedup_group="CERT_VALIDITY",
        technical_impact=(
            "Clients enforcing validity reject the connection; clients that do not "
            "lose the assurance the expiry date exists to provide."
        ),
    ),
    _rule(
        "CERT-002",
        "Certificate was not yet valid at the assessment reference time",
        "The end-entity certificate's notBefore had not been reached, which usually "
        "indicates a clock or provisioning error rather than expiry.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=("A decoded certificate and a reference timestamp",),
        applicable_when="A certificate was observed in plaintext.",
        references=("RFC5280-4.1.2.5",),
        remediation_ids=("REM-CERT-RENEW",),
        dedup_group="CERT_VALIDITY",
        technical_impact=(
            "Conforming clients reject the certificate, and the mismatch suggests the "
            "server or its issuer has an incorrect clock."
        ),
    ),
    _rule(
        "CERT-003",
        "Certificate public key is below the policy minimum strength",
        "The subject public key is smaller than the policy allows. Algorithms with "
        "fixed parameters, such as Ed25519, are NOT_APPLICABLE rather than failed.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=("A decoded certificate with a describable public key",),
        applicable_when="A certificate was observed and its key has a variable size.",
        references=("RFC9325", "NIST80052R2"),
        remediation_ids=("REM-CERT-KEY",),
        dedup_group="CERT_KEY_STRENGTH",
        technical_impact=(
            "A key below the policy floor offers less work factor than the policy "
            "requires against an attacker attempting to recover it."
        ),
    ),
    _rule(
        "CERT-004",
        "Certificate signature uses a deprecated hash",
        "The certificate is signed with MD5 or SHA-1, for which practical collisions "
        "exist, so the signature no longer binds the certificate contents reliably.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=("A decoded certificate naming its signature hash",),
        applicable_when="A certificate was observed and its signature hash is known.",
        references=("RFC9155",),
        remediation_ids=("REM-CERT-SIGALG",),
        dedup_group="CERT_SIGNATURE",
        technical_impact=(
            "An attacker able to construct a hash collision can produce a second "
            "certificate that the same signature appears to authenticate."
        ),
    ),
    _rule(
        "CERT-005",
        "Certificate chain verification failed",
        "Path validation was attempted against a configured trust store and did not "
        "succeed. This rule fires ONLY on a verified failure: an unverified chain -- "
        "no trust store configured -- is UNKNOWN, not a failure.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=(
            "A configured trust store and a completed path validation attempt",
        ),
        applicable_when="A certificate was observed and chain verification was attempted.",
        references=("RFC5280-6",),
        remediation_ids=("REM-CERT-CHAIN",),
        dedup_group="CERT_CHAIN",
        technical_impact=(
            "The presented certificate cannot be traced to a trusted issuer, so it "
            "provides no assurance about who the server is."
        ),
    ),
    _rule(
        "CERT-006",
        "Certificate does not name the expected server identity",
        "The certificate's subjectAltName entries do not match the identity the "
        "operator supplied. Fires ONLY on a verified mismatch: with no reference "
        "identity the rule is UNKNOWN, because there is nothing to compare against.",
        C.CERTIFICATE,
        S.HIGH,
        required_evidence=(
            "An operator-supplied expected identity and a completed comparison",
        ),
        applicable_when="A certificate was observed and hostname verification ran.",
        references=("RFC6125",),
        remediation_ids=("REM-CERT-IDENTITY",),
        dedup_group="CERT_IDENTITY",
        technical_impact=(
            "A client that checks names will refuse the connection; one that does not "
            "may be talking to a different service than intended."
        ),
    ),
    _rule(
        "CERT-007",
        "End-entity certificate does not permit server authentication",
        "The certificate carries an extendedKeyUsage extension that omits serverAuth. "
        "When the extension is absent, RFC 5280 leaves the certificate unconstrained, "
        "so the rule is UNKNOWN rather than failed.",
        C.CERTIFICATE,
        S.MEDIUM,
        required_evidence=("A decoded certificate carrying an extendedKeyUsage extension",),
        applicable_when="A certificate was observed and declares an EKU.",
        references=("RFC5280",),
        remediation_ids=("REM-CERT-EKU",),
        dedup_group="CERT_EKU",
        technical_impact=(
            "Clients enforcing EKU reject the certificate for TLS server "
            "authentication, and the certificate is being used outside its stated purpose."
        ),
    ),
    # -- E. Email transport ------------------------------------------------
    _rule(
        "MAIL-001",
        "Credentials submitted over an unencrypted email session",
        "An authentication command was observed on a session where no TLS upgrade was "
        "ever accepted, so the credentials travelled in the clear. The credential "
        "itself is never recorded; only that an attempt occurred.",
        C.EMAIL_TRANSPORT,
        S.CRITICAL,
        required_evidence=(
            "An observed authentication command with no accepted TLS upgrade in effect",
        ),
        applicable_when="A plaintext email protocol was identified from payload.",
        references=("RFC8314", "RFC9325-3.2"),
        remediation_ids=("REM-MAIL-TLS-BEFORE-AUTH", "REM-MAIL-ENABLE-STARTTLS"),
        dedup_group="PLAINTEXT_AUTH",
        technical_impact=(
            "Anyone able to observe the network path obtains working mailbox "
            "credentials. Whether they did so is not something a capture can show."
        ),
    ),
    _rule(
        "MAIL-002",
        "Credentials submitted before the TLS upgrade took effect",
        "An authentication command was observed before an upgrade that the server "
        "later accepted, so those credentials were exposed even though the session "
        "was eventually protected.",
        C.EMAIL_TRANSPORT,
        S.HIGH,
        required_evidence=(
            "An authentication command preceding an accepted upgrade boundary",
        ),
        applicable_when="A plaintext email protocol was identified and an upgrade occurred.",
        references=("RFC8314", "RFC3207"),
        remediation_ids=("REM-MAIL-TLS-BEFORE-AUTH",),
        dedup_group="PLAINTEXT_AUTH",
        technical_impact=(
            "The later upgrade does not protect what was already sent; those "
            "credentials should be treated as disclosed."
        ),
    ),
    _rule(
        "MAIL-003",
        "Opportunistic TLS upgrade was refused by the server",
        "The client asked to upgrade and the server declined. Recorded as an "
        "observation of the server's configuration; no attack is inferred, since a "
        "refusal is also what a server without TLS configured legitimately does.",
        C.EMAIL_TRANSPORT,
        S.MEDIUM,
        required_evidence=("An upgrade command and a refusing server response",),
        applicable_when="A plaintext email protocol was identified.",
        references=("RFC3207", "RFC8314"),
        remediation_ids=("REM-MAIL-ENABLE-STARTTLS", "REM-MAIL-IMPLICIT-TLS"),
        dedup_group="UPGRADE_OUTCOME",
        technical_impact=(
            "The session continues without transport protection, so everything after "
            "the refusal is readable on the path."
        ),
    ),
    _rule(
        "MAIL-004",
        "Upgrade accepted but TLS establishment was not observable",
        "The server agreed to begin TLS and no TLS record framing follows in this "
        "capture. That is most often a capture artefact rather than a failure, which "
        "is why the severity is low and the limitation is stated explicitly.",
        C.EMAIL_TRANSPORT,
        S.LOW,
        required_evidence=("An accepted upgrade response and the bytes that follow it",),
        applicable_when="An upgrade was accepted.",
        references=("RFC3207",),
        remediation_ids=(),
        dedup_group="UPGRADE_OUTCOME",
        technical_impact=(
            "This capture does not establish that the protected channel was actually "
            "set up. It is equally consistent with the capture simply ending."
        ),
    ),
    _rule(
        "MAIL-005",
        "Plaintext email protocol continued after the upgrade was refused",
        "After the server declined to upgrade, the client carried on issuing "
        "protocol commands in the clear rather than stopping.",
        C.EMAIL_TRANSPORT,
        S.HIGH,
        required_evidence=("A refused upgrade followed by further plaintext commands",),
        applicable_when="An upgrade was refused on an identified email session.",
        references=("RFC8314",),
        remediation_ids=("REM-MAIL-TLS-BEFORE-AUTH", "REM-MAIL-ENABLE-STARTTLS"),
        dedup_group="PLAINTEXT_CONTINUATION",
        technical_impact=(
            "Mail transactions, recipient lists and any credentials that follow are "
            "exposed on the network path."
        ),
    ),
    _rule(
        "MAIL-006",
        "No opportunistic TLS mechanism was advertised",
        "The server's capability response on a plaintext email session did not offer "
        "STARTTLS or STLS. This is an observation about the advertised configuration; "
        "it is NOT evidence of a stripping attack, which this tool cannot establish.",
        C.EMAIL_TRANSPORT,
        S.MEDIUM,
        required_evidence=("A parsed server capability advertisement",),
        applicable_when="A plaintext email protocol was identified and capabilities seen.",
        references=("RFC8314", "RFC3207"),
        remediation_ids=("REM-MAIL-ENABLE-STARTTLS", "REM-MAIL-IMPLICIT-TLS"),
        dedup_group="UPGRADE_AVAILABILITY",
        technical_impact=(
            "Clients that would have upgraded have no way to do so, so the session "
            "stays in the clear."
        ),
    ),
    _rule(
        "MAIL-007",
        "Implicit TLS observed without an assessable negotiation",
        "The session is TLS-framed from its first byte but the handshake was not "
        "observed well enough to assess the negotiated parameters. Reported UNKNOWN: "
        "the transport may be perfectly configured, and this capture does not say.",
        C.EMAIL_TRANSPORT,
        S.INFO,
        required_evidence=("An observable ServerHello on an implicit-TLS session",),
        applicable_when="The session is TLS from its first byte.",
        references=("RFC8314",),
        remediation_ids=(),
        dedup_group="IMPLICIT_TLS_VISIBILITY",
        technical_impact=(
            "An evidence gap, not a weakness. A longer or earlier capture would "
            "resolve it."
        ),
    ),
)

RULES: Final[dict[str, RuleDefinition]] = {
    definition.rule_id: definition for definition in _DEFINITIONS
}


def rule(rule_id: str) -> RuleDefinition:
    return RULES[rule_id]


def rules_for_category(category: RuleCategory) -> tuple[RuleDefinition, ...]:
    return tuple(
        definition for definition in _DEFINITIONS if definition.category is category
    )


# ---------------------------------------------------------------------------
# Remediation catalogue
# ---------------------------------------------------------------------------
def _remediation(
    remediation_id: str,
    related: tuple[str, ...],
    title: str,
    technical_explanation: str,
    recommended_action: str,
    expected_security_effect: str,
    operational_considerations: str,
    validation_steps: tuple[str, ...],
    references: tuple[str, ...],
) -> Remediation:
    return Remediation(
        remediation_id=remediation_id,
        related_rule_ids=related,
        title=title,
        technical_explanation=technical_explanation,
        recommended_action=recommended_action,
        expected_security_effect=expected_security_effect,
        operational_considerations=operational_considerations,
        validation_steps=validation_steps,
        standards_references=tuple(R[key] for key in references),
    )


_REMEDIATIONS: Final[tuple[Remediation, ...]] = (
    _remediation(
        "REM-TLS-VERSION",
        ("TLS-PROTO-001", "TLS-PROTO-002"),
        "Disable obsolete TLS protocol versions",
        "TLS 1.0 and TLS 1.1 predate modern AEAD constructions and retain design "
        "weaknesses that later versions removed. RFC 9325 §3.1.1 states they MUST NOT "
        "be used; NIST SP 800-52r2 §3.1 requires TLS 1.2 support.",
        "Set the mail service's minimum protocol version to TLS 1.2, and enable "
        "TLS 1.3 alongside it where the implementation supports it. Configure this on "
        "every listener -- submission, IMAP, POP3 and MTA-to-MTA -- not only the one "
        "in this capture.",
        "Negotiation with the obsolete versions becomes impossible, so a client that "
        "would have used one either upgrades or fails visibly rather than silently "
        "using weaker protection.",
        "Clients older than roughly 2015 may lose connectivity. Inventory client "
        "versions before enforcing, and stage the change on submission ports before "
        "MTA-to-MTA ports, where a hard failure would bounce mail.",
        (
            "Re-capture a session to the affected listener and confirm the negotiated "
            "version is TLS 1.2 or later.",
            "Confirm the server refuses a client that offers only TLS 1.0 or 1.1.",
            "Repeat for every listener, not only the one originally observed.",
        ),
        ("RFC9325-3.1", "NIST80052R2-3.1"),
    ),
    _remediation(
        "REM-TLS-CIPHER",
        (
            "TLS-CIPHER-001",
            "TLS-CIPHER-002",
            "TLS-CIPHER-003",
            "TLS-CIPHER-004",
            "TLS-CIPHER-005",
        ),
        "Restrict the negotiated cipher suites to policy-approved AEAD suites",
        "The suite that was actually negotiated is prohibited or not approved by the "
        "active policy. RFC 9325 §4.2 recommends AEAD suites; NULL, anonymous, "
        "export-grade, RC4 and 3DES suites all have practical attacks or provide no "
        "protection at all.",
        "Configure the server's cipher list to offer only AEAD suites -- "
        "AES-GCM, AES-CCM or ChaCha20-Poly1305 -- with ephemeral key exchange, and "
        "remove NULL, anonymous, export, RC4, DES and 3DES suites entirely. Set the "
        "server to choose the suite rather than honouring the client's preference.",
        "Every subsequent session negotiates a suite whose confidentiality and "
        "integrity properties the policy accepts.",
        "Removing CBC-mode suites can break very old clients. If some must be kept, "
        "keep them only on a listener whose client population is known and record the "
        "exception in your own policy, rather than leaving them on every port.",
        (
            "Re-capture a session and confirm the negotiated suite appears in the "
            "policy-approved list.",
            "Confirm the server declines a client that offers only prohibited suites.",
            "Check that server-side cipher preference is enabled.",
        ),
        ("RFC9325-4.1", "RFC9325-4.2"),
    ),
    _remediation(
        "REM-TLS-FS",
        ("TLS-KEX-001",),
        "Use an ephemeral key exchange so recorded traffic stays protected",
        "The negotiated key establishment has no ephemeral contribution. With static "
        "RSA key transport (RFC 5246 §7.4.7.1) the premaster secret is encrypted to "
        "the server's long-term key, so recovering that key later decrypts every "
        "recorded session. TLS 1.3 psk_ke resumption has the same property with "
        "respect to the pre-shared key.",
        "Remove static RSA key transport suites (TLS_RSA_*) and any static DH/ECDH "
        "suites from the server's cipher list, leaving ECDHE or DHE suites. For "
        "TLS 1.3, configure psk_dhe_ke so resumption still contributes fresh key "
        "material; do not offer psk_ke alone.",
        "A future compromise of the server's long-term key no longer decrypts "
        "sessions recorded before the compromise.",
        "ECDHE costs slightly more CPU per handshake than RSA key transport; on "
        "modern hardware this is normally negligible, but measure if the listener "
        "handles a very high connection rate. Some embedded clients support only "
        "static RSA and will need replacing.",
        (
            "Re-capture a session and confirm the negotiated suite names ECDHE or DHE, "
            "or that a TLS 1.3 ServerHello carries a key_share.",
            "Confirm no TLS_RSA_* suite remains in the server's offered list.",
            "For TLS 1.3, confirm resumption still carries a key_share.",
        ),
        ("RFC9325-4.2", "RFC5246-7.4.7.1", "RFC8446-2.2"),
    ),
    _remediation(
        "REM-CERT-RENEW",
        ("CERT-001", "CERT-002"),
        "Renew the certificate and correct the issuing clock",
        "The certificate was outside its validity window at the time of the capture. "
        "RFC 5280 §4.1.2.5 makes that window part of what the certificate asserts, and "
        "conforming clients enforce it.",
        "Issue a replacement certificate covering the current period and install it on "
        "every listener that presents it. If the certificate was not yet valid, check "
        "the clock on the issuing system as well as the server, since a future "
        "notBefore usually means one of them is wrong.",
        "Clients enforcing validity can complete the handshake, and the assurance the "
        "validity window is meant to carry is restored.",
        "Schedule renewal well before expiry and automate it; a manual renewal cycle "
        "is the usual reason this recurs. Reload each service after installing, since "
        "many keep the old certificate in memory.",
        (
            "Re-capture a session and confirm the presented certificate's notBefore "
            "and notAfter bracket the current time.",
            "Confirm every listener presents the new certificate, not only the one "
            "originally observed.",
            "Confirm the renewal is automated or diarised before the next expiry.",
        ),
        ("RFC5280-4.1.2.5",),
    ),
    _remediation(
        "REM-CERT-CHAIN",
        ("CERT-005",),
        "Serve a complete certificate chain to a trusted issuer",
        "Path validation against the configured trust anchors did not succeed. The "
        "most common cause is a server that presents only its end-entity certificate "
        "and omits the intermediates that link it to a root (RFC 5280 §6).",
        "Configure the server to present the end-entity certificate followed by every "
        "intermediate, in issuing order, excluding the root. Obtain the intermediates "
        "from your certificate authority rather than from a network fetch.",
        "Clients can build a path to a trusted anchor using only what the server "
        "sends, which is what the protocol requires of them.",
        "Chain order matters to some implementations. After changing it, verify from "
        "a client that does not already have the intermediates cached, since a "
        "previously-connected client may succeed for the wrong reason.",
        (
            "Re-capture a session and confirm the Certificate message carries the "
            "intermediates as well as the leaf.",
            "Re-run the assessment with the appropriate trust store configured and "
            "confirm chain verification passes.",
            "Verify from a client with an empty intermediate cache.",
        ),
        ("RFC5280-6",),
    ),
    _remediation(
        "REM-CERT-IDENTITY",
        ("CERT-006",),
        "Present a certificate that names the expected service identity",
        "The certificate's subjectAltName entries did not match the identity supplied "
        "for this service. RFC 6125 §6 makes subjectAltName the authoritative place "
        "for service identity; the common name is not a substitute.",
        "Reissue the certificate with every name clients use to reach this service in "
        "its subjectAltName list, including any alternative hostnames and the names "
        "used by internal clients. Alternatively, correct the client configuration if "
        "it is the expectation that is wrong.",
        "Clients performing name verification accept the connection, and the "
        "certificate genuinely attests to the identity being contacted.",
        "Enumerate names before reissuing: missing one causes a hard failure for the "
        "clients that use it. Wildcards cover one label only, so a name two levels "
        "deep needs its own entry.",
        (
            "Re-capture a session and confirm the presented subjectAltName list "
            "contains the expected name.",
            "Re-run the assessment with the expected identity supplied and confirm "
            "hostname verification passes.",
            "Test each hostname clients actually use, not only the primary one.",
        ),
        ("RFC6125",),
    ),
    _remediation(
        "REM-CERT-KEY",
        ("CERT-003",),
        "Reissue the certificate with a key that meets the policy floor",
        "The subject public key is smaller than the active policy requires. RFC 9325 "
        "§3.2 and NIST SP 800-52r2 place the general-purpose RSA floor at 2048 bits.",
        "Generate a new key at or above the policy minimum -- 2048-bit RSA at least, "
        "or an elliptic-curve key of secp256r1 or larger -- and reissue the "
        "certificate against it. Do not reuse the old key.",
        "The work factor to recover the key rises to what the policy requires.",
        "Larger RSA keys cost more per handshake; an elliptic-curve key usually gives "
        "equivalent strength more cheaply. Verify client support before switching "
        "algorithm families.",
        (
            "Re-capture a session and confirm the reported public key size meets the "
            "policy minimum.",
            "Confirm the old key is no longer served on any listener.",
        ),
        ("RFC9325", "NIST80052R2"),
    ),
    _remediation(
        "REM-CERT-SIGALG",
        ("CERT-004",),
        "Reissue the certificate with a modern signature hash",
        "The certificate is signed with MD5 or SHA-1. RFC 9155 deprecates both, "
        "because practical collisions mean the signature no longer reliably binds the "
        "certificate's contents.",
        "Request reissuance from the certificate authority using a SHA-256 or stronger "
        "signature. Check intermediates as well as the end-entity certificate, since a "
        "weak intermediate undermines the path regardless of the leaf.",
        "The signature again binds the certificate contents to the issuer.",
        "Certificate authorities stopped issuing SHA-1 certificates years ago, so one "
        "appearing here usually indicates a private or long-unrotated internal CA. "
        "That CA's own policy likely needs attention too.",
        (
            "Re-capture a session and confirm the signature algorithm is SHA-256 or "
            "stronger.",
            "Check every certificate in the presented chain, not only the leaf.",
        ),
        ("RFC9155",),
    ),
    _remediation(
        "REM-CERT-EKU",
        ("CERT-007",),
        "Issue the certificate with an extendedKeyUsage permitting server authentication",
        "The certificate declares an extendedKeyUsage that omits serverAuth, so it is "
        "being used outside the purpose it states (RFC 5280 §4.2.1.12).",
        "Reissue with serverAuth in the extendedKeyUsage list, or use a certificate "
        "profile intended for TLS servers. Do not simply remove the extension to avoid "
        "the check.",
        "Clients that enforce extendedKeyUsage accept the certificate, and it is used "
        "for the purpose it declares.",
        "Some internal CAs issue from a general-purpose profile. Correcting the "
        "profile prevents the same problem recurring on the next issuance.",
        (
            "Re-capture a session and confirm the extendedKeyUsage list contains "
            "serverAuth.",
            "Confirm the CA profile used for reissuance sets it by default.",
        ),
        ("RFC5280",),
    ),
    _remediation(
        "REM-MAIL-TLS-BEFORE-AUTH",
        ("MAIL-001", "MAIL-002", "MAIL-005"),
        "Refuse authentication until the session is protected",
        "Authentication was observed while the session was still in the clear. Once "
        "credentials have crossed an unprotected path they must be treated as "
        "disclosed, regardless of what the session does afterwards.",
        "Configure the mail service to advertise and accept authentication mechanisms "
        "only after TLS is active -- on SMTP submission this means not listing AUTH in "
        "the pre-STARTTLS EHLO response, and refusing AUTH before STARTTLS. Apply the "
        "same rule on IMAP (LOGINDISABLED until STARTTLS) and POP3.",
        "A client cannot submit credentials over an unprotected channel even if it "
        "would otherwise try, so this class of exposure stops occurring.",
        "Clients configured to authenticate without TLS will break, which is the "
        "intended outcome but needs communicating. Treat every credential observed in "
        "this capture as compromised and rotate it; the configuration change does not "
        "undo the exposure that already happened.",
        (
            "Re-capture a submission session and confirm no authentication mechanism "
            "is advertised before the upgrade.",
            "Confirm the server rejects an authentication command issued before TLS.",
            "Confirm the credentials observed in the original capture have been rotated.",
        ),
        ("RFC8314", "RFC9325-3.2"),
    ),
    _remediation(
        "REM-MAIL-ENABLE-STARTTLS",
        ("MAIL-001", "MAIL-003", "MAIL-005", "MAIL-006"),
        "Offer and accept opportunistic TLS on plaintext email ports",
        "The session ran in the clear because the server either did not advertise an "
        "upgrade mechanism or refused one that was requested. RFC 3207 defines "
        "STARTTLS for SMTP and RFC 2595 defines STLS for POP3 and STARTTLS for IMAP.",
        "Install a certificate for the service and enable STARTTLS on ports 25 and "
        "587, and STARTTLS/STLS on 143 and 110. Ensure the capability is advertised in "
        "the EHLO, CAPABILITY or CAPA response and that the server actually completes "
        "the upgrade when asked.",
        "Clients that support opportunistic TLS obtain a protected channel instead of "
        "continuing in the clear.",
        "Opportunistic TLS is strippable by an active attacker, so it improves on "
        "plaintext without being equivalent to implicit TLS. Prefer implicit TLS ports "
        "for client submission and access; keep STARTTLS for MTA-to-MTA, where "
        "requiring it can bounce mail.",
        (
            "Re-capture a session and confirm the upgrade capability is advertised.",
            "Confirm the server completes the upgrade when the client requests it.",
            "Confirm the certificate presented on the upgraded session is the intended "
            "one.",
        ),
        ("RFC3207", "RFC8314"),
    ),
    _remediation(
        "REM-MAIL-IMPLICIT-TLS",
        ("MAIL-003", "MAIL-006"),
        "Prefer implicit TLS ports for client submission and access",
        "Opportunistic upgrade can be stripped by an attacker who can modify the "
        "plaintext phase, because the capability advertisement itself is unprotected. "
        "RFC 8314 §3 recommends implicit TLS for message submission and access.",
        "Enable implicit TLS on port 465 for submission, 993 for IMAP and 995 for "
        "POP3, and configure mail clients to use those ports. Keep the plaintext ports "
        "available only for as long as migration requires.",
        "The session is protected from its first byte, so there is no unprotected "
        "phase in which an upgrade could be stripped.",
        "This is a client-configuration change as much as a server one, so plan the "
        "migration and keep both available during it. MTA-to-MTA traffic on port 25 "
        "still relies on STARTTLS and is out of scope for this change.",
        (
            "Re-capture a client session and confirm it connects to the implicit TLS "
            "port.",
            "Confirm the implicit TLS listener presents the intended certificate.",
            "Confirm clients have been migrated before withdrawing the plaintext port.",
        ),
        ("RFC8314",),
    ),
)

REMEDIATIONS: Final[dict[str, Remediation]] = {
    item.remediation_id: item for item in _REMEDIATIONS
}


def remediation(remediation_id: str) -> Remediation:
    return REMEDIATIONS[remediation_id]
