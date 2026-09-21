"""M4 assessment fixtures (AA-AC).

The M1-M3 fixture set already covers most of the configurations M4 needs to
assess: secure TLS 1.2 (T_A), TLS 1.3 with an encrypted certificate (T_D/T_E),
static RSA key exchange (T_C), expired and not-yet-valid certificates (T_O,
T_P), chain and hostname failures (T_S, T_T), missing validation evidence
(T_R), insufficient evidence for scoring (T_G), plaintext authentication
(P_M), a rejected STARTTLS (P_B) and an incomplete upgrade (P_J/P_K). Those
fixtures are reused rather than duplicated.

Three configurations were not reachable from the earlier milestones, because
the local OpenSSL will not negotiate them at any security level:

* **AA** -- an obsolete *negotiated* protocol version. T_M offers TLS 1.0 but
  M3 had no fixture where a server actually selected it.
* **AB** -- NULL encryption, which is the cleanest case of one underlying
  weakness tripping several rules in the same de-duplication group.
* **AC** -- an RC4 cipher suite, prohibited by RFC 7465 and RFC 9325.

Each is assembled byte by byte from the RFC structures, so the handshake is
standards-conformant without needing a library that still implements these
constructions. The certificate is issued by the synthetic authority, which
generates a fresh key per build, so the captures are not byte-reproducible;
their manifests assert negotiated parameters and assessment outcomes instead
of a capture hash.

Every expected score in this module was computed by hand from the policy
weights and the expected rule outcomes. None of it was read back from
:mod:`securemailscope.assessment.scoring`. The working is written out in each
fixture's docstring so a reviewer can check the arithmetic without running the
code, and so that a change in the scoring implementation fails a test rather
than quietly redefining the answer.
"""

from __future__ import annotations

from typing import Final

from .certs import CAPTURE_EPOCH, SyntheticCA
from .dialogue import Dialogue
from .fixtures import FixtureSpec
from .manifest import (
    ExpectedAssessment,
    ExpectedFinding,
    ExpectedRuleOutcome,
    ExpectedScore,
    ExpectedTLS,
)
from .tls_messages import (
    CONTENT_HANDSHAKE,
    TLS10,
    TLS12,
    certificate_message,
    client_hello,
    record,
    server_hello,
    server_hello_done,
)
from .writers import write_pcap

__all__ = ["build_assessment_fixtures", "ASSESSMENT_IDENTITY"]

ASSESSMENT_IDENTITY: Final = "mail.example.invalid"
CAPTURE_TIMESTAMP_NS: Final = int(CAPTURE_EPOCH.timestamp()) * 1_000_000_000

_CA: SyntheticCA | None = None


def _ca() -> SyntheticCA:
    global _CA
    if _CA is None:
        _CA = SyntheticCA()
    return _CA


def _handshake(
    *, legacy_version: int, cipher_suite: int, serial: int
) -> tuple[Dialogue, str]:
    """One implicit-TLS session negotiating exactly the requested parameters."""
    leaf = _ca().issue(
        ASSESSMENT_IDENTITY, sans=[ASSESSMENT_IDENTITY], serial=serial
    )
    dialogue = Dialogue(server_port=993, handshake=True, start_ns=CAPTURE_TIMESTAMP_NS)
    dialogue.send_client(
        record(
            CONTENT_HANDSHAKE,
            client_hello(
                legacy_version=legacy_version,
                cipher_suites=[cipher_suite],
                server_name=ASSESSMENT_IDENTITY,
            ),
            version=legacy_version,
        )
    )
    dialogue.send_server(
        record(
            CONTENT_HANDSHAKE,
            server_hello(legacy_version=legacy_version, cipher_suite=cipher_suite)
            + certificate_message([leaf.der])
            + server_hello_done(),
            version=legacy_version,
        )
    )
    return dialogue, leaf.certificate.subject.rfc4514_string()


def _spec(
    name: str,
    filename: str,
    description: str,
    generation: str,
    dialogue: Dialogue,
    tls: list[ExpectedTLS],
    assessment: list[ExpectedAssessment],
) -> FixtureSpec:
    packets = dialogue.packets
    return FixtureSpec(
        name=name,
        filename=filename,
        description=description,
        generation=generation,
        file_format="pcap",
        link_type_code=1,
        data=write_pcap(packets),
        timestamps_ns=[timestamp for timestamp, _ in packets],
        expected_packet_count=len(packets),
        expected_tcp_packet_count=len(packets),
        expected_sessions=[],
        expected_warning_codes=[],
        expected_tls=tls,
        expected_assessment=assessment,
        byte_reproducible=False,
    )


def _tls(
    *, version: str, suite: str, forward_secrecy: str, key_exchange: str
) -> ExpectedTLS:
    return ExpectedTLS(
        session_index=0,
        entry_point="IMPLICIT",
        handshake_state="SERVER_FLIGHT_COMPLETE",
        client_record_parse_state="COMPLETE",
        server_record_parse_state="COMPLETE",
        selected_version=version,
        selected_cipher_suite=suite,
        server_name_indication=ASSESSMENT_IDENTITY,
        message_types=[
            "client_hello",
            "server_hello",
            "certificate",
            "server_hello_done",
        ],
        cipher_key_exchange=key_exchange,
        key_exchange_method=key_exchange,
        key_exchange_source="CIPHER_SUITE",
        forward_secrecy_status=forward_secrecy,
        certificate_visibility="OBSERVED",
        certificate_count=1,
    )


#: Rules whose outcome is identical across all three fixtures, because every
#: fixture presents the same freshly issued, EC P-256, SHA-256 signed,
#: serverAuth certificate over implicit TLS with no trust store configured.
_SHARED_OUTCOMES: Final = (
    # No fatal alert: the server flight completed.
    ExpectedRuleOutcome("TLS-PROTO-003", "PASS", "LOW"),
    # The suite is in the build's registry, so nothing is unassessable.
    ExpectedRuleOutcome("TLS-CIPHER-006", "PASS", "INFO"),
    # These suites are all static RSA, and none carries a hybrid group.
    ExpectedRuleOutcome("TLS-KEX-001", "FAIL", "HIGH"),
    ExpectedRuleOutcome("TLS-KEX-002", "NOT_APPLICABLE"),
    # Issued 30 days before the capture epoch, valid for a further 365.
    ExpectedRuleOutcome("CERT-001", "PASS", "HIGH"),
    ExpectedRuleOutcome("CERT-002", "PASS", "HIGH"),
    # EC P-256: 256 bits, above the 224-bit floor.
    ExpectedRuleOutcome("CERT-003", "PASS", "HIGH"),
    ExpectedRuleOutcome("CERT-004", "PASS", "HIGH"),
    # No trust store and no expected identity are configured for these runs,
    # so chain and hostname are honestly UNKNOWN rather than assumed good.
    ExpectedRuleOutcome("CERT-005", "UNKNOWN", "HIGH"),
    ExpectedRuleOutcome("CERT-006", "UNKNOWN", "HIGH"),
    ExpectedRuleOutcome("CERT-007", "PASS", "MEDIUM"),
    # Port 993 with TLS from the first byte is a port hint, not an email
    # protocol identification, so the mail rules do not apply.
    ExpectedRuleOutcome("MAIL-001", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-002", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-003", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-004", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-005", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-006", "NOT_APPLICABLE"),
    ExpectedRuleOutcome("MAIL-007", "PASS", "INFO"),
)

#: Findings every fixture must NOT raise. Asserting absence is the only way a
#: false positive is caught; asserting presence alone never would.
_SHARED_FORBIDDEN: Final = [
    "TLS-PROTO-003",
    "TLS-CIPHER-002",
    "TLS-KEX-002",
    "CERT-001",
    "CERT-002",
    "CERT-003",
    "CERT-004",
    # UNKNOWN is not a finding: an unchecked chain is an evidence gap.
    "CERT-005",
    "CERT-006",
    "CERT-007",
    "MAIL-001",
    "MAIL-002",
    "MAIL-003",
    "MAIL-004",
    "MAIL-005",
    "MAIL-006",
    "MAIL-007",
]


def _fixture_aa() -> FixtureSpec:
    """An obsolete negotiated version, static RSA and an unapproved cipher.

    Also the "several independent findings in one session" case: three
    distinct weaknesses in three different de-duplication groups, plus one
    informational finding about the client.

    Scoring units with a non-zero weight (weight = the policy weight of the
    most severe rule producing the unit's outcome)::

        NEGOTIATED_PROTOCOL_VERSION  FAIL     TLS-PROTO-001   HIGH     6
        NEGOTIATED_CIPHER_SUITE      FAIL     TLS-CIPHER-005  MEDIUM   3
        FORWARD_SECRECY              FAIL     TLS-KEX-001     HIGH     6
        NEGOTIATION_OUTCOME          PASS     TLS-PROTO-003   LOW      1
        CERT_VALIDITY                PASS     CERT-001        HIGH     6
        CERT_KEY_STRENGTH            PASS     CERT-003        HIGH     6
        CERT_SIGNATURE               PASS     CERT-004        HIGH     6
        CERT_EKU                     PASS     CERT-007        MEDIUM   3
        CERT_CHAIN                   UNKNOWN  CERT-005        HIGH     6
        CERT_IDENTITY                UNKNOWN  CERT-006        HIGH     6

    OFFERED_PROTOCOL_VERSION (TLS-PROTO-002, INFO) and UNKNOWN_CIPHER_SUITE
    and IMPLICIT_TLS_VISIBILITY carry weight 0 and are excluded from the
    arithmetic, though TLS-PROTO-002 still produces a reportable finding.

        W(failed)     = 6 + 3 + 6                 = 15
        W(passed)     = 1 + 6 + 6 + 6 + 3         = 22
        W(evaluated)  = 15 + 22                   = 37
        W(unknown)    = 6 + 6                     = 12
        W(applicable) = 37 + 12                   = 49
        coverage      = 37 / 49                   = 0.7551...
        score         = 100 * (37 - 15) / 37      = 59.459... -> 59  (WEAK)
    """
    dialogue, _ = _handshake(legacy_version=TLS10, cipher_suite=0x002F, serial=400)
    score = ExpectedScore(
        status="AVAILABLE",
        score=59,
        band="WEAK",
        evaluated_units=8,
        passed_units=5,
        failed_units=3,
        unknown_units=2,
        weighted_evaluated=37.0,
        weighted_deductions=15.0,
        weighted_applicable=49.0,
        coverage_ratio=0.7551,
    )
    outcomes = [
        ExpectedRuleOutcome("TLS-PROTO-001", "FAIL", "HIGH", True),
        ExpectedRuleOutcome("TLS-PROTO-002", "FAIL", "INFO", True),
        ExpectedRuleOutcome("TLS-CIPHER-001", "PASS", "CRITICAL"),
        ExpectedRuleOutcome("TLS-CIPHER-002", "PASS", "CRITICAL"),
        ExpectedRuleOutcome("TLS-CIPHER-003", "PASS", "HIGH"),
        ExpectedRuleOutcome("TLS-CIPHER-004", "PASS", "MEDIUM"),
        ExpectedRuleOutcome("TLS-CIPHER-005", "FAIL", "MEDIUM", True),
        *_SHARED_OUTCOMES,
    ]
    return _spec(
        "AA_tls10_static_rsa_multiple_findings",
        "aa_tls10_static_rsa.pcap",
        "A server that negotiated TLS 1.0 with TLS_RSA_WITH_AES_128_CBC_SHA. Three "
        "independent weaknesses -- an obsolete negotiated version, no forward secrecy "
        "and a cipher outside the approved set -- plus an informational finding about "
        "the versions the client offered.",
        "securemailscope.testing.assessment_fixtures._fixture_aa (synthetic)",
        dialogue,
        [
            _tls(
                version="TLS 1.0",
                suite="TLS_RSA_WITH_AES_128_CBC_SHA",
                forward_secrecy="STATIC_RSA_KEY_EXCHANGE",
                key_exchange="RSA",
            )
        ],
        [
            ExpectedAssessment(
                session_index=0,
                score=score,
                rule_outcomes=outcomes,
                findings=[
                    # HIGH before MEDIUM before INFO; within HIGH, by rule id,
                    # so TLS-KEX-001 sorts before TLS-PROTO-001.
                    ExpectedFinding("TLS-KEX-001", "HIGH", "CONFIRMED", "P1", 1),
                    ExpectedFinding("TLS-PROTO-001", "HIGH", "CONFIRMED", "P1", 2),
                    ExpectedFinding("TLS-CIPHER-005", "MEDIUM", "CONFIRMED", "P2", 3),
                    ExpectedFinding("TLS-PROTO-002", "INFO", "CONFIRMED", "P4", 4),
                ],
                forbidden_finding_rule_ids=[
                    *_SHARED_FORBIDDEN,
                    "TLS-CIPHER-001",
                    "TLS-CIPHER-003",
                    "TLS-CIPHER-004",
                    "TLS-CIPHER-006",
                ],
                remediation_ids=[
                    "REM-TLS-FS",
                    "REM-TLS-VERSION",
                    "REM-TLS-CIPHER",
                ],
            )
        ],
    )


def _fixture_ab() -> FixtureSpec:
    """NULL encryption: one weakness, two rules, one finding.

    TLS_RSA_WITH_NULL_SHA256 trips TLS-CIPHER-001 (no encryption) and
    TLS-CIPHER-005 (outside the approved set). Both share the
    NEGOTIATED_CIPHER_SUITE group, so the more severe carries the unit and the
    other is suppressed: the weakness is counted once and reported once.

    TLS-CIPHER-003 passes, and deliberately so. The policy names TLS-CIPHER-001
    as the owner of NULL encryption, so the prohibited-construction rule does
    not also claim it. Ownership is how the catalogue avoids reporting one
    misconfigured setting under three headings at three severities.

    Scoring units with a non-zero weight::

        NEGOTIATED_CIPHER_SUITE      FAIL     TLS-CIPHER-001  CRITICAL 10
        FORWARD_SECRECY              FAIL     TLS-KEX-001     HIGH      6
        NEGOTIATED_PROTOCOL_VERSION  PASS     TLS-PROTO-001   HIGH      6
        NEGOTIATION_OUTCOME          PASS     TLS-PROTO-003   LOW       1
        CERT_VALIDITY                PASS     CERT-001        HIGH      6
        CERT_KEY_STRENGTH            PASS     CERT-003        HIGH      6
        CERT_SIGNATURE               PASS     CERT-004        HIGH      6
        CERT_EKU                     PASS     CERT-007        MEDIUM    3
        CERT_CHAIN                   UNKNOWN  CERT-005        HIGH      6
        CERT_IDENTITY                UNKNOWN  CERT-006        HIGH      6

        W(failed)     = 10 + 6                    = 16
        W(passed)     = 6 + 1 + 6 + 6 + 6 + 3     = 28
        W(evaluated)  = 16 + 28                   = 44
        W(unknown)    = 6 + 6                     = 12
        W(applicable) = 44 + 12                   = 56
        coverage      = 44 / 56                   = 0.7857...
        score         = 100 * (44 - 16) / 44      = 63.636... -> 64  (WEAK)

    Had both cipher rules been counted, the deduction would have been
    10 + 3 = 13 against a larger evaluated weight -- a different, and wrong,
    answer for a single misconfigured setting.
    """
    dialogue, _ = _handshake(legacy_version=TLS12, cipher_suite=0x003B, serial=401)
    score = ExpectedScore(
        status="AVAILABLE",
        score=64,
        band="WEAK",
        evaluated_units=8,
        passed_units=6,
        failed_units=2,
        unknown_units=2,
        weighted_evaluated=44.0,
        weighted_deductions=16.0,
        weighted_applicable=56.0,
        coverage_ratio=0.7857,
    )
    outcomes = [
        ExpectedRuleOutcome("TLS-PROTO-001", "PASS", "HIGH"),
        ExpectedRuleOutcome("TLS-PROTO-002", "PASS", "INFO"),
        ExpectedRuleOutcome("TLS-CIPHER-001", "FAIL", "CRITICAL", True),
        ExpectedRuleOutcome("TLS-CIPHER-002", "PASS", "CRITICAL"),
        # TLS-CIPHER-001 owns NULL, so the prohibition rule does not re-report it.
        ExpectedRuleOutcome("TLS-CIPHER-003", "PASS", "HIGH"),
        ExpectedRuleOutcome("TLS-CIPHER-004", "PASS", "MEDIUM"),
        # Suppressed: same weakness, same group, less severe than CIPHER-001.
        ExpectedRuleOutcome("TLS-CIPHER-005", "FAIL", "MEDIUM", False),
        *_SHARED_OUTCOMES,
    ]
    return _spec(
        "AB_null_cipher_duplicate_evidence",
        "ab_null_cipher.pcap",
        "A TLS 1.2 handshake negotiating TLS_RSA_WITH_NULL_SHA256. One misconfigured "
        "setting trips two cipher rules in the same de-duplication group; exactly "
        "one finding and one deduction must result.",
        "securemailscope.testing.assessment_fixtures._fixture_ab (synthetic)",
        dialogue,
        [
            _tls(
                version="TLS 1.2",
                suite="TLS_RSA_WITH_NULL_SHA256",
                forward_secrecy="STATIC_RSA_KEY_EXCHANGE",
                key_exchange="RSA",
            )
        ],
        [
            ExpectedAssessment(
                session_index=0,
                score=score,
                rule_outcomes=outcomes,
                findings=[
                    ExpectedFinding("TLS-CIPHER-001", "CRITICAL", "CONFIRMED", "P1", 1),
                    ExpectedFinding("TLS-KEX-001", "HIGH", "CONFIRMED", "P1", 2),
                ],
                forbidden_finding_rule_ids=[
                    *_SHARED_FORBIDDEN,
                    "TLS-PROTO-001",
                    "TLS-PROTO-002",
                    # Suppressed duplicates must not appear as findings.
                    "TLS-CIPHER-003",
                    "TLS-CIPHER-004",
                    "TLS-CIPHER-005",
                    "TLS-CIPHER-006",
                ],
                remediation_ids=["REM-TLS-CIPHER", "REM-TLS-FS"],
            )
        ],
    )


def _fixture_ac() -> FixtureSpec:
    """An RC4 cipher suite, prohibited by RFC 7465 and RFC 9325.

    Scoring units with a non-zero weight::

        NEGOTIATED_CIPHER_SUITE      FAIL     TLS-CIPHER-003  HIGH      6
        FORWARD_SECRECY              FAIL     TLS-KEX-001     HIGH      6
        NEGOTIATED_PROTOCOL_VERSION  PASS     TLS-PROTO-001   HIGH      6
        NEGOTIATION_OUTCOME          PASS     TLS-PROTO-003   LOW       1
        CERT_VALIDITY                PASS     CERT-001        HIGH      6
        CERT_KEY_STRENGTH            PASS     CERT-003        HIGH      6
        CERT_SIGNATURE               PASS     CERT-004        HIGH      6
        CERT_EKU                     PASS     CERT-007        MEDIUM    3
        CERT_CHAIN                   UNKNOWN  CERT-005        HIGH      6
        CERT_IDENTITY                UNKNOWN  CERT-006        HIGH      6

        W(failed)     = 6 + 6                     = 12
        W(passed)     = 6 + 1 + 6 + 6 + 6 + 3     = 28
        W(evaluated)  = 12 + 28                   = 40
        W(unknown)    = 6 + 6                     = 12
        W(applicable) = 40 + 12                   = 52
        coverage      = 40 / 52                   = 0.7692...
        score         = 100 * (40 - 12) / 40      = 70  (ADEQUATE)

    A score of 70 for an RC4 transport is a deliberate illustration of what
    the number is and is not. The score summarises weighted control coverage
    across a session whose certificate handling is otherwise sound; it is not
    a verdict on the worst finding. The finding list, where RC4 sits at P1, is
    the substance. :doc:`scoring-methodology` states this explicitly.
    """
    dialogue, _ = _handshake(legacy_version=TLS12, cipher_suite=0x0005, serial=402)
    score = ExpectedScore(
        status="AVAILABLE",
        score=70,
        band="ADEQUATE",
        evaluated_units=8,
        passed_units=6,
        failed_units=2,
        unknown_units=2,
        weighted_evaluated=40.0,
        weighted_deductions=12.0,
        weighted_applicable=52.0,
        coverage_ratio=0.7692,
    )
    outcomes = [
        ExpectedRuleOutcome("TLS-PROTO-001", "PASS", "HIGH"),
        ExpectedRuleOutcome("TLS-PROTO-002", "PASS", "INFO"),
        ExpectedRuleOutcome("TLS-CIPHER-001", "PASS", "CRITICAL"),
        ExpectedRuleOutcome("TLS-CIPHER-002", "PASS", "CRITICAL"),
        ExpectedRuleOutcome("TLS-CIPHER-003", "FAIL", "HIGH", True),
        ExpectedRuleOutcome("TLS-CIPHER-004", "PASS", "MEDIUM"),
        ExpectedRuleOutcome("TLS-CIPHER-005", "FAIL", "MEDIUM", False),
        *_SHARED_OUTCOMES,
    ]
    return _spec(
        "AC_rc4_weak_cipher",
        "ac_rc4_weak_cipher.pcap",
        "A TLS 1.2 handshake negotiating TLS_RSA_WITH_RC4_128_SHA. RC4 is prohibited "
        "by RFC 7465 and RFC 9325; the stream cipher is the finding, and the suite's "
        "static RSA key exchange is a second, independent one.",
        "securemailscope.testing.assessment_fixtures._fixture_ac (synthetic)",
        dialogue,
        [
            _tls(
                version="TLS 1.2",
                suite="TLS_RSA_WITH_RC4_128_SHA",
                forward_secrecy="STATIC_RSA_KEY_EXCHANGE",
                key_exchange="RSA",
            )
        ],
        [
            ExpectedAssessment(
                session_index=0,
                score=score,
                rule_outcomes=outcomes,
                findings=[
                    # Equal severity and confidence; ordered by rule id.
                    ExpectedFinding("TLS-CIPHER-003", "HIGH", "CONFIRMED", "P1", 1),
                    ExpectedFinding("TLS-KEX-001", "HIGH", "CONFIRMED", "P1", 2),
                ],
                forbidden_finding_rule_ids=[
                    *_SHARED_FORBIDDEN,
                    "TLS-PROTO-001",
                    "TLS-PROTO-002",
                    "TLS-CIPHER-001",
                    "TLS-CIPHER-004",
                    "TLS-CIPHER-005",
                    "TLS-CIPHER-006",
                ],
                remediation_ids=["REM-TLS-CIPHER", "REM-TLS-FS"],
            )
        ],
    )


_BUILDERS: Final = (_fixture_aa, _fixture_ab, _fixture_ac)


def build_assessment_fixtures() -> list[FixtureSpec]:
    return [builder() for builder in _BUILDERS]
