"""Multi-capture investigation fixtures (M5, groups A-T).

Each group is a small set of captures designed so that exactly one
intelligence behaviour is under test, together with a hand-derived expectation
of what the engine must conclude -- including, for several groups, what it must
**refuse** to conclude.

The negative groups are the important ones. ``L_unrelated_same_configuration``
puts two entirely unrelated servers, with different certificates and different
keys, on the same TLS settings; the engine must record a configuration match
and must not merge them or claim any certificate relationship. Groups like that
are how a correlation engine is kept from turning coincidence into a finding.

Captures are assembled byte by byte from the RFC structures so the scenarios --
an identical client offer against two different server configurations, a
certificate renewal that keeps its key -- can be constructed exactly. The
synthetic authority generates fresh keys per build, so captures carrying
certificates are not byte-reproducible; their expectations are semantic.

No real traffic, no real server and no real certificate is involved, and no
capture or key material is committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from .certs import CAPTURE_EPOCH, IssuedCertificate, SyntheticCA
from .dialogue import Dialogue
from .tls_messages import (
    CONTENT_HANDSHAKE,
    TLS10,
    TLS12,
    TLS13,
    certificate_message,
    client_hello,
    record,
    server_hello,
    server_hello_done,
)
from .writers import write_pcap

__all__ = [
    "InvestigationFixture",
    "ExpectedInvestigation",
    "ExpectedDrift",
    "ExpectedBlast",
    "build_investigation_fixtures",
]

IDENTITY: Final = "mail.example.invalid"
OTHER_IDENTITY: Final = "mail.other.invalid"
CAPTURE_NS: Final = int(CAPTURE_EPOCH.timestamp()) * 1_000_000_000
HOUR_NS: Final = 3_600_000_000_000

SERVER_A: Final = "198.51.100.25"
SERVER_B: Final = "198.51.100.40"

#: A rich offer and a narrow one. Two captures sharing an offer signature ask
#: the server the same question, which is what makes a different answer
#: attributable to the server rather than to the client.
WIDE_SUITES: Final = [0xC02B, 0xC030, 0x009C, 0x002F, 0x0005]
NARROW_SUITES: Final = [0x002F]

_CA: SyntheticCA | None = None


def _ca() -> SyntheticCA:
    global _CA
    if _CA is None:
        _CA = SyntheticCA()
    return _CA


@dataclass(frozen=True)
class ExpectedDrift:
    kind: str
    status: str


@dataclass(frozen=True)
class ExpectedBlast:
    rule_id: str
    session_count: int
    entity_count: int
    capture_count: int


@dataclass(frozen=True)
class ExpectedInvestigation:
    """Hand-derived expectations for one fixture group.

    Every field was worked out from the fixture's construction, not read back
    from the engine. The ``forbidden_*`` fields are the negative half and carry
    most of the value: they say what the evidence does not support.
    """

    entity_count: int
    capture_statuses: list[str]
    fingerprint_completeness: list[str] = field(default_factory=list)
    drift: list[ExpectedDrift] = field(default_factory=list)
    correlation_types: list[str] = field(default_factory=list)
    identity_relations: list[str] = field(default_factory=list)
    blast_radius: list[ExpectedBlast] = field(default_factory=list)
    #: Drift kinds that must NOT be reported as an observed change.
    forbidden_observed_changes: list[str] = field(default_factory=list)
    #: Correlation types the evidence does not support.
    forbidden_correlation_types: list[str] = field(default_factory=list)
    #: Identity relations the evidence does not support.
    forbidden_identity_relations: list[str] = field(default_factory=list)
    warning_codes: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(frozen=True)
class InvestigationFixture:
    name: str
    description: str
    generation: str
    captures: list[tuple[str, bytes]]
    expected: ExpectedInvestigation
    byte_reproducible: bool = False


# ---------------------------------------------------------------------------
# construction helpers
# ---------------------------------------------------------------------------
def _tls_capture(
    *,
    server_ip: str = SERVER_A,
    server_port: int = 993,
    offered: list[int],
    selected: int | None,
    legacy_version: int = TLS12,
    client_version: int | None = None,
    supported_version: int | None = None,
    leaf: IssuedCertificate | None,
    start_ns: int = CAPTURE_NS,
    client_port: int = 49152,
    sni: str | None = IDENTITY,
) -> bytes:
    """One implicit-TLS session with exactly the requested parameters.

    ``selected=None`` produces a capture with a ClientHello and no ServerHello,
    which is how the "missing evidence" groups are built.
    """
    dialogue = Dialogue(
        server_ip=server_ip,
        server_port=server_port,
        client_port=client_port,
        handshake=True,
        start_ns=start_ns,
    )
    # The client's advertised version is held separate from the server's
    # selection, so a fixture can present the *same* offer to two differently
    # configured servers. Without that the offer changes too, and a genuine
    # server-side change is indistinguishable from a different question.
    hello_version = (
        TLS12 if supported_version == TLS13 else (client_version or legacy_version)
    )
    dialogue.send_client(
        record(
            CONTENT_HANDSHAKE,
            client_hello(
                legacy_version=hello_version,
                cipher_suites=offered,
                server_name=sni,
                supported_versions=[TLS13, TLS12] if supported_version == TLS13 else None,
                key_share_groups=[0x001D] if supported_version == TLS13 else None,
            ),
            version=hello_version,
        )
    )
    if selected is not None:
        flight = server_hello(
            legacy_version=legacy_version,
            cipher_suite=selected,
            supported_version=supported_version,
            key_share_group=0x001D if supported_version == TLS13 else None,
        )
        if leaf is not None and supported_version != TLS13:
            flight += certificate_message([leaf.der]) + server_hello_done()
        dialogue.send_server(record(CONTENT_HANDSHAKE, flight, version=hello_version))
    return write_pcap(dialogue.packets)


def _fixture(
    name: str,
    description: str,
    captures: list[tuple[str, bytes]],
    expected: ExpectedInvestigation,
) -> InvestigationFixture:
    return InvestigationFixture(
        name=name,
        description=description,
        generation=f"securemailscope.testing.investigation_fixtures ({name})",
        captures=captures,
        expected=expected,
    )


# ---------------------------------------------------------------------------
# A: the same configuration, observed twice
# ---------------------------------------------------------------------------
def _group_a() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=500)
    return _fixture(
        "A_same_configuration",
        "One endpoint, two captures an hour apart, identical client offers and "
        "identical server selections. Every comparable property must come back "
        "UNCHANGED_WITH_EVIDENCE -- positive evidence of stability, which is a "
        "different statement from having found nothing.",
        [
            (
                "a1_first.pcap",
                _tls_capture(
                    offered=WIDE_SUITES, selected=0xC02B, leaf=leaf, start_ns=CAPTURE_NS
                ),
            ),
            (
                "a2_second.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            fingerprint_completeness=["PARTIAL", "PARTIAL"],
            drift=[
                ExpectedDrift("NEGOTIATED_VERSION", "UNCHANGED_WITH_EVIDENCE"),
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "UNCHANGED_WITH_EVIDENCE"),
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "UNCHANGED_WITH_EVIDENCE"),
                ExpectedDrift("CERTIFICATE_PUBLIC_KEY", "UNCHANGED_WITH_EVIDENCE"),
            ],
            correlation_types=["SHARED_CERTIFICATE", "SHARED_ENDPOINT", "SHARED_PUBLIC_KEY"],
            forbidden_observed_changes=[
                "NEGOTIATED_VERSION",
                "NEGOTIATED_CIPHER_SUITE",
                "CERTIFICATE_FINGERPRINT",
                "CERTIFICATE_PUBLIC_KEY",
                "POSTURE_SCORE",
            ],
            forbidden_correlation_types=["ENDPOINT_CONFIGURATION_DIVERGENCE"],
            notes="Identical configuration must produce no drift of any kind.",
        ),
    )


# ---------------------------------------------------------------------------
# B, C: genuine change, with the client offer held constant
# ---------------------------------------------------------------------------
def _group_b() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=501)
    return _fixture(
        "B_version_downgrade",
        "One endpoint, the same client offer in both captures, but the server "
        "selects TLS 1.2 and then TLS 1.0. Because the offer is identical, the "
        "difference is attributable to the server: OBSERVED_CHANGE.",
        [
            (
                "b1_tls12.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0x002F,
                    legacy_version=TLS12,
                    client_version=TLS12,
                    leaf=leaf,
                ),
            ),
            (
                "b2_tls10.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0x002F,
                    legacy_version=TLS10,
                    # The client still advertises TLS 1.2: only the server's
                    # answer changed, which is what makes this attributable.
                    client_version=TLS12,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            drift=[
                ExpectedDrift("NEGOTIATED_VERSION", "OBSERVED_CHANGE"),
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "UNCHANGED_WITH_EVIDENCE"),
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "UNCHANGED_WITH_EVIDENCE"),
            ],
            correlation_types=[
                "ENDPOINT_CONFIGURATION_DIVERGENCE",
                "SHARED_CERTIFICATE",
                "SHARED_ENDPOINT",
                "SHARED_PUBLIC_KEY",
                "SHARED_RULE_FAILURE",
            ],
            # Only the later capture negotiated TLS 1.0, so TLS-PROTO-001 is
            # one session. The CBC suite was negotiated in both, so its
            # findings span two sessions on the one endpoint.
            blast_radius=[
                ExpectedBlast("TLS-PROTO-001", 1, 1, 1),
                ExpectedBlast("TLS-CIPHER-005", 2, 1, 2),
                ExpectedBlast("TLS-KEX-001", 2, 1, 2),
            ],
            forbidden_observed_changes=["CERTIFICATE_FINGERPRINT", "CERTIFICATE_PUBLIC_KEY"],
            notes="Same offer, different selection: the server moved.",
        ),
    )


def _group_c() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=502)
    return _fixture(
        "C_cipher_suite_change",
        "One endpoint, the same client offer, a different cipher suite "
        "selected. Attributable to the server for the same reason as group B.",
        [
            ("c1_gcm.pcap", _tls_capture(offered=WIDE_SUITES, selected=0xC02B, leaf=leaf)),
            (
                "c2_cbc.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0x002F,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            drift=[
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "OBSERVED_CHANGE"),
                ExpectedDrift("NEGOTIATED_VERSION", "UNCHANGED_WITH_EVIDENCE"),
            ],
            correlation_types=[
                "ENDPOINT_CONFIGURATION_DIVERGENCE",
                "SHARED_CERTIFICATE",
                "SHARED_ENDPOINT",
                "SHARED_PUBLIC_KEY",
            ],
            forbidden_observed_changes=["NEGOTIATED_VERSION", "CERTIFICATE_FINGERPRINT"],
        ),
    )


# ---------------------------------------------------------------------------
# D: different offers, different selections -- not a server change
# ---------------------------------------------------------------------------
def _group_d() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=503)
    return _fixture(
        "D_different_client_offers",
        "One endpoint selecting different suites for two clients that offered "
        "different things. A server answering two different questions "
        "differently has not been shown to have changed: INCONCLUSIVE, with "
        "the offers recorded.",
        [
            ("d1_wide_offer.pcap", _tls_capture(offered=WIDE_SUITES, selected=0xC02B, leaf=leaf)),
            (
                "d2_narrow_offer.pcap",
                _tls_capture(
                    offered=NARROW_SUITES,
                    selected=0x002F,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            drift=[
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "INCONCLUSIVE"),
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "UNCHANGED_WITH_EVIDENCE"),
            ],
            correlation_types=[
                "ENDPOINT_CONFIGURATION_DIVERGENCE",
                "SHARED_CERTIFICATE",
                "SHARED_ENDPOINT",
                "SHARED_PUBLIC_KEY",
            ],
            forbidden_observed_changes=["NEGOTIATED_CIPHER_SUITE", "NEGOTIATED_VERSION"],
            notes=(
                "The central conservatism test for drift. A divergence is "
                "reported -- two different configurations were observed -- but "
                "the drift event refuses to attribute it to the server."
            ),
        ),
    )


# ---------------------------------------------------------------------------
# E: certificate rotation that keeps the key
# ---------------------------------------------------------------------------
def _group_e() -> InvestigationFixture:
    authority = _ca()
    first = authority.issue(IDENTITY, sans=[IDENTITY], serial=504)
    renewed = authority.reissue(first, serial=505)
    return _fixture(
        "E_certificate_rotation_same_key",
        "One endpoint presenting a renewed certificate built on the same key "
        "pair. The certificate fingerprint changes and the public-key "
        "fingerprint does not, which is exactly what distinguishes a renewal "
        "from a rekey.",
        [
            ("e1_original.pcap", _tls_capture(offered=WIDE_SUITES, selected=0xC02B, leaf=first)),
            (
                "e2_renewed.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=renewed,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            drift=[
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "OBSERVED_CHANGE"),
                ExpectedDrift("CERTIFICATE_PUBLIC_KEY", "UNCHANGED_WITH_EVIDENCE"),
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "UNCHANGED_WITH_EVIDENCE"),
            ],
            correlation_types=["SHARED_ENDPOINT", "SHARED_PUBLIC_KEY"],
            forbidden_observed_changes=["CERTIFICATE_PUBLIC_KEY", "NEGOTIATED_CIPHER_SUITE"],
            forbidden_correlation_types=[
                "SHARED_CERTIFICATE",
                # The settings did not diverge; only the certificate changed.
                "ENDPOINT_CONFIGURATION_DIVERGENCE",
            ],
            notes="Renewal, not rekey. The key fingerprint is what says so.",
        ),
    )


# ---------------------------------------------------------------------------
# F, L: shared and coincidental properties across distinct endpoints
# ---------------------------------------------------------------------------
def _group_f() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY, OTHER_IDENTITY], serial=506)
    return _fixture(
        "F_shared_certificate_distinct_endpoints",
        "Two different IP addresses presenting the same certificate, which is "
        "what a load-balanced pool and a shared-hosting provider both look "
        "like. Two entities must remain two entities, linked by a typed "
        "SHARED_CERTIFICATE relationship and not merged.",
        [
            (
                "f1_endpoint_a.pcap",
                _tls_capture(server_ip=SERVER_A, offered=WIDE_SUITES, selected=0xC02B, leaf=leaf),
            ),
            (
                "f2_endpoint_b.pcap",
                _tls_capture(
                    server_ip=SERVER_B,
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=2,
            capture_statuses=["ANALYZED", "ANALYZED"],
            identity_relations=[
                "SHARED_CERTIFICATE",
                "SHARED_PUBLIC_KEY",
                "OBSERVED_SNI",
                "CONFIGURATION_MATCH",
            ],
            correlation_types=["SHARED_CERTIFICATE", "SHARED_PUBLIC_KEY"],
            forbidden_correlation_types=["SHARED_ENDPOINT"],
            # A certificate link is already strong, so no POSSIBLE_RELATION is
            # added on top: it would add nothing and read as a second finding.
            forbidden_identity_relations=["POSSIBLE_RELATION"],
            notes="A shared certificate must never collapse two endpoints into one.",
        ),
    )


def _group_l() -> InvestigationFixture:
    authority = _ca()
    one = authority.issue(IDENTITY, sans=[IDENTITY], serial=507)
    two = authority.issue(OTHER_IDENTITY, sans=[OTHER_IDENTITY], serial=508)
    return _fixture(
        "L_unrelated_same_configuration",
        "Two unrelated servers with identical TLS settings and entirely "
        "different certificates, keys and names -- what two hosts installed "
        "from the same distribution defaults look like. A CONFIGURATION_MATCH "
        "may be recorded. Any certificate or key relationship, and any "
        "POSSIBLE_RELATION, would be a false correlation.",
        [
            (
                "l1_server_one.pcap",
                _tls_capture(
                    server_ip=SERVER_A,
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=one,
                    sni=IDENTITY,
                ),
            ),
            (
                "l2_server_two.pcap",
                _tls_capture(
                    server_ip=SERVER_B,
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=two,
                    sni=OTHER_IDENTITY,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=2,
            capture_statuses=["ANALYZED", "ANALYZED"],
            identity_relations=["CONFIGURATION_MATCH"],
            forbidden_identity_relations=[
                "SHARED_CERTIFICATE",
                "SHARED_PUBLIC_KEY",
                "OBSERVED_SNI",
                # Two weak signals are required, and the names differ, so the
                # engine must stop at "configured alike".
                "POSSIBLE_RELATION",
            ],
            forbidden_correlation_types=[
                "SHARED_CERTIFICATE",
                "SHARED_PUBLIC_KEY",
                "SHARED_ENDPOINT",
            ],
            notes="The primary false-correlation test.",
        ),
    )


# ---------------------------------------------------------------------------
# G: one address, several services
# ---------------------------------------------------------------------------
def _group_g() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=509)
    return _fixture(
        "G_same_ip_multiple_services",
        "One IP address serving two ports. These are two independently "
        "configurable services and must be two entities: merging them would "
        "attribute one service's weakness to the other.",
        [
            (
                "g1_imaps.pcap",
                _tls_capture(server_port=993, offered=WIDE_SUITES, selected=0xC02B, leaf=leaf),
            ),
            (
                "g2_submission.pcap",
                _tls_capture(
                    server_port=465,
                    offered=WIDE_SUITES,
                    selected=0x002F,
                    leaf=leaf,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=2,
            capture_statuses=["ANALYZED", "ANALYZED"],
            identity_relations=["SHARED_CERTIFICATE", "SHARED_PUBLIC_KEY"],
            forbidden_correlation_types=["SHARED_ENDPOINT"],
            notes="Same IP is not the same application.",
        ),
    )


# ---------------------------------------------------------------------------
# H, I, R: missing and encrypted evidence
# ---------------------------------------------------------------------------
def _group_h() -> InvestigationFixture:
    return _fixture(
        "H_tls13_encrypted_certificate_both",
        "Two TLS 1.3 captures. The Certificate message is encrypted in both, "
        "so no certificate component exists on either side. Fingerprints must "
        "be PARTIAL, certificate drift must be NOT_COMPARABLE, and no "
        "certificate relationship may be claimed.",
        [
            (
                "h1_tls13.pcap",
                _tls_capture(
                    offered=[0x1301],
                    selected=0x1301,
                    supported_version=TLS13,
                    leaf=None,
                ),
            ),
            (
                "h2_tls13.pcap",
                _tls_capture(
                    offered=[0x1301],
                    selected=0x1301,
                    supported_version=TLS13,
                    leaf=None,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            fingerprint_completeness=["PARTIAL", "PARTIAL"],
            drift=[
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "NOT_COMPARABLE"),
                ExpectedDrift("CERTIFICATE_PUBLIC_KEY", "NOT_COMPARABLE"),
                ExpectedDrift("NEGOTIATED_VERSION", "UNCHANGED_WITH_EVIDENCE"),
            ],
            forbidden_observed_changes=["CERTIFICATE_FINGERPRINT", "CERTIFICATE_PUBLIC_KEY"],
            forbidden_correlation_types=["SHARED_CERTIFICATE", "SHARED_PUBLIC_KEY"],
            notes="Encryption is not absence of a certificate, and not a fault.",
        ),
    )


def _group_i() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=510)
    return _fixture(
        "I_missing_server_hello",
        "A complete capture followed by one holding only a ClientHello. Every "
        "server-side property is NOT_COMPARABLE: the second capture did not "
        "observe them, which is not the same as their having changed.",
        [
            ("i1_complete.pcap", _tls_capture(offered=WIDE_SUITES, selected=0xC02B, leaf=leaf)),
            (
                "i2_client_hello_only.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=None,
                    leaf=None,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            fingerprint_completeness=["INSUFFICIENT", "PARTIAL"],
            drift=[
                ExpectedDrift("NEGOTIATED_VERSION", "NOT_COMPARABLE"),
                ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "NOT_COMPARABLE"),
                ExpectedDrift("CERTIFICATE_FINGERPRINT", "NOT_COMPARABLE"),
            ],
            forbidden_observed_changes=[
                "NEGOTIATED_VERSION",
                "NEGOTIATED_CIPHER_SUITE",
                "CERTIFICATE_FINGERPRINT",
            ],
            notes="Gate 7: missing evidence is never reported as drift.",
        ),
    )


# ---------------------------------------------------------------------------
# J, Q: findings repeating across sessions and endpoints
# ---------------------------------------------------------------------------
def _group_q() -> InvestigationFixture:
    authority = _ca()
    one = authority.issue(IDENTITY, sans=[IDENTITY], serial=511)
    two = authority.issue(OTHER_IDENTITY, sans=[OTHER_IDENTITY], serial=512)
    return _fixture(
        "Q_same_finding_across_endpoints",
        "Two distinct endpoints both negotiating an obsolete version with a "
        "static-RSA suite. The shared rule failure must correlate, and the "
        "blast radius must count two sessions across two endpoints in two "
        "captures -- numbers that have to come from the evidence.",
        [
            (
                "q1_endpoint_a.pcap",
                _tls_capture(
                    server_ip=SERVER_A,
                    offered=NARROW_SUITES,
                    selected=0x002F,
                    legacy_version=TLS10,
                    client_version=TLS12,
                    leaf=one,
                ),
            ),
            (
                "q2_endpoint_b.pcap",
                _tls_capture(
                    server_ip=SERVER_B,
                    offered=NARROW_SUITES,
                    selected=0x002F,
                    legacy_version=TLS10,
                    client_version=TLS12,
                    leaf=two,
                    start_ns=CAPTURE_NS + HOUR_NS,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=2,
            capture_statuses=["ANALYZED", "ANALYZED"],
            correlation_types=[
                "REPEATED_OBSOLETE_TLS",
                "SHARED_RULE_FAILURE",
            ],
            # Both clients request the same name and both servers negotiate
            # the same settings: two weak signals with no strong one, which is
            # exactly the POSSIBLE_RELATION case. Different certificates and
            # different keys keep it from becoming anything stronger.
            identity_relations=[
                "OBSERVED_SNI",
                "CONFIGURATION_MATCH",
                "POSSIBLE_RELATION",
            ],
            blast_radius=[
                ExpectedBlast("TLS-PROTO-001", 2, 2, 2),
                ExpectedBlast("TLS-KEX-001", 2, 2, 2),
                ExpectedBlast("TLS-CIPHER-005", 2, 2, 2),
            ],
            forbidden_correlation_types=["SHARED_CERTIFICATE", "SHARED_ENDPOINT"],
            forbidden_identity_relations=["SHARED_CERTIFICATE", "SHARED_PUBLIC_KEY"],
            notes="Gate 12: blast-radius counts must match the observations.",
        ),
    )


# ---------------------------------------------------------------------------
# K: the same capture supplied twice
# ---------------------------------------------------------------------------
def _group_k() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=513)
    data = _tls_capture(
        offered=NARROW_SUITES,
        selected=0x002F,
        legacy_version=TLS10,
        client_version=TLS12,
        leaf=leaf,
    )
    return _fixture(
        "K_duplicate_capture",
        "The same bytes supplied twice under two names. The second must be "
        "recorded as a DUPLICATE and must not inflate any count: two file "
        "names are not two pieces of evidence.",
        [("k1_original.pcap", data), ("k2_copy_renamed.pcap", data)],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "DUPLICATE"],
            blast_radius=[ExpectedBlast("TLS-PROTO-001", 1, 1, 1)],
            warning_codes=["DUPLICATE_CAPTURE"],
            forbidden_correlation_types=["SHARED_ENDPOINT", "SHARED_CERTIFICATE"],
            notes="Gate 13: a duplicate must not double a blast radius.",
        ),
    )


# ---------------------------------------------------------------------------
# M, N: chronology
# ---------------------------------------------------------------------------
def _group_m() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=514)
    later = _tls_capture(
        offered=WIDE_SUITES, selected=0x002F, leaf=leaf, start_ns=CAPTURE_NS + HOUR_NS
    )
    earlier = _tls_capture(
        offered=WIDE_SUITES, selected=0xC02B, leaf=leaf, start_ns=CAPTURE_NS
    )
    return _fixture(
        "M_out_of_order_arguments",
        "The chronologically later capture is supplied first. Drift must "
        "follow the capture timestamps, not the argument order, so the "
        "reported direction is GCM then CBC rather than the reverse.",
        [("m1_later_supplied_first.pcap", later), ("m2_earlier.pcap", earlier)],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            drift=[ExpectedDrift("NEGOTIATED_CIPHER_SUITE", "OBSERVED_CHANGE")],
            notes="Chronology comes from the capture, never from the command line.",
        ),
    )


def _group_n() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=515)
    return _fixture(
        "N_overlapping_time_ranges",
        "Two captures whose time ranges overlap, taken from two clients "
        "against one endpoint. Ordering within the investigation must still be "
        "deterministic, and the clock limitations must be stated.",
        [
            (
                "n1_overlap_first.pcap",
                _tls_capture(
                    offered=WIDE_SUITES, selected=0xC02B, leaf=leaf, client_port=49152
                ),
            ),
            (
                "n2_overlap_second.pcap",
                _tls_capture(
                    offered=WIDE_SUITES,
                    selected=0xC02B,
                    leaf=leaf,
                    client_port=49153,
                    start_ns=CAPTURE_NS + 1_000_000,
                ),
            ),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "ANALYZED"],
            correlation_types=["SHARED_CERTIFICATE", "SHARED_ENDPOINT", "SHARED_PUBLIC_KEY"],
            forbidden_observed_changes=["NEGOTIATED_CIPHER_SUITE", "CERTIFICATE_FINGERPRINT"],
            notes="Different source ports are one endpoint, not two.",
        ),
    )


# ---------------------------------------------------------------------------
# T: a batch member that cannot be analysed
# ---------------------------------------------------------------------------
def _group_t() -> InvestigationFixture:
    leaf = _ca().issue(IDENTITY, sans=[IDENTITY], serial=516)
    return _fixture(
        "T_malformed_batch_member",
        "A valid capture alongside a file that is not a capture at all. The "
        "failure must appear in the inventory with its reason and raise a "
        "warning: a reader must not take the surviving results as covering "
        "everything they submitted.",
        [
            ("t1_valid.pcap", _tls_capture(offered=WIDE_SUITES, selected=0xC02B, leaf=leaf)),
            ("t2_not_a_capture.pcap", b"this is not a capture file, not even close\n"),
        ],
        ExpectedInvestigation(
            entity_count=1,
            capture_statuses=["ANALYZED", "FAILED"],
            warning_codes=["CAPTURE_FAILED"],
            notes="Gate: a failed capture never silently disappears.",
        ),
    )


_BUILDERS: Final = (
    _group_a,
    _group_b,
    _group_c,
    _group_d,
    _group_e,
    _group_f,
    _group_g,
    _group_h,
    _group_i,
    _group_k,
    _group_l,
    _group_m,
    _group_n,
    _group_q,
    _group_t,
)


def build_investigation_fixtures() -> list[InvestigationFixture]:
    return [builder() for builder in _BUILDERS]
