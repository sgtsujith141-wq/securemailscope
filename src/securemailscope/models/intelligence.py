"""Forensic intelligence contracts (M5).

M1-M3 answer *what was observed*. M4 answers *what that means under a policy*.
M5 answers *what the observations across several captures have in common* --
and the hardest part of that job is refusing to answer when the evidence does
not support an answer.

Four ideas shape these models:

* **An endpoint is the unit of identity, and entities are never merged.**  A
  :class:`ServerEntity` is one observed ``(ip, port)``.  Two entities that
  share a certificate are linked by a typed :class:`IdentityRelationship`,
  never combined: a shared certificate establishes a shared certificate, not a
  shared machine.  Load balancers, shared hosting and SNI-based virtual hosting
  all make the naive merge wrong.
* **A fingerprint is an index, not an identity.**  Two sessions with the same
  cryptographic fingerprint were configured alike.  Nothing here claims they
  ran on the same host, and :class:`FingerprintCompleteness` records exactly
  how much of the fingerprint the capture actually supplied.
* **Absence is not change.**  A parameter missing from the second capture is
  ``NOT_COMPARABLE``, never ``OBSERVED_CHANGE``.  A server that selected a
  different suite for a different client offer is ``INCONCLUSIVE``, because the
  offer changed too.
* **Counts are scoped to what was analysed.**  Every blast-radius number
  carries ``Observed within analyzed captures only``.  Unobserved infrastructure
  stays unobserved.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import PacketReference

__all__ = [
    "FingerprintSource",
    "FingerprintCompleteness",
    "FingerprintMatch",
    "IdentityRelation",
    "DriftKind",
    "DriftStatus",
    "CorrelationType",
    "TimelineEventType",
    "CaptureStatus",
    "FingerprintComponent",
    "CryptographicFingerprint",
    "FingerprintComparison",
    "EndpointRef",
    "IdentityRelationship",
    "ServerEntity",
    "DriftObservation",
    "DriftEvent",
    "SessionCorrelation",
    "TimelineEvent",
    "BlastRadius",
    "CaptureRecord",
    "IntelligenceWarning",
    "Investigation",
]

#: Bumped whenever the canonical form or component set changes, so a
#: fingerprint from an older build is never silently compared with a new one.
FINGERPRINT_ALGORITHM_VERSION = "smsfp/1"


class FingerprintSource(StrEnum):
    """Where one fingerprint component came from.

    Keeping client and server apart is the whole point. A cipher suite the
    client *offered* says nothing about what the server *supports*; treating
    the two alike is how capability claims get invented.
    """

    #: The client advertised it. A capability of the client, nothing more.
    CLIENT_OFFERED = "CLIENT_OFFERED"
    #: The server chose it from what the client offered.
    SERVER_SELECTED = "SERVER_SELECTED"
    #: Read out of a certificate that was visible in plaintext.
    CERTIFICATE_OBSERVED = "CERTIFICATE_OBSERVED"
    #: Derived from other observations, never seen directly.
    INFERRED = "INFERRED"
    #: The capture does not establish it.
    UNKNOWN = "UNKNOWN"


class FingerprintCompleteness(StrEnum):
    """How much of the fingerprint the capture actually supplied.

    A TLS 1.3 session encrypts its Certificate message, so no certificate
    component can be recorded without decryption material this tool will never
    accept. That session still has a useful fingerprint -- it just is not a
    complete one, and must never be presented as though it were.
    """

    #: Every defined component was observed.
    COMPLETE = "COMPLETE"
    #: The server-selected core was observed; at least one component was not.
    PARTIAL = "PARTIAL"
    #: No server selection was observed. Nothing may be concluded.
    INSUFFICIENT = "INSUFFICIENT"


class FingerprintMatch(StrEnum):
    """The result of comparing two fingerprints."""

    #: Identical hashes, and both fingerprints are COMPLETE.
    EXACT_MATCH = "EXACT_MATCH"
    #: Every component present in both agrees, but something is missing.
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    #: At least one component present in both has different values.
    CONFLICTING_COMPONENTS = "CONFLICTING_COMPONENTS"
    #: One or both sides lack a server selection.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class IdentityRelation(StrEnum):
    """How two observed endpoints are related, by the property actually matched.

    Each value names exactly what was established and nothing more. None of
    them means "the same machine".
    """

    #: The same ``(ip, port)`` was observed. The strongest available signal.
    EXACT_ENDPOINT = "EXACT_ENDPOINT"
    #: The same certificate was presented. Common across a load-balanced pool
    #: and across unrelated tenants of one hosting provider alike.
    SHARED_CERTIFICATE = "SHARED_CERTIFICATE"
    #: The same public key, under different certificates. Usually a renewal
    #: that kept the key; occasionally a key deliberately shared.
    SHARED_PUBLIC_KEY = "SHARED_PUBLIC_KEY"
    #: The same SNI was requested. What a client asked for, not what answered.
    OBSERVED_SNI = "OBSERVED_SNI"
    #: The same cryptographic fingerprint. Identical configuration, which two
    #: unrelated servers running the same distribution defaults will also have.
    CONFIGURATION_MATCH = "CONFIGURATION_MATCH"
    #: Several weak signals agree. Reported for a human to consider, never
    #: acted on as an identity.
    POSSIBLE_RELATION = "POSSIBLE_RELATION"
    #: Nothing links them.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class DriftKind(StrEnum):
    """Which observable property is being compared across captures."""

    NEGOTIATED_VERSION = "NEGOTIATED_VERSION"
    NEGOTIATED_CIPHER_SUITE = "NEGOTIATED_CIPHER_SUITE"
    KEY_EXCHANGE_GROUP = "KEY_EXCHANGE_GROUP"
    CERTIFICATE_FINGERPRINT = "CERTIFICATE_FINGERPRINT"
    CERTIFICATE_PUBLIC_KEY = "CERTIFICATE_PUBLIC_KEY"
    CERTIFICATE_VALIDITY = "CERTIFICATE_VALIDITY"
    SECURITY_FINDINGS = "SECURITY_FINDINGS"
    ASSESSMENT_COVERAGE = "ASSESSMENT_COVERAGE"
    POSTURE_SCORE = "POSTURE_SCORE"


class DriftStatus(StrEnum):
    """What the comparison established."""

    #: Both sides observed, they differ, and the difference is attributable.
    OBSERVED_CHANGE = "OBSERVED_CHANGE"
    #: Both sides observed and identical. Evidence of stability, not silence.
    UNCHANGED_WITH_EVIDENCE = "UNCHANGED_WITH_EVIDENCE"
    #: Both sides observed and different, but something else differed too --
    #: most often the client's offer -- so the server is not implicated.
    INCONCLUSIVE = "INCONCLUSIVE"
    #: One side was not observed. Absence is never reported as change.
    NOT_COMPARABLE = "NOT_COMPARABLE"


class CorrelationType(StrEnum):
    """What links a group of sessions.

    Every value describes an *observation* the sessions share. None describes
    an actor, a campaign or an intent.
    """

    SHARED_RULE_FAILURE = "SHARED_RULE_FAILURE"
    SHARED_CERTIFICATE = "SHARED_CERTIFICATE"
    SHARED_PUBLIC_KEY = "SHARED_PUBLIC_KEY"
    SHARED_ENDPOINT = "SHARED_ENDPOINT"
    REPEATED_OBSOLETE_TLS = "REPEATED_OBSOLETE_TLS"
    REPEATED_WEAK_CIPHER = "REPEATED_WEAK_CIPHER"
    AUTHENTICATION_EXPOSURE = "AUTHENTICATION_EXPOSURE"
    ENDPOINT_CONFIGURATION_DIVERGENCE = "ENDPOINT_CONFIGURATION_DIVERGENCE"


class TimelineEventType(StrEnum):
    """Observable events, plus events derived from them.

    A derived event names the observations it came from, so a reader can
    always get back to packets.
    """

    SESSION_FIRST_PACKET = "SESSION_FIRST_PACKET"
    PROTOCOL_IDENTIFIED = "PROTOCOL_IDENTIFIED"
    UPGRADE_ADVERTISED = "UPGRADE_ADVERTISED"
    UPGRADE_REQUESTED = "UPGRADE_REQUESTED"
    UPGRADE_ACCEPTED = "UPGRADE_ACCEPTED"
    UPGRADE_REJECTED = "UPGRADE_REJECTED"
    CLIENT_HELLO = "CLIENT_HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    CRYPTO_PARAMETERS_SELECTED = "CRYPTO_PARAMETERS_SELECTED"
    CERTIFICATE_OBSERVED = "CERTIFICATE_OBSERVED"
    TLS_ALERT = "TLS_ALERT"
    AUTHENTICATION_OBSERVED = "AUTHENTICATION_OBSERVED"
    SECURITY_FINDING = "SECURITY_FINDING"
    CONFIGURATION_DRIFT = "CONFIGURATION_DRIFT"


class CaptureStatus(StrEnum):
    """What happened to one member of a batch.

    A capture that failed is recorded with its reason. It never silently
    disappears from the aggregate, because a reader would then take the
    remaining results as covering everything that was submitted.
    """

    ANALYZED = "ANALYZED"
    #: Its bytes hash to a capture already analysed in this investigation.
    DUPLICATE = "DUPLICATE"
    #: Analysis raised. The reason is recorded.
    FAILED = "FAILED"
    #: Read successfully and contained no TCP sessions.
    EMPTY = "EMPTY"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class EndpointRef(_Frozen):
    """One observed server endpoint.

    Deliberately ``(ip, port)`` and not the full four-tuple: a client opening
    five connections from five ephemeral source ports has contacted one
    endpoint, and counting five would inflate every blast-radius number.
    """

    ip: str
    port: int = Field(ge=0, le=65535)

    @property
    def label(self) -> str:
        return f"[{self.ip}]:{self.port}" if ":" in self.ip else f"{self.ip}:{self.port}"


class FingerprintComponent(_Frozen):
    """One field that contributed to a fingerprint -- or that could not.

    A component with ``present=False`` is still listed. The absences are what
    make the completeness metadata checkable rather than asserted.
    """

    name: str
    value: str | None = None
    source: FingerprintSource
    present: bool
    explanation: str
    evidence_refs: tuple[PacketReference, ...] = ()


class CryptographicFingerprint(_Frozen):
    """A versioned, canonical digest of one session's observable crypto.

    The hash is an index for grouping. The components are the explanation, and
    the hash alone is never presented as one.
    """

    fingerprint_id: str = Field(description="'smsfp/1:<16 hex>' over the canonical form.")
    algorithm_version: str = FINGERPRINT_ALGORITHM_VERSION
    canonical_form: str = Field(
        description="The exact string that was hashed, so the digest is recomputable."
    )
    components: tuple[FingerprintComponent, ...]
    completeness: FingerprintCompleteness
    missing_components: tuple[str, ...] = ()
    capture_id: str
    session_id: str
    endpoint: EndpointRef
    limitations: tuple[str, ...] = ()


class FingerprintComparison(_Frozen):
    """The result of comparing two fingerprints, component by component."""

    match: FingerprintMatch
    agreeing_components: tuple[str, ...] = ()
    conflicting_components: tuple[str, ...] = ()
    missing_components: tuple[str, ...] = ()
    explanation: str
    limitations: tuple[str, ...] = ()


class IdentityRelationship(_Frozen):
    """A typed link between two entities, naming what was actually matched."""

    relation: IdentityRelation
    entity_id: str = Field(description="The other entity this one is related to.")
    basis: str = Field(description="The exact property that matched, and its value.")
    supporting_session_ids: tuple[str, ...] = ()
    supporting_capture_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class ServerEntity(_Frozen):
    """One observed server endpoint, across every capture in the investigation.

    Entities are created by exact ``(ip, port)`` equality and are **never**
    merged on any weaker signal. Weaker signals become
    :class:`IdentityRelationship` entries instead, so the report can say "these
    two endpoints presented the same certificate" without ever saying "these
    two endpoints are the same server".
    """

    entity_id: str
    endpoint: EndpointRef
    session_ids: tuple[str, ...] = ()
    capture_ids: tuple[str, ...] = ()
    observed_snis: tuple[str, ...] = ()
    certificate_fingerprints: tuple[str, ...] = ()
    public_key_fingerprints: tuple[str, ...] = ()
    fingerprint_ids: tuple[str, ...] = ()
    #: Digests of the negotiated settings alone. Two endpoints matching here
    #: are configured alike; their certificates may still differ, and usually
    #: do, since a certificate names a host.
    configuration_fingerprints: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    relationships: tuple[IdentityRelationship, ...] = ()
    limitations: tuple[str, ...] = ()


class DriftObservation(_Frozen):
    """One side of a drift comparison, with the evidence behind it."""

    capture_id: str
    session_id: str
    value: str | None = None
    observed: bool
    timestamp: datetime | None = None
    #: Full-precision capture time. Carried alongside ``timestamp`` so an
    #: event derived from this observation can state both, rather than a
    #: timestamp with no precision behind it.
    timestamp_ns: int | None = None
    evidence_refs: tuple[PacketReference, ...] = ()


class DriftEvent(_Frozen):
    """A comparison of one property for one entity across two captures."""

    drift_id: str
    kind: DriftKind
    status: DriftStatus
    entity_id: str
    before: DriftObservation
    after: DriftObservation
    #: What the two clients offered. A server that selected differently for
    #: differing offers has not been shown to have changed.
    client_offer_context: str | None = None
    #: ``None`` where the client's offer cannot explain the difference and was
    #: therefore not consulted -- certificate and score comparisons. Reporting
    #: ``True`` there would suggest a check that was never made.
    client_offers_comparable: bool | None = None
    explanation: str
    limitations: tuple[str, ...] = ()


class SessionCorrelation(_Frozen):
    """Sessions linked by a shared observation."""

    correlation_id: str
    correlation_type: CorrelationType
    related_session_ids: tuple[str, ...]
    related_capture_ids: tuple[str, ...]
    related_finding_ids: tuple[str, ...] = ()
    related_entity_ids: tuple[str, ...] = ()
    supporting_evidence: tuple[PacketReference, ...] = ()
    relationship_basis: str = Field(description="The exact shared property and its value.")
    #: Policy versions behind the correlated findings. Listed so a reader can
    #: see when findings produced under different criteria were grouped.
    policy_versions: tuple[str, ...] = ()
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    limitations: tuple[str, ...] = ()


class TimelineEvent(_Frozen):
    """One forensic event, anchored to the capture it came from."""

    event_id: str
    event_type: TimelineEventType
    timestamp: datetime | None = None
    timestamp_ns: int | None = None
    capture_id: str
    session_id: str | None = None
    entity_id: str | None = None
    description: str
    packet_refs: tuple[PacketReference, ...] = ()
    stream_offsets: tuple[int, ...] = ()
    evidence_status: str = Field(description="OBSERVED, INFERRED, UNKNOWN or NOT_AVAILABLE.")
    #: For derived events: the observations this was computed from.
    derived_from: tuple[str, ...] = ()
    #: Position in the deterministic ordering, so equal timestamps still have
    #: a stable, documented order.
    order_index: int = Field(ge=0)


class BlastRadius(_Frozen):
    """How far one condition was observed to reach -- and no further."""

    subject: str = Field(description="The rule id or condition this describes.")
    subject_kind: str = Field(description="'RULE' or 'CONDITION'.")
    affected_session_ids: tuple[str, ...] = ()
    affected_entity_ids: tuple[str, ...] = ()
    affected_capture_ids: tuple[str, ...] = ()
    related_finding_ids: tuple[str, ...] = ()
    session_count: int = Field(ge=0)
    entity_count: int = Field(ge=0)
    capture_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    scope_statement: str = "Observed within analyzed captures only."
    counting_method: str = Field(
        description="Exactly how each count was derived, so it can be checked."
    )
    limitations: tuple[str, ...] = ()


class CaptureRecord(_Frozen):
    """One member of the batch, whatever happened to it."""

    capture_id: str
    source_name: str
    status: CaptureStatus
    sha256: str | None = None
    file_size_bytes: int | None = None
    packet_count: int = Field(default=0, ge=0)
    session_count: int = Field(default=0, ge=0)
    first_packet_timestamp: datetime | None = None
    last_packet_timestamp: datetime | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    policy_fingerprint: str | None = None
    #: Present when status is FAILED. The class name and message, never a
    #: traceback and never a path outside the base name.
    failure_reason: str | None = None
    #: Present when status is DUPLICATE: the capture whose bytes these match.
    duplicate_of_source: str | None = None


class IntelligenceWarning(_Frozen):
    """Something the reader must know to read the results correctly.

    A limit that truncated the analysis produces one of these. Results that
    stop early without saying so are worse than no results.
    """

    code: str
    message: str
    capture_id: str | None = None
    detail: str | None = None


class Investigation(_Frozen):
    """The multi-capture intelligence report.

    Individual capture results are reported unchanged alongside this; nothing
    here replaces or summarises them away.
    """

    investigation_id: str
    schema_version: str
    fingerprint_algorithm_version: str = FINGERPRINT_ALGORITHM_VERSION
    created_at: datetime | None = None
    capture_inventory: tuple[CaptureRecord, ...] = ()
    server_entities: tuple[ServerEntity, ...] = ()
    cryptographic_fingerprints: tuple[CryptographicFingerprint, ...] = ()
    drift_events: tuple[DriftEvent, ...] = ()
    session_correlations: tuple[SessionCorrelation, ...] = ()
    evidence_timeline: tuple[TimelineEvent, ...] = ()
    blast_radius: tuple[BlastRadius, ...] = ()
    intelligence_warnings: tuple[IntelligenceWarning, ...] = ()
    scope_statement: str = "Observed within analyzed captures only."
    limitations: tuple[str, ...] = ()
