"""Email protocol analysis contracts (M2).

These models describe what the *application* layer of a reconstructed TCP
session showed: which email protocol was actually spoken, whether an
opportunistic TLS upgrade was advertised, requested and accepted, and exactly
where plaintext stopped.

Two disciplines are enforced structurally rather than by review:

**No capture text reaches these models.**  Every string field is either
engine-authored prose, a protocol keyword matched against an allowlist, or a
token that has passed :func:`securemailscope.protocols.redaction.safe_token`.
Greeting banners, command arguments, mailbox names, addresses, literals and
authentication payloads are never carried.

**An upgrade is not encryption.**  ``TLSUpgradeAttempt.handshake_analyzed`` is
``False`` for the whole of M2 and the field exists precisely so a consumer
cannot mistake "the server agreed to start TLS" for "a TLS handshake was
observed and verified".  Record framing is evidence that *something* TLS-shaped
followed; it is not a handshake analysis.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import AnalysisWarning, EvidenceStatus, PacketReference
from .tcp import Direction

__all__ = [
    "EmailProtocol",
    "DetectionStatus",
    "ProtocolEventType",
    "UpgradeState",
    "UpgradeMechanism",
    "ParseState",
    "TLSFramingEvidence",
    "TLSContentType",
    "ProtocolEvent",
    "ProtocolDetection",
    "TLSBoundary",
    "TLSRecordObservation",
    "TLSUpgradeAttempt",
    "ImplicitTLSObservation",
    "AuthenticationObservation",
    "ProtocolSessionAnalysis",
    "ProtocolInventory",
]


class EmailProtocol(StrEnum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class DetectionStatus(StrEnum):
    """How firmly the protocol was established.

    The ladder is deliberately steep.  A port number never reaches
    ``CONFIRMED``; only application-level syntax does.
    """

    #: Application-level evidence: a conforming greeting or command/response
    #: exchange was parsed. Independent of the port number.
    CONFIRMED = "CONFIRMED"
    #: Real but incomplete application evidence -- a conforming greeting with
    #: no completed exchange, or commands with no observed greeting.
    PROBABLE = "PROBABLE"
    #: Only the TCP port suggests this protocol. Nothing was parsed.
    PORT_HINT = "PORT_HINT"
    #: Neither the port nor any payload indicates an email protocol.
    UNKNOWN = "UNKNOWN"


class ProtocolEventType(StrEnum):
    SERVER_GREETING = "SERVER_GREETING"
    CLIENT_COMMAND = "CLIENT_COMMAND"
    SERVER_REPLY = "SERVER_REPLY"
    CAPABILITY_ADVERTISEMENT = "CAPABILITY_ADVERTISEMENT"
    UPGRADE_ADVERTISED = "UPGRADE_ADVERTISED"
    UPGRADE_REQUESTED = "UPGRADE_REQUESTED"
    UPGRADE_ACCEPTED = "UPGRADE_ACCEPTED"
    UPGRADE_REJECTED = "UPGRADE_REJECTED"
    UPGRADE_TEMPORARY_FAILURE = "UPGRADE_TEMPORARY_FAILURE"
    AUTHENTICATION_COMMAND = "AUTHENTICATION_COMMAND"
    AUTHENTICATION_CONTINUATION = "AUTHENTICATION_CONTINUATION"
    MESSAGE_BODY_SKIPPED = "MESSAGE_BODY_SKIPPED"
    LITERAL_SKIPPED = "LITERAL_SKIPPED"
    MULTILINE_RESPONSE_SKIPPED = "MULTILINE_RESPONSE_SKIPPED"
    SESSION_TERMINATION = "SESSION_TERMINATION"
    TLS_RECORD_OBSERVED = "TLS_RECORD_OBSERVED"
    GAP_ENCOUNTERED = "GAP_ENCOUNTERED"
    INCOMPLETE_RECORD = "INCOMPLETE_RECORD"
    PARSE_DESYNCHRONISED = "PARSE_DESYNCHRONISED"


class UpgradeMechanism(StrEnum):
    #: SMTP (RFC 3207) and IMAP (RFC 2595 / RFC 9051).
    STARTTLS = "STARTTLS"
    #: POP3 (RFC 2595).
    STLS = "STLS"


class UpgradeState(StrEnum):
    """Lifecycle of an opportunistic TLS upgrade.

    States are ordered by how far the negotiation got.  ``UPGRADE_ACCEPTED``
    means the server said yes -- it does **not** mean TLS was established.
    ``TLS_BYTES_OBSERVED`` additionally means bytes with valid TLS record
    framing followed, which is still not a verified handshake.
    """

    #: No upgrade mechanism was advertised, requested or observed.
    PLAINTEXT = "PLAINTEXT"
    #: The server advertised the capability; nobody used it.
    UPGRADE_ADVERTISED = "UPGRADE_ADVERTISED"
    #: The client issued the command; no matching response was observed.
    UPGRADE_REQUESTED = "UPGRADE_REQUESTED"
    #: The server returned a success response to the pending command.
    UPGRADE_ACCEPTED = "UPGRADE_ACCEPTED"
    #: The server refused, permanently or temporarily.
    UPGRADE_REJECTED = "UPGRADE_REJECTED"
    #: Accepted, and bytes with valid TLS record framing followed.
    TLS_BYTES_OBSERVED = "TLS_BYTES_OBSERVED"
    #: A gap, truncation or ambiguity prevents a safe conclusion.
    INCOMPLETE = "INCOMPLETE"
    #: Not determinable from this capture.
    UNKNOWN = "UNKNOWN"


class ParseState(StrEnum):
    #: The dialogue was parsed from greeting to termination without incident.
    COMPLETE = "COMPLETE"
    #: Parsed as far as the capture allowed; the capture ended mid-dialogue.
    INCOMPLETE = "INCOMPLETE"
    #: A gap, oversized record or ambiguity stopped parsing. Anything after
    #: the stopping point is deliberately not interpreted.
    INDETERMINATE = "INDETERMINATE"
    #: Parsing stopped because plaintext ended at a TLS upgrade boundary.
    HANDED_OFF_TO_TLS = "HANDED_OFF_TO_TLS"
    #: No plaintext email protocol was found to parse.
    NOT_APPLICABLE = "NOT_APPLICABLE"


class TLSFramingEvidence(StrEnum):
    """Strength of the evidence that a byte range is TLS.

    A single well-formed record header is a weak signal: plenty of binary
    payloads start with a byte in 20-23 followed by 0x03.  Only an identifiable
    handshake message or a chain of records whose declared lengths line up is
    treated as observed.
    """

    HANDSHAKE_CLIENT_HELLO = "HANDSHAKE_CLIENT_HELLO"
    HANDSHAKE_SERVER_HELLO = "HANDSHAKE_SERVER_HELLO"
    HANDSHAKE_RECORD = "HANDSHAKE_RECORD"
    RECORD_CHAIN = "RECORD_CHAIN"
    SINGLE_RECORD_HEADER = "SINGLE_RECORD_HEADER"
    TRUNCATED_RECORD = "TRUNCATED_RECORD"


class TLSContentType(StrEnum):
    CHANGE_CIPHER_SPEC = "CHANGE_CIPHER_SPEC"
    ALERT = "ALERT"
    HANDSHAKE = "HANDSHAKE"
    APPLICATION_DATA = "APPLICATION_DATA"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ProtocolEvent(_Frozen):
    """One parsed protocol element, with its exact position and provenance.

    ``detail`` is written by the engine.  No field on this model ever carries
    bytes copied out of the capture.
    """

    event_type: ProtocolEventType
    protocol: EmailProtocol
    direction: Direction
    stream_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0, description="Exclusive; includes the line terminator.")
    packet_refs: tuple[PacketReference, ...] = ()
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED

    command_verb: str | None = Field(
        default=None, description="Allowlisted command keyword, upper case. Never an argument."
    )
    reply_code: str | None = Field(
        default=None, description="'220', '+OK', '-ERR', 'OK', 'NO', 'BAD', 'PREAUTH', 'BYE'."
    )
    tag: str | None = Field(default=None, description="IMAP client tag, allowlist-filtered.")
    capabilities: tuple[str, ...] = Field(
        default=(), description="Allowlist-filtered capability keywords only."
    )
    byte_count: int | None = Field(
        default=None, description="Bytes skipped, for body/literal events."
    )

    detail: str = Field(description="Engine-authored description. Never capture content.")
    complete: bool = Field(default=True, description="False when the record was cut short.")
    ambiguous: bool = Field(
        default=False,
        description="True when these bytes overlap an unresolved TCP overlap conflict.",
    )
    limitations: tuple[str, ...] = ()


class ProtocolDetection(_Frozen):
    """Which email protocol this session actually spoke, and how we know."""

    protocol: EmailProtocol
    status: DetectionStatus
    evidence_status: EvidenceStatus
    confidence_basis: str = Field(
        description="Short machine-readable basis, e.g. 'GREETING_AND_EXCHANGE'."
    )
    explanation: str = Field(description="Engine-authored sentence.")
    evidence_refs: tuple[PacketReference, ...] = ()
    evidence_summary: tuple[str, ...] = Field(
        default=(), description="Engine-authored bullet points naming what was parsed."
    )
    port_hint: str | None = Field(
        default=None, description="What the server port alone would have suggested."
    )
    port_hint_agrees: bool | None = Field(
        default=None, description="None when there was no port hint to compare against."
    )
    limitations: tuple[str, ...] = ()


class TLSBoundary(_Frozen):
    """The exact stream offset at which one direction stopped being plaintext.

    Client and server have independent offsets and independent bases: the
    server's is the end of its success reply, the client's is wherever TLS
    bytes were actually first seen -- which is not assumed to be the end of the
    upgrade command.
    """

    direction: Direction
    stream_offset: int = Field(ge=0)
    basis: str = Field(
        description="'SERVER_SUCCESS_REPLY_END', 'FIRST_TLS_RECORD', or 'NOT_OBSERVED'."
    )
    packet_ref: PacketReference | None = None
    timestamp: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class TLSRecordObservation(_Frozen):
    """A byte range whose framing is consistent with a TLS record.

    This is framing evidence only.  Nothing here is decrypted, no handshake is
    reconstructed, and no cryptographic parameter is extracted -- that is M3.
    """

    direction: Direction
    stream_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0)
    content_type: int = Field(ge=0, le=255)
    content_type_name: TLSContentType
    legacy_record_version: str = Field(description="e.g. '0x0301'.")
    declared_length: int = Field(ge=0)
    bytes_available: int = Field(ge=0)
    complete: bool
    handshake_type: int | None = None
    handshake_type_name: str | None = None
    evidence: TLSFramingEvidence
    status: EvidenceStatus
    packet_refs: tuple[PacketReference, ...] = ()
    limitations: tuple[str, ...] = ()


class TLSUpgradeAttempt(_Frozen):
    """The complete STARTTLS/STLS story for one session."""

    mechanism: UpgradeMechanism
    protocol: EmailProtocol
    state: UpgradeState

    advertised: ProtocolEvent | None = None
    requested: ProtocolEvent | None = None
    response: ProtocolEvent | None = None
    response_code: str | None = None

    server_boundary: TLSBoundary | None = None
    client_boundary: TLSBoundary | None = None
    tls_records: tuple[TLSRecordObservation, ...] = ()

    handshake_analyzed: bool = Field(
        default=False,
        description="Always False in M2. TLS handshake reconstruction is M3.",
    )
    handshake_analysis_status: str = Field(
        default="NOT_IMPLEMENTED",
        description="Always 'NOT_IMPLEMENTED' in M2.",
    )
    negotiated_parameters_available: bool = Field(
        default=False,
        description="Always False in M2: no version, cipher suite or certificate is extracted.",
    )

    notes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


class ImplicitTLSObservation(_Frozen):
    """TLS record framing at the very start of a session (no plaintext phase).

    The *framing* may be observed; the underlying email protocol is not, and is
    reported separately as a port hint at best.
    """

    observed: bool
    records: tuple[TLSRecordObservation, ...] = ()
    port_hint: str | None = None
    service_identity_status: DetectionStatus = DetectionStatus.UNKNOWN
    explanation: str = ""
    limitations: tuple[str, ...] = ()


class AuthenticationObservation(_Frozen):
    """An authentication attempt was seen. No credential material is retained.

    ``credentials_recorded`` is a constant ``False``: the field documents the
    guarantee so that a reader of a report does not have to take it on trust.
    """

    protocol: EmailProtocol
    command_verb: str
    mechanism: str | None = Field(
        default=None, description="Only when explicitly and safely observable, e.g. 'PLAIN'."
    )
    direction: Direction
    stream_offset: int = Field(ge=0)
    packet_refs: tuple[PacketReference, ...] = ()
    timestamp: datetime | None = None

    occurred_before_tls_upgrade: bool = Field(
        description="True when no TLS upgrade had been accepted at this point."
    )
    upgrade_state_at_attempt: UpgradeState
    continuation_exchanges: int = Field(
        default=0, ge=0, description="Count of challenge/response rounds. Contents discarded."
    )
    credentials_recorded: bool = Field(default=False)
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    limitations: tuple[str, ...] = ()


class ProtocolSessionAnalysis(_Frozen):
    """Application-layer analysis of one reconstructed TCP session."""

    session_id: str
    capture_id: str
    detection: ProtocolDetection
    parse_state: ParseState
    events: tuple[ProtocolEvent, ...] = ()
    upgrade: TLSUpgradeAttempt | None = None
    implicit_tls: ImplicitTLSObservation | None = None
    authentication: tuple[AuthenticationObservation, ...] = ()
    warnings: tuple[AnalysisWarning, ...] = ()
    limitations: tuple[str, ...] = ()

    client_plaintext_end_offset: int | None = Field(
        default=None, description="Where client plaintext parsing stopped, if it did."
    )
    server_plaintext_end_offset: int | None = Field(
        default=None, description="Where server plaintext parsing stopped, if it did."
    )


class ProtocolInventory(_Frozen):
    """Capture-wide totals for the protocol layer."""

    analysed_session_count: int = Field(default=0, ge=0)
    confirmed_smtp_count: int = Field(default=0, ge=0)
    confirmed_imap_count: int = Field(default=0, ge=0)
    confirmed_pop3_count: int = Field(default=0, ge=0)
    probable_count: int = Field(default=0, ge=0)
    port_hint_only_count: int = Field(default=0, ge=0)
    unknown_count: int = Field(default=0, ge=0)

    upgrade_advertised_count: int = Field(default=0, ge=0)
    upgrade_requested_count: int = Field(default=0, ge=0)
    upgrade_accepted_count: int = Field(default=0, ge=0)
    upgrade_rejected_count: int = Field(default=0, ge=0)
    upgrade_incomplete_count: int = Field(default=0, ge=0)
    tls_bytes_observed_count: int = Field(default=0, ge=0)
    implicit_tls_session_count: int = Field(default=0, ge=0)

    authentication_observation_count: int = Field(default=0, ge=0)
    authentication_before_upgrade_count: int = Field(default=0, ge=0)

    tls_handshakes_analysed: int = Field(
        default=0, ge=0, description="Always 0 in M2: handshake analysis is not implemented."
    )
