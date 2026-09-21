"""TLS record, handshake and cryptographic-parameter contracts (M3).

The distinctions this module exists to preserve:

* **Offered is not selected.**  A ClientHello lists what the client would
  accept. Only a ServerHello says what was chosen. When no ServerHello was
  observed, the selected version and cipher suite stay ``UNKNOWN`` -- the
  highest offered version is never promoted into a negotiated one.
* **TLS 1.3 cipher suites do not encode key exchange or authentication.**
  ``TLS_AES_128_GCM_SHA256`` says nothing about ECDHE or RSA. The TLS 1.2
  decomposition fields are therefore marked inapplicable rather than guessed.
* **Observing a ServerHello is not observing a completed handshake.**  In
  TLS 1.3 everything after it is encrypted; in TLS 1.2 everything after
  ChangeCipherSpec is. Completion cannot be verified passively without key
  material, so it is reported as not observable rather than assumed.
* **Record framing is not decryption.**  An ``application_data`` record in a
  TLS 1.3 session carries encrypted handshake messages. It is never parsed as
  plaintext.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .certificates import CertificateInventory
from .evidence import AnalysisWarning, EvidenceStatus, PacketReference
from .protocol import TLSRecordObservation
from .tcp import Direction

__all__ = [
    "TLSEntryPoint",
    "HandshakeState",
    "RecordParseState",
    "EncryptionBoundary",
    "TLSMessageObservation",
    "CodePointRef",
    "TLSVersionAnalysis",
    "CipherSuiteAnalysis",
    "KeyExchangeAnalysis",
    "ForwardSecrecyStatus",
    "ForwardSecrecyAssessment",
    "TLSAlertObservation",
    "ResumptionObservation",
    "TLSSessionAnalysis",
    "TLSInventory",
]


class TLSEntryPoint(StrEnum):
    """How TLS began in this TCP session."""

    #: TLS from the first byte (ports 465/993/995 and anything else observed).
    IMPLICIT = "IMPLICIT"
    #: Plaintext email protocol upgraded via STARTTLS/STLS; offsets come from
    #: the M2 transition boundaries.
    STARTTLS_UPGRADE = "STARTTLS_UPGRADE"
    #: TLS records were found but their origin is not established.
    UNKNOWN = "UNKNOWN"


class HandshakeState(StrEnum):
    """How far the *observable* handshake progressed.

    None of these states means "cryptographically verified". They describe
    what was visible in the capture.
    """

    #: No handshake message was parsed.
    NOT_OBSERVED = "NOT_OBSERVED"
    #: A ClientHello only; no server response seen.
    CLIENT_HELLO_ONLY = "CLIENT_HELLO_ONLY"
    #: A ServerHello without a preceding ClientHello (midstream capture).
    SERVER_HELLO_WITHOUT_CLIENT_HELLO = "SERVER_HELLO_WITHOUT_CLIENT_HELLO"
    #: Both hellos parsed; parameters are negotiated and observable.
    NEGOTIATED = "NEGOTIATED"
    #: Server asked the client to retry with a different group (RFC 8446 §4.1.4).
    HELLO_RETRY_REQUESTED = "HELLO_RETRY_REQUESTED"
    #: Negotiated, and the remainder is encrypted so it cannot be followed.
    NEGOTIATED_THEN_ENCRYPTED = "NEGOTIATED_THEN_ENCRYPTED"
    #: The full TLS 1.2 plaintext flight through ServerHelloDone was observed.
    SERVER_FLIGHT_COMPLETE = "SERVER_FLIGHT_COMPLETE"
    #: An alert ended the negotiation before it completed.
    ABORTED_BY_ALERT = "ABORTED_BY_ALERT"
    #: Parsing stopped: missing bytes, ambiguity or a malformed record.
    INDETERMINATE = "INDETERMINATE"


class RecordParseState(StrEnum):
    #: All records in this direction were framed to the end of the data.
    COMPLETE = "COMPLETE"
    #: The last record is cut short by the end of the capture.
    TRUNCATED_RECORD = "TRUNCATED_RECORD"
    #: A hole means record alignment after it is unknowable; parsing stopped.
    ALIGNMENT_LOST_AT_GAP = "ALIGNMENT_LOST_AT_GAP"
    #: A record header was structurally invalid; parsing stopped.
    MALFORMED_RECORD = "MALFORMED_RECORD"
    #: Bytes overlapped a TCP conflict and are not unambiguous evidence.
    AMBIGUOUS_BYTES = "AMBIGUOUS_BYTES"
    #: A configured record or buffer limit stopped parsing.
    LIMIT_REACHED = "LIMIT_REACHED"
    #: No TLS records were found at the entry point.
    NOT_TLS = "NOT_TLS"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class EncryptionBoundary(_Frozen):
    """Where one direction stopped being readable as plaintext."""

    direction: Direction
    stream_offset: int | None = Field(
        default=None, description="None when the direction never became encrypted."
    )
    reason: str = Field(
        description="'TLS13_AFTER_SERVER_HELLO', 'TLS12_CHANGE_CIPHER_SPEC', "
        "'NOT_ENCRYPTED' or 'UNKNOWN'."
    )
    packet_ref: PacketReference | None = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED


class TLSMessageObservation(_Frozen):
    """One handshake message, reassembled across records if necessary."""

    message_type: int = Field(ge=0, le=255)
    message_type_name: str
    direction: Direction
    #: Stream offset of the first byte of this message's record fragment.
    stream_offset: int = Field(ge=0)
    end_offset: int = Field(ge=0)
    declared_length: int = Field(ge=0)
    available_length: int = Field(ge=0)
    complete: bool = Field(
        description="False when the declared length exceeds the bytes available."
    )
    #: Indices into the session's record list that carried this message.
    record_indices: tuple[int, ...] = ()
    spans_records: bool = False
    packet_refs: tuple[PacketReference, ...] = ()
    first_timestamp: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    detail: str = ""
    limitations: tuple[str, ...] = ()


class CodePointRef(_Frozen):
    """A wire code point, with its registered name when we have one."""

    value: int = Field(ge=0)
    hex_value: str
    name: str | None = Field(default=None, description="None when not in the registry.")
    known: bool = Field(description="False means the numeric value is reported as-is.")
    grease: bool = Field(default=False, description="RFC 8701 filler; carries no meaning.")


class TLSVersionAnalysis(_Frozen):
    """Offered versus selected protocol version.

    RFC 8446 §4.2.1: a TLS 1.3 server signals the version in the
    ``supported_versions`` extension of its ServerHello and leaves
    ``legacy_version`` at 0x0303. Identifying TLS 1.3 from the legacy field or
    the record-layer version is therefore wrong, and this model records which
    source was actually used.
    """

    client_legacy_version: CodePointRef | None = None
    offered_versions: tuple[CodePointRef, ...] = ()
    offered_source: str | None = Field(
        default=None, description="'SUPPORTED_VERSIONS_EXTENSION' or 'LEGACY_VERSION'."
    )
    server_legacy_version: CodePointRef | None = None
    selected_version: CodePointRef | None = None
    selected_source: str | None = Field(
        default=None, description="'SUPPORTED_VERSIONS_EXTENSION' or 'LEGACY_VERSION'."
    )
    negotiation_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    record_layer_versions: tuple[CodePointRef, ...] = Field(
        default=(),
        description="Record-layer legacy versions seen. Never used to identify the "
        "negotiated version.",
    )
    evidence_refs: tuple[PacketReference, ...] = ()
    limitations: tuple[str, ...] = ()


class CipherSuiteAnalysis(_Frozen):
    """Offered versus selected cipher suite, and what the suite encodes."""

    offered: tuple[CodePointRef, ...] = ()
    offered_count: int = Field(default=0, ge=0)
    grease_count: int = Field(default=0, ge=0)
    unknown_offered_count: int = Field(default=0, ge=0)

    selected: CodePointRef | None = None
    selection_status: EvidenceStatus = EvidenceStatus.UNKNOWN

    #: Decomposition of the SELECTED suite. Meaningless for TLS 1.3, where
    #: ``decomposition_applicable`` is False and the fields stay None.
    decomposition_applicable: bool = True
    key_exchange: str | None = None
    authentication: str | None = None
    encryption: str | None = None
    mac_or_prf: str | None = None
    aead: bool | None = None

    registry_source: str
    registry_revision: str
    evidence_refs: tuple[PacketReference, ...] = ()
    limitations: tuple[str, ...] = ()


class KeyExchangeAnalysis(_Frozen):
    """What can be observed about how keys were established."""

    method: str = Field(description="Key exchange family, or 'UNKNOWN'.")
    method_status: EvidenceStatus = EvidenceStatus.UNKNOWN
    method_source: str | None = Field(
        default=None,
        description="'CIPHER_SUITE' (TLS<=1.2) or 'KEY_SHARE_EXTENSION' / "
        "'PSK_EXTENSIONS' (TLS 1.3).",
    )

    client_supported_groups: tuple[CodePointRef, ...] = ()
    client_key_share_groups: tuple[CodePointRef, ...] = ()
    selected_group: CodePointRef | None = None
    selected_group_source: str | None = None
    server_key_share_length: int | None = Field(
        default=None, description="Length of the server's key_share entry, in bytes."
    )

    #: TLS 1.2 ServerKeyExchange, when observed in plaintext.
    server_key_exchange_observed: bool = False
    server_key_exchange_curve: CodePointRef | None = None
    server_key_exchange_public_length: int | None = None
    dh_prime_length_bits: int | None = None

    #: TLS 1.3 pre-shared key signals.
    psk_offered: bool = False
    psk_key_exchange_modes: tuple[str, ...] = ()
    server_selected_psk: bool | None = Field(
        default=None, description="None when no ServerHello was observed."
    )
    hello_retry_request_observed: bool = False

    client_signature_algorithms: tuple[CodePointRef, ...] = ()
    evidence_refs: tuple[PacketReference, ...] = ()
    limitations: tuple[str, ...] = ()


class ForwardSecrecyStatus(StrEnum):
    """Forward-secrecy classification. Criteria are in the assessment model.

    These are *cryptographic observations*, not findings. Converting them into
    a posture judgement is M4's job.
    """

    #: An ephemeral key exchange was negotiated AND ephemeral key material was
    #: actually observed on the wire.
    EPHEMERAL_OBSERVED = "EPHEMERAL_OBSERVED"
    #: A forward-secrecy-capable method was negotiated, but the ephemeral
    #: material itself was not visible (typically TLS 1.3 after ServerHello).
    CAPABLE_NEGOTIATED = "CAPABLE_NEGOTIATED"
    #: Static RSA key exchange: the premaster secret is encrypted to the
    #: server's long-term key, so a later key compromise decrypts this session.
    STATIC_RSA_KEY_EXCHANGE = "STATIC_RSA_KEY_EXCHANGE"
    #: PSK without any ephemeral contribution.
    PSK_ONLY = "PSK_ONLY"
    #: Negotiated method is known and provides no forward secrecy.
    NOT_FORWARD_SECRET = "NOT_FORWARD_SECRET"  # noqa: S105 - a status name, not a secret
    #: Evidence is insufficient to classify.
    UNKNOWN_INCOMPLETE_EVIDENCE = "UNKNOWN_INCOMPLETE_EVIDENCE"
    #: The property cannot be determined from a passive capture of this session.
    NOT_OBSERVABLE = "NOT_OBSERVABLE"


class ForwardSecrecyAssessment(_Frozen):
    """Structured forward-secrecy observation with its criteria stated."""

    status: ForwardSecrecyStatus
    criteria: str = Field(description="The exact rule that produced this status.")
    ephemeral_key_exchange_negotiated: bool | None = None
    ephemeral_key_material_observed: bool = False
    #: Passive analysis cannot verify Finished messages without key material,
    #: so this is False for every session M3 analyses.
    handshake_completion_observable: bool = False
    handshake_completion_explanation: str = ""
    evidence_refs: tuple[PacketReference, ...] = ()
    limitations: tuple[str, ...] = ()


class TLSAlertObservation(_Frozen):
    """A TLS alert record. Only plaintext alerts carry readable detail."""

    direction: Direction
    stream_offset: int = Field(ge=0)
    level: int | None = None
    level_name: str | None = None
    description: int | None = None
    description_name: str | None = None
    encrypted: bool = Field(
        default=False,
        description="True when the alert body is encrypted and only its record framing "
        "is observable.",
    )
    packet_refs: tuple[PacketReference, ...] = ()
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    limitations: tuple[str, ...] = ()


class ResumptionObservation(_Frozen):
    """Signals that a session was resumed rather than freshly negotiated."""

    #: TLS 1.2: a non-empty legacy_session_id echoed by the server.
    tls12_session_id_echoed: bool | None = None
    tls12_session_id_length: int | None = None
    #: TLS 1.3: the client offered pre_shared_key and the server selected one.
    tls13_psk_offered: bool = False
    tls13_psk_selected: bool | None = None
    new_session_ticket_observed: bool = False
    likely_resumed: bool | None = Field(
        default=None, description="None when the evidence does not support a conclusion."
    )
    explanation: str = ""
    limitations: tuple[str, ...] = ()


class TLSSessionAnalysis(_Frozen):
    """Everything M3 established about one TCP session's TLS."""

    session_id: str
    capture_id: str
    entry_point: TLSEntryPoint
    entry_offsets: dict[str, int] = Field(
        default_factory=dict, description="Per-direction stream offset where parsing began."
    )

    client_record_parse_state: RecordParseState
    server_record_parse_state: RecordParseState
    record_count: int = Field(default=0, ge=0)
    records: tuple[TLSRecordObservation, ...] = ()
    messages: tuple[TLSMessageObservation, ...] = ()
    encryption_boundaries: tuple[EncryptionBoundary, ...] = ()

    handshake_state: HandshakeState
    version: TLSVersionAnalysis
    cipher_suite: CipherSuiteAnalysis
    key_exchange: KeyExchangeAnalysis
    forward_secrecy: ForwardSecrecyAssessment
    certificates: CertificateInventory
    resumption: ResumptionObservation
    alerts: tuple[TLSAlertObservation, ...] = ()

    server_name_indication: str | None = Field(
        default=None,
        description="SNI from the ClientHello. Evidence about what the client asked for; "
        "not proof of the server's identity.",
    )
    alpn_offered: tuple[str, ...] = ()
    alpn_selected: str | None = None

    warnings: tuple[AnalysisWarning, ...] = ()
    limitations: tuple[str, ...] = ()


class TLSInventory(_Frozen):
    """Capture-wide TLS totals."""

    tls_session_count: int = Field(default=0, ge=0)
    implicit_tls_count: int = Field(default=0, ge=0)
    starttls_upgrade_count: int = Field(default=0, ge=0)
    negotiated_count: int = Field(default=0, ge=0)
    tls13_count: int = Field(default=0, ge=0)
    tls12_count: int = Field(default=0, ge=0)
    legacy_version_count: int = Field(
        default=0, ge=0, description="Sessions negotiating TLS 1.1 or older."
    )
    certificates_observed_count: int = Field(default=0, ge=0)
    certificates_encrypted_count: int = Field(default=0, ge=0)
    chain_verified_count: int = Field(default=0, ge=0)
    hostname_verified_count: int = Field(default=0, ge=0)
    forward_secret_count: int = Field(default=0, ge=0)
    static_rsa_count: int = Field(default=0, ge=0)
    alert_count: int = Field(default=0, ge=0)
    #: Always 0: passive analysis cannot verify a handshake completed.
    handshakes_cryptographically_verified: int = Field(default=0, ge=0)
    #: Always 0: no live OCSP or CRL fetching exists.
    revocation_checks_performed: int = Field(default=0, ge=0)
