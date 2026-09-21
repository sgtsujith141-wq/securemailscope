"""X.509 observation and validation contracts (M3).

Two ideas are enforced structurally here.

**Observation is not validation.**  Parsing a certificate successfully tells
you what it claims, not whether it is trustworthy.  The two live in separate
models, and :class:`CertificateValidation` keeps five *independent* checks --
presence, dates, chain, hostname, revocation -- each with its own status and
explanation.  A passing chain check never implies a passing hostname check,
and neither implies anything about revocation.

**Absence has causes.**  A connection with no certificate message may be a
TLS 1.3 session whose certificate is encrypted, a resumed session that
legitimately carries none, or a capture that simply missed it.
:class:`CertificateVisibility` distinguishes those, so "no certificate" is
never reported as a certificate failure.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import EvidenceStatus, PacketReference
from .tcp import Direction

__all__ = [
    "CertificateVisibility",
    "ValidationStatus",
    "AssessmentMode",
    "PublicKeyInfo",
    "CertificateObservation",
    "ValidationCheck",
    "TrustStoreInfo",
    "CertificateValidation",
    "CertificateInventory",
]


class CertificateVisibility(StrEnum):
    """Why a certificate is, or is not, available for analysis."""

    #: A Certificate message was observed in plaintext and parsed.
    OBSERVED = "OBSERVED"
    #: TLS 1.3: the Certificate message exists but is encrypted under
    #: handshake traffic keys. It cannot be recovered passively. Permanent.
    ENCRYPTED_TLS13 = "ENCRYPTED_TLS13"
    #: TLS 1.2: the handshake continued past a ChangeCipherSpec before any
    #: Certificate message was seen, so anything after it is encrypted.
    ENCRYPTED_AFTER_CCS = "ENCRYPTED_AFTER_CCS"
    #: A resumed session legitimately carries no new certificate.
    NOT_PRESENT_RESUMED = "NOT_PRESENT_RESUMED"
    #: The handshake was not observed far enough to contain one.
    NOT_OBSERVED = "NOT_OBSERVED"
    #: A Certificate message was found but could not be decoded.
    PARSE_FAILED = "PARSE_FAILED"
    #: The cryptographic library needed to decode X.509 is unavailable.
    PARSER_UNAVAILABLE = "PARSER_UNAVAILABLE"
    #: An anonymous cipher suite was negotiated: there is no certificate.
    NOT_APPLICABLE_ANONYMOUS = "NOT_APPLICABLE_ANONYMOUS"


class ValidationStatus(StrEnum):
    """Outcome of one independent validation check."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    #: The check could be run but was deliberately not attempted.
    NOT_PERFORMED = "NOT_PERFORMED"
    #: The check cannot be performed from this evidence or configuration --
    #: no trust store, no reference identity, no certificate.
    NOT_AVAILABLE = "NOT_AVAILABLE"
    #: The check was attempted and raised.
    ERROR = "ERROR"
    #: The check does not apply to this session.
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AssessmentMode(StrEnum):
    #: Validity judged against the capture's own timestamp. The default, and
    #: the only mode that describes what was true when the traffic happened.
    CAPTURE_TIME = "CAPTURE_TIME"
    #: Validity judged against the clock at analysis time.
    CURRENT_TIME = "CURRENT_TIME"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PublicKeyInfo(_Frozen):
    """A certificate's subject public key.

    ``size_bits`` is ``None`` for algorithms where a bit length is not a
    meaningful description -- Ed25519 and Ed448 have fixed parameters and no
    variable modulus, so inventing "256 bits" for them would be misleading.
    """

    algorithm: str = Field(description="'RSA', 'EC', 'Ed25519', 'Ed448', 'DSA', or 'UNKNOWN'.")
    size_bits: int | None = Field(
        default=None, description="RSA modulus / DSA prime length. None where inapplicable."
    )
    curve: str | None = Field(default=None, description="Curve name for EC keys.")
    rsa_public_exponent: int | None = None
    supported: bool = Field(
        default=True, description="False when the installed library cannot describe this key."
    )
    notes: tuple[str, ...] = ()


class CertificateObservation(_Frozen):
    """What one certificate in the presented chain claims.

    Nothing here is a judgement. ``self_signed`` means subject equals issuer
    and the signature verifies against its own key -- it does not mean
    untrusted, and a self-signed root in a trust store is perfectly normal.
    """

    chain_position: int = Field(ge=0, description="0 is the end-entity certificate.")
    sha256_fingerprint: str = Field(description="Lower-case hex SHA-256 of the DER encoding.")
    der_size_bytes: int = Field(ge=0)
    version: str

    subject: str = Field(description="RFC 4514 string form.")
    issuer: str
    serial_number: str = Field(description="Hex, no leading '0x'.")

    not_valid_before: datetime
    not_valid_after: datetime

    public_key: PublicKeyInfo
    signature_algorithm: str
    signature_hash_algorithm: str | None = None

    subject_alternative_names: tuple[str, ...] = ()
    basic_constraints_ca: bool | None = None
    basic_constraints_path_length: int | None = None
    key_usage: tuple[str, ...] = ()
    extended_key_usage: tuple[str, ...] = ()
    is_self_issued: bool = Field(
        default=False, description="Subject equals issuer. Not a trust judgement."
    )

    #: Factual, RFC-referenced statements about the algorithms this
    #: certificate uses. Observations, not a score -- scoring is M4.
    policy_notes: tuple[str, ...] = ()

    stream_offset: int = Field(ge=0, description="Offset of this certificate within the stream.")
    direction: Direction
    packet_refs: tuple[PacketReference, ...] = ()
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    limitations: tuple[str, ...] = ()


class ValidationCheck(_Frozen):
    """One independent validation question and its answer."""

    name: str
    status: ValidationStatus
    explanation: str = Field(description="Engine-authored; says why this status was reached.")
    detail: str | None = Field(
        default=None, description="Library error text, when a check failed or errored."
    )
    reference_time: datetime | None = None
    assessment_mode: AssessmentMode | None = None
    limitations: tuple[str, ...] = ()


class TrustStoreInfo(_Frozen):
    """Which trust anchors were used, without disclosing local paths."""

    configured: bool
    anchor_count: int = Field(default=0, ge=0)
    #: A stable identifier for the anchor set: sorted SHA-256 fingerprints,
    #: hashed. Lets two reports be compared without naming a filesystem path.
    anchor_set_digest: str | None = None
    source_kind: str = Field(
        default="NONE", description="'NONE', 'EXPLICIT_FILE', 'EXPLICIT_PEM', 'IN_MEMORY'."
    )
    policy: str = Field(
        default="RFC5280_WEB_PKI",
        description="Verification policy applied, as offered by the installed library.",
    )


class CertificateValidation(_Frozen):
    """The five checks, kept deliberately independent of one another."""

    certificate_observed: ValidationCheck
    validity_dates_checked: ValidationCheck
    chain_verified: ValidationCheck
    hostname_verified: ValidationCheck
    revocation_checked: ValidationCheck

    trust_store: TrustStoreInfo
    reference_identity: str | None = Field(
        default=None, description="The expected server identity that was supplied, if any."
    )
    reference_identity_source: str = Field(
        default="NONE",
        description="'NONE', 'OPERATOR_SUPPLIED', or 'OBSERVED_SNI_EXPLICITLY_TRUSTED'.",
    )
    observed_sni: str | None = Field(
        default=None,
        description="SNI seen in the ClientHello. Evidence only; never a reference identity "
        "unless the operator explicitly elects to trust it.",
    )
    capture_time: datetime | None = None
    limitations: tuple[str, ...] = ()


class CertificateInventory(_Frozen):
    """Certificates for one TLS session, plus why they are or are not there."""

    visibility: CertificateVisibility
    visibility_explanation: str
    certificates: tuple[CertificateObservation, ...] = ()
    validation: CertificateValidation | None = None
    chain_length: int = Field(default=0, ge=0)
    truncated: bool = Field(
        default=False, description="True when a certificate or count limit was reached."
    )
    limitations: tuple[str, ...] = ()
