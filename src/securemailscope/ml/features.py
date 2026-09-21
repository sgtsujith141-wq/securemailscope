"""Evidence-derived feature extraction (M6).

Every feature here is read from an M1-M5 observation. Nothing is invented, and
a value that was not observed is never quietly replaced by a number.

## Three rules that shape the schema

**A code point is a name, not a magnitude.** TLS 1.2 is ``0x0303`` and TLS 1.3
is ``0x0304``, but the difference between them is not 1, and a suite's
identifier says nothing about its strength. Every protocol identifier is
one-hot encoded as a category. Feeding the raw integers to a model would invite
it to learn an ordering that does not exist.

**Missing is a category, and it has reasons.** A certificate absent from a TLS
1.3 session is ``NOT_APPLICABLE`` -- the protocol encrypts it, and no capture
without keys will ever show it. A certificate absent from a truncated TLS 1.2
session is ``UNKNOWN`` -- it may well have been sent. Collapsing both to zero
would teach the model that TLS 1.3 servers have no certificate. Each optional
value therefore carries an explicit absence reason alongside an indicator, and
numeric features that are missing are marked rather than zero-filled.

**Incomplete evidence is not an observation.** A session that shows no
negotiation has fewer features, and a naive model would find it unusual for
exactly that reason -- reporting the capture's shortcomings as the server's. So
there is a minimum-evidence gate: a session without an observed negotiated
version and cipher suite is ``ML_NOT_EVALUABLE`` and never reaches a model.

## Prohibited inputs

These are excluded deliberately and asserted against in the tests:

* file names, capture hashes, session ids, finding ids;
* M4 posture scores, severities, rule outcomes and any policy-derived label;
* dataset split assignments and generator family or scenario names;
* IP addresses, host names, SNI and certificate subject or issuer names, which
  would let a model memorise training entities and pass it off as
  generalisation;
* cryptographic fingerprint digests as numbers. The *structure* of a
  fingerprint -- how many components were observed -- is informative and is
  used. The digest itself is a hash: its magnitude means nothing, and treating
  it as a quantity would be numerology.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from ..models.analysis import AnalysisResult

__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "FEATURE_NAMES",
    "AbsenceReason",
    "EligibilityStatus",
    "SessionFeatures",
    "extract_features",
    "extract_from_result",
    "vector_names",
]

#: Bumped whenever a feature is added, removed or re-encoded. A model trained
#: under one schema refuses to load against another.
FEATURE_SCHEMA_VERSION: Final = "smsfeat/1"


class AbsenceReason(StrEnum):
    """Why a value is not present, kept distinct because they differ.

    Conflating these is how a model learns that TLS 1.3 servers have no
    certificate.
    """

    OBSERVED = "OBSERVED"
    #: The capture could have shown it and did not.
    UNKNOWN = "UNKNOWN"
    #: Passive capture can never show it for this session.
    NOT_AVAILABLE = "NOT_AVAILABLE"
    #: The concept does not apply here at all.
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EligibilityStatus(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    #: Too little evidence for any model to say something meaningful.
    ML_NOT_EVALUABLE = "ML_NOT_EVALUABLE"


# ---------------------------------------------------------------------------
# Frozen vocabularies. Order is part of the schema: the one-hot layout must not
# depend on dictionary iteration or on what happened to appear in a dataset.
# ---------------------------------------------------------------------------
VERSIONS: Final = ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "OTHER", "MISSING")
ENCRYPTIONS: Final = (
    "AES_128_GCM",
    "AES_256_GCM",
    "CHACHA20_POLY1305",
    "AES_128_CBC",
    "AES_256_CBC",
    "3DES_EDE_CBC",
    "RC4_128",
    "NULL",
    "OTHER",
    "MISSING",
)
KEY_EXCHANGES: Final = ("ECDHE", "DHE", "RSA", "PSK", "ECDH", "OTHER", "MISSING")
AUTHENTICATIONS: Final = ("ECDSA", "RSA", "PSK", "ANON", "OTHER", "MISSING")
MACS: Final = ("SHA1", "SHA256", "SHA384", "OTHER", "MISSING")
GROUPS: Final = ("x25519", "secp256r1", "secp384r1", "ffdhe2048", "OTHER", "MISSING")
KEY_ALGORITHMS: Final = ("RSA", "EC", "Ed25519", "Ed448", "DSA", "OTHER", "MISSING")
SIGNATURE_HASHES: Final = ("sha256", "sha384", "sha512", "sha1", "OTHER", "MISSING")
ENTRY_POINTS: Final = ("IMPLICIT", "STARTTLS", "UNKNOWN", "OTHER", "MISSING")
HANDSHAKE_STATES: Final = (
    "SERVER_FLIGHT_COMPLETE",
    "SERVER_HELLO_SEEN",
    "CLIENT_HELLO_ONLY",
    "NONE_OBSERVED",
    "OTHER",
    "MISSING",
)
DETECTION_STATUSES: Final = (
    "CONFIRMED",
    "PROBABLE",
    "PORT_HINT",
    "UNKNOWN",
    "OTHER",
    "MISSING",
)
ABSENCE_REASONS: Final = tuple(reason.value for reason in AbsenceReason)

_CATEGORICAL: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("tls_version", VERSIONS),
    ("cipher_encryption", ENCRYPTIONS),
    ("cipher_key_exchange", KEY_EXCHANGES),
    ("cipher_authentication", AUTHENTICATIONS),
    ("cipher_mac", MACS),
    ("key_exchange_group", GROUPS),
    ("cert_key_algorithm", KEY_ALGORITHMS),
    ("cert_signature_hash", SIGNATURE_HASHES),
    ("entry_point", ENTRY_POINTS),
    ("handshake_state", HANDSHAKE_STATES),
    ("protocol_detection", DETECTION_STATUSES),
    ("certificate_absence_reason", ABSENCE_REASONS),
    ("group_absence_reason", ABSENCE_REASONS),
)

_BOOLEAN: Final[tuple[str, ...]] = (
    "cipher_is_aead",
    "forward_secrecy_observed",
    "certificate_observed",
    "client_offered_tls13",
    "sni_present",
)

#: Numeric features, each paired with an explicit ``*_missing`` indicator so a
#: missing value is never mistaken for a small one.
_NUMERIC: Final[tuple[str, ...]] = (
    "cert_key_bits",
    "cert_lifetime_days",
    "offered_suite_count",
    "offered_version_count",
    "evidence_completeness",
)

#: Scales chosen so every numeric lands roughly in [0, 1] without fitting
#: anything to the data -- the split happens before preprocessing, and a
#: hand-set scale cannot leak across it.
_NUMERIC_SCALE: Final[dict[str, float]] = {
    "cert_key_bits": 4096.0,
    "cert_lifetime_days": 3650.0,
    "offered_suite_count": 32.0,
    "offered_version_count": 4.0,
    "evidence_completeness": 1.0,
}


def vector_names() -> list[str]:
    """Every column in the feature vector, in order. Part of the schema."""
    names: list[str] = []
    for feature, vocabulary in _CATEGORICAL:
        names.extend(f"{feature}={value}" for value in vocabulary)
    names.extend(_BOOLEAN)
    for feature in _NUMERIC:
        names.append(feature)
        names.append(f"{feature}_missing")
    return names


FEATURE_NAMES: Final[tuple[str, ...]] = tuple(vector_names())


@dataclass(frozen=True)
class SessionFeatures:
    """One session's features, with the provenance of each one."""

    capture_id: str
    session_id: str
    eligibility: EligibilityStatus
    reason: str
    categorical: dict[str, str]
    boolean: dict[str, bool]
    numeric: dict[str, float | None]
    #: Where each feature came from, for the explanation block.
    provenance: dict[str, str]
    #: Packet references supporting the negotiated parameters.
    evidence_refs: tuple[Any, ...] = ()

    def vector(self) -> list[float]:
        """The encoded vector, in ``FEATURE_NAMES`` order."""
        values: list[float] = []
        for feature, vocabulary in _CATEGORICAL:
            actual = self.categorical.get(feature, "MISSING")
            if actual not in vocabulary:
                actual = "OTHER" if "OTHER" in vocabulary else "MISSING"
            values.extend(1.0 if value == actual else 0.0 for value in vocabulary)
        values.extend(1.0 if self.boolean.get(name, False) else 0.0 for name in _BOOLEAN)
        for name in _NUMERIC:
            raw = self.numeric.get(name)
            if raw is None:
                # Zero *and* the indicator set. The model can tell the
                # difference between "zero" and "not known" because the
                # indicator column carries it.
                values.append(0.0)
                values.append(1.0)
            else:
                values.append(min(raw / _NUMERIC_SCALE[name], 2.0))
                values.append(0.0)
        return values


def _category(value: str | None, vocabulary: tuple[str, ...]) -> str:
    if value is None:
        return "MISSING"
    if value in vocabulary:
        return value
    return "OTHER" if "OTHER" in vocabulary else "MISSING"


def extract_features(
    session: Any,
    tls: Any,
    protocol: Any,
    capture_id: str,
) -> SessionFeatures:
    """Read one session's features from its M1-M5 observations."""
    categorical: dict[str, str] = {}
    boolean: dict[str, bool] = {}
    numeric: dict[str, float | None] = {}
    provenance: dict[str, str] = {}

    if tls is None:
        return SessionFeatures(
            capture_id=capture_id,
            session_id=session.session_id,
            eligibility=EligibilityStatus.ML_NOT_EVALUABLE,
            reason=(
                "The session carried no TLS, so there is no cryptographic "
                "configuration to describe."
            ),
            categorical={},
            boolean={},
            numeric={},
            provenance={},
        )

    version = tls.version.selected_version
    suite = tls.cipher_suite.selected
    group = tls.key_exchange.selected_group

    categorical["tls_version"] = _category(
        version.name if version else None, VERSIONS
    )
    provenance["tls_version"] = "tls.version.selected_version"

    analysis = tls.cipher_suite
    categorical["cipher_encryption"] = _category(analysis.encryption, ENCRYPTIONS)
    categorical["cipher_key_exchange"] = _category(analysis.key_exchange, KEY_EXCHANGES)
    categorical["cipher_authentication"] = _category(
        analysis.authentication, AUTHENTICATIONS
    )
    categorical["cipher_mac"] = _category(analysis.mac_or_prf, MACS)
    for name in ("cipher_encryption", "cipher_key_exchange", "cipher_authentication", "cipher_mac"):
        provenance[name] = "tls.cipher_suite (registry decomposition)"
    boolean["cipher_is_aead"] = bool(analysis.aead)

    categorical["key_exchange_group"] = _category(
        group.name if group else None, GROUPS
    )
    provenance["key_exchange_group"] = "tls.key_exchange.selected_group"
    categorical["group_absence_reason"] = (
        AbsenceReason.OBSERVED.value
        if group is not None
        else (
            AbsenceReason.NOT_APPLICABLE.value
            if version is not None
            and version.value < 0x0304
            and analysis.key_exchange == "RSA"
            else AbsenceReason.UNKNOWN.value
        )
    )
    provenance["group_absence_reason"] = "derived: tls.key_exchange + negotiated suite"

    forward = tls.forward_secrecy
    boolean["forward_secrecy_observed"] = bool(
        forward is not None
        and forward.status.value
        in ("EPHEMERAL_OBSERVED", "CAPABLE_NEGOTIATED")
    )
    provenance["forward_secrecy_observed"] = "tls.forward_secrecy.status"

    leaf = next(
        (
            certificate
            for certificate in tls.certificates.certificates
            if certificate.chain_position == 0
        ),
        None,
    )
    boolean["certificate_observed"] = leaf is not None
    if leaf is not None:
        categorical["certificate_absence_reason"] = AbsenceReason.OBSERVED.value
        categorical["cert_key_algorithm"] = _category(
            leaf.public_key.algorithm, KEY_ALGORITHMS
        )
        categorical["cert_signature_hash"] = _category(
            leaf.signature_hash_algorithm, SIGNATURE_HASHES
        )
        numeric["cert_key_bits"] = (
            float(leaf.public_key.size_bits)
            if leaf.public_key.size_bits is not None
            else None
        )
        if leaf.not_valid_before is not None and leaf.not_valid_after is not None:
            numeric["cert_lifetime_days"] = (
                leaf.not_valid_after - leaf.not_valid_before
            ).days
        else:
            numeric["cert_lifetime_days"] = None
        provenance["cert_key_algorithm"] = "certificates[0].public_key.algorithm"
        provenance["cert_signature_hash"] = "certificates[0].signature_hash_algorithm"
        provenance["cert_key_bits"] = "certificates[0].public_key.size_bits"
        provenance["cert_lifetime_days"] = "certificates[0] validity dates"
    else:
        # TLS 1.3 encrypts the Certificate message. That is a property of the
        # protocol, not a gap in this capture, and the two must not look alike.
        tls13 = version is not None and version.value == 0x0304
        categorical["certificate_absence_reason"] = (
            AbsenceReason.NOT_AVAILABLE.value if tls13 else AbsenceReason.UNKNOWN.value
        )
        categorical["cert_key_algorithm"] = "MISSING"
        categorical["cert_signature_hash"] = "MISSING"
        numeric["cert_key_bits"] = None
        numeric["cert_lifetime_days"] = None
        provenance["certificate_absence_reason"] = (
            "derived: no certificate observed; TLS 1.3 encrypts it"
            if tls13
            else "derived: no certificate observed in plaintext"
        )

    categorical["entry_point"] = _category(
        tls.entry_point.value if tls.entry_point else None, ENTRY_POINTS
    )
    categorical["handshake_state"] = _category(
        tls.handshake_state.value if tls.handshake_state else None, HANDSHAKE_STATES
    )
    provenance["entry_point"] = "tls.entry_point"
    provenance["handshake_state"] = "tls.handshake_state"

    categorical["protocol_detection"] = _category(
        protocol.detection.status.value if protocol is not None else None,
        DETECTION_STATUSES,
    )
    provenance["protocol_detection"] = "protocol.detection.status"

    offered_versions = [ref for ref in tls.version.offered_versions if not ref.grease]
    offered_suites = [ref for ref in tls.cipher_suite.offered if not ref.grease]
    numeric["offered_suite_count"] = float(len(offered_suites)) if offered_suites else None
    numeric["offered_version_count"] = (
        float(len(offered_versions)) if offered_versions else None
    )
    boolean["client_offered_tls13"] = any(
        ref.value == 0x0304 for ref in offered_versions
    )
    boolean["sni_present"] = bool(tls.server_name_indication)
    provenance["offered_suite_count"] = "tls.cipher_suite.offered (GREASE removed)"
    provenance["offered_version_count"] = "tls.version.offered_versions (GREASE removed)"
    provenance["client_offered_tls13"] = "tls.version.offered_versions"
    provenance["sni_present"] = "tls.server_name_indication (presence only, never the value)"

    observed = sum(
        1
        for present in (
            version is not None,
            suite is not None,
            group is not None,
            leaf is not None,
        )
        if present
    )
    numeric["evidence_completeness"] = observed / 4.0
    provenance["evidence_completeness"] = "derived: fraction of core observations present"

    eligible = version is not None and suite is not None
    return SessionFeatures(
        capture_id=capture_id,
        session_id=session.session_id,
        eligibility=(
            EligibilityStatus.ELIGIBLE if eligible else EligibilityStatus.ML_NOT_EVALUABLE
        ),
        reason=(
            "A negotiated version and cipher suite were observed."
            if eligible
            else (
                "No negotiated version and cipher suite were observed. A session "
                "with too little evidence is not evaluated, rather than being "
                "reported as unusual for having little to show."
            )
        ),
        categorical=categorical,
        boolean=boolean,
        numeric=numeric,
        provenance=provenance,
        evidence_refs=tuple(tls.cipher_suite.evidence_refs),
    )


def extract_from_result(result: AnalysisResult) -> list[SessionFeatures]:
    """Features for every session in one analysed capture."""
    tls_by_session = {item.session_id: item for item in result.tls}
    protocols = {item.session_id: item for item in result.protocols}
    return [
        extract_features(
            session,
            tls_by_session.get(session.session_id),
            protocols.get(session.session_id),
            result.capture.capture_id,
        )
        for session in result.sessions
    ]
