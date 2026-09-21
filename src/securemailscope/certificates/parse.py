"""DER certificate decoding into provenanced observations.

Only the ``cryptography`` library interprets X.509 here; nothing in this
project hand-rolls ASN.1.  If the library is unavailable the module reports
``PARSER_UNAVAILABLE`` rather than failing the analysis, so the TLS record and
handshake layers keep working.

Nothing in this module validates anything. It records what a certificate
*claims*; whether those claims are trustworthy is
:mod:`securemailscope.certificates.validate`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from ..models.certificates import CertificateObservation, PublicKeyInfo
from ..models.evidence import EvidenceStatus, PacketReference
from ..models.tcp import Direction
from .policy import describe_public_key, describe_signature

__all__ = ["CRYPTOGRAPHY_AVAILABLE", "parse_certificate", "load_pem_certificates"]

try:  # pragma: no cover - exercised by whichever branch the environment takes
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False


_KEY_USAGE_FIELDS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)


def _spki_sha256(key: Any) -> str | None:
    """SHA-256 over the DER SubjectPublicKeyInfo, or None if unserialisable.

    This identifies the *key pair*, not the certificate. A renewal that keeps
    the key produces a new certificate fingerprint and the same SPKI
    fingerprint; a rekey changes both. M5 relies on that distinction, so the
    value is computed here, from the certificate bytes, rather than being
    re-derived later from a parsed description.
    """
    try:
        der = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return hashlib.sha256(der).hexdigest()


def _public_key_info(certificate: Any) -> PublicKeyInfo:
    """Describe the subject public key without inventing a bit length."""
    key = certificate.public_key()
    spki = _spki_sha256(key)
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return PublicKeyInfo(
            algorithm="RSA",
            size_bits=key.key_size,
            rsa_public_exponent=numbers.e,
            spki_sha256=spki,
            notes=describe_public_key("RSA", key.key_size, None),
        )
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve.name
        return PublicKeyInfo(
            algorithm="EC",
            size_bits=key.curve.key_size,
            curve=curve,
            spki_sha256=spki,
            notes=describe_public_key("EC", key.curve.key_size, curve),
        )
    if isinstance(key, ed25519.Ed25519PublicKey):
        return PublicKeyInfo(
            algorithm="Ed25519",
            size_bits=None,
            spki_sha256=spki,
            notes=describe_public_key("Ed25519", None, None),
        )
    if isinstance(key, ed448.Ed448PublicKey):
        return PublicKeyInfo(
            algorithm="Ed448",
            size_bits=None,
            spki_sha256=spki,
            notes=describe_public_key("Ed448", None, None),
        )
    if isinstance(key, dsa.DSAPublicKey):
        return PublicKeyInfo(
            algorithm="DSA",
            size_bits=key.key_size,
            spki_sha256=spki,
            notes=describe_public_key("DSA", key.key_size, None),
        )
    return PublicKeyInfo(
        algorithm="UNKNOWN",
        size_bits=None,
        spki_sha256=spki,
        supported=False,
        notes=(
            "The installed cryptography build does not expose a description for this "
            "public key type; no key size is reported.",
        ),
    )


def _subject_alternative_names(certificate: Any) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return ()
    names: list[str] = []
    for entry in extension.value:
        if isinstance(entry, x509.DNSName):
            names.append(f"DNS:{entry.value}")
        elif isinstance(entry, x509.IPAddress):
            names.append(f"IP:{entry.value}")
        elif isinstance(entry, x509.RFC822Name):
            names.append(f"email:{entry.value}")
        elif isinstance(entry, x509.UniformResourceIdentifier):
            names.append(f"URI:{entry.value}")
        if len(names) >= 64:
            break
    return tuple(names)


def _key_usage(certificate: Any) -> tuple[str, ...]:
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return ()
    flags = [name for name in _KEY_USAGE_FIELDS if getattr(usage, name, False)]
    # encipher_only/decipher_only are only defined when key_agreement is set.
    if usage.key_agreement:
        for name in ("encipher_only", "decipher_only"):
            try:
                if getattr(usage, name):
                    flags.append(name)
            except ValueError:  # pragma: no cover - guarded by key_agreement
                pass
    return tuple(flags)


def _extended_key_usage(certificate: Any) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return ()
    return tuple(oid._name or oid.dotted_string for oid in extension.value)[:32]


def _basic_constraints(certificate: Any) -> tuple[bool | None, int | None]:
    try:
        value = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None, None
    return value.ca, value.path_length


def _signature_hash_name(certificate: Any) -> str | None:
    try:
        algorithm = certificate.signature_hash_algorithm
    except Exception:
        return None
    if algorithm is None or not isinstance(algorithm, hashes.HashAlgorithm):
        return None
    return algorithm.name


def parse_certificate(
    der: bytes,
    *,
    chain_position: int,
    direction: Direction,
    stream_offset: int,
    packet_refs: tuple[PacketReference, ...],
) -> tuple[CertificateObservation | None, Any | None, str | None]:
    """Decode one DER certificate.

    Returns ``(observation, x509 object, error)``. The x509 object is handed to
    the validator and never reaches a report.
    """
    if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
        return None, None, "the cryptography library is not installed"
    try:
        certificate = x509.load_der_x509_certificate(der)
    except Exception as error:
        return None, None, f"{type(error).__name__}: {error}"

    try:
        signature_algorithm = (
            certificate.signature_algorithm_oid._name
            or certificate.signature_algorithm_oid.dotted_string
        )
        hash_name = _signature_hash_name(certificate)
        public_key = _public_key_info(certificate)
        ca_flag, path_length = _basic_constraints(certificate)
        observation = CertificateObservation(
            chain_position=chain_position,
            sha256_fingerprint=hashlib.sha256(der).hexdigest(),
            der_size_bytes=len(der),
            version=certificate.version.name,
            subject=certificate.subject.rfc4514_string(),
            issuer=certificate.issuer.rfc4514_string(),
            serial_number=format(certificate.serial_number, "x"),
            not_valid_before=certificate.not_valid_before_utc,
            not_valid_after=certificate.not_valid_after_utc,
            public_key=public_key,
            signature_algorithm=signature_algorithm,
            signature_hash_algorithm=hash_name,
            subject_alternative_names=_subject_alternative_names(certificate),
            basic_constraints_ca=ca_flag,
            basic_constraints_path_length=path_length,
            key_usage=_key_usage(certificate),
            extended_key_usage=_extended_key_usage(certificate),
            is_self_issued=certificate.subject == certificate.issuer,
            policy_notes=describe_signature(signature_algorithm, hash_name)
            + public_key.notes,
            stream_offset=stream_offset,
            direction=direction,
            packet_refs=packet_refs,
            status=EvidenceStatus.OBSERVED,
            limitations=(
                "These are the certificate's own claims. Whether they are trustworthy is "
                "reported separately under validation.",
            ),
        )
    except Exception as error:
        return None, certificate, f"{type(error).__name__}: {error}"
    return observation, certificate, None


def load_pem_certificates(data: bytes) -> list[Any]:
    """Decode a PEM bundle into certificate objects."""
    if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
        return []
    return list(x509.load_pem_x509_certificates(data))


def certificate_to_der_base64(certificate: Any) -> str:
    """Base64 DER, only ever used behind an explicit opt-in flag."""
    import base64

    return base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)
    ).decode("ascii")
