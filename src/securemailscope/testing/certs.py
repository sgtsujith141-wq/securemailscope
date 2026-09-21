"""A synthetic certificate authority for fixtures.

Every certificate here is issued at fixture-build time from a key created in
this process.  **No private key material is committed to the repository** --
there are no PEM files in git, only the code that generates them, and the
generated files live in gitignored temporary directories.

Identities use ``.invalid`` (RFC 6761) and ``.example`` so nothing can
accidentally resolve or collide with a real service.

A note on reproducibility: ECDSA signatures are randomised, so certificates
signed by this CA differ byte for byte between runs.  Fixtures that carry one
are therefore marked ``byte_reproducible=False`` in their manifest and are
asserted on their *semantic* content -- subject, issuer, key algorithm, key
size, SANs, validity window, validation outcomes -- rather than on a capture
hash.  An Ed25519 CA would sign deterministically, but the installed
``cryptography`` verification profile rejects Ed25519 trust anchors, and
chain verification is the more valuable property to keep testable.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = ["SyntheticCA", "IssuedCertificate", "CAPTURE_EPOCH"]

#: All fixture captures are timestamped here, so "expired at capture time" and
#: "not yet valid at capture time" are stable facts rather than clock-dependent.
CAPTURE_EPOCH = datetime.datetime(2026, 6, 1, 12, 0, 0, tzinfo=datetime.UTC)

KeyKind = Literal["ec256", "ec384", "rsa1024", "rsa2048", "ed25519"]


def _make_key(kind: KeyKind) -> Any:
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    if kind == "rsa1024":
        # Deliberately below the policy minimum. Generated only for synthetic
        # fixtures that need a weak key to be observable; never used to
        # protect anything.
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,  # noqa: S505 - weak on purpose, never used to protect anything
        )
    if kind == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported key kind {kind}")


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    certificate: x509.Certificate
    private_key: Any

    @property
    def pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )


class SyntheticCA:
    """Issues test certificates, optionally through an intermediate."""

    def __init__(self, name: str = "SecureMailScope Synthetic Test Root") -> None:
        self.name = name
        self.root = self._self_signed(name)
        self.intermediate = self._intermediate("SecureMailScope Synthetic Test Intermediate")

    # -- issuance ----------------------------------------------------------
    def _self_signed(self, common_name: str) -> IssuedCertificate:
        key = _make_key("ec256")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (
            self._base(subject, subject, key.public_key(), serial=1, ca=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )
            .not_valid_before(CAPTURE_EPOCH - datetime.timedelta(days=365))
            .not_valid_after(CAPTURE_EPOCH + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        return IssuedCertificate(certificate=certificate, private_key=key)

    def _intermediate(self, common_name: str) -> IssuedCertificate:
        key = _make_key("ec256")
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (
            self._base(subject, self.root.certificate.subject, key.public_key(), serial=2, ca=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.root.private_key.public_key()
                ),
                critical=False,
            )
            .not_valid_before(CAPTURE_EPOCH - datetime.timedelta(days=180))
            .not_valid_after(CAPTURE_EPOCH + datetime.timedelta(days=1825))
            .sign(self.root.private_key, hashes.SHA256())
        )
        return IssuedCertificate(certificate=certificate, private_key=key)

    @staticmethod
    def _base(
        subject: x509.Name,
        issuer: x509.Name,
        public_key: Any,
        *,
        serial: int,
        ca: bool,
    ) -> x509.CertificateBuilder:
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )
        if ca:
            return builder.add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        return builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )

    def issue(
        self,
        common_name: str,
        *,
        sans: list[str] | None = None,
        key_kind: KeyKind = "ec256",
        serial: int = 100,
        not_before_days: int = -30,
        not_after_days: int = 365,
        via_intermediate: bool = False,
        self_signed: bool = False,
    ) -> IssuedCertificate:
        """Issue an end-entity certificate with the requested properties."""
        key = _make_key(key_kind)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        if self_signed:
            issuer_name, issuer_key = subject, key
        elif via_intermediate:
            issuer_name = self.intermediate.certificate.subject
            issuer_key = self.intermediate.private_key
        else:
            issuer_name = self.root.certificate.subject
            issuer_key = self.root.private_key

        builder = self._base(subject, issuer_name, key.public_key(), serial=serial, ca=False)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (sans or [common_name])]
            ),
            critical=False,
        )
        builder = builder.not_valid_before(
            CAPTURE_EPOCH + datetime.timedelta(days=not_before_days)
        ).not_valid_after(CAPTURE_EPOCH + datetime.timedelta(days=not_after_days))
        algorithm = (
            None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
        )
        return IssuedCertificate(
            certificate=builder.sign(issuer_key, algorithm), private_key=key
        )

    def reissue(
        self,
        original: IssuedCertificate,
        *,
        serial: int,
        not_before_days: int = -1,
        not_after_days: int = 730,
    ) -> IssuedCertificate:
        """Re-issue a certificate for the **same key pair**.

        This is what an ordinary renewal looks like: a new certificate, with a
        new serial and new validity dates, built on the key the server already
        had. The certificate fingerprint changes and the SubjectPublicKeyInfo
        fingerprint does not, which is the only way an observer can tell a
        renewal from a rekey -- and M5 relies on being able to.
        """
        key = original.private_key
        subject = original.certificate.subject
        builder = self._base(
            subject, self.root.certificate.subject, key.public_key(), serial=serial, ca=False
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.root.private_key.public_key()
            ),
            critical=False,
        )
        # _base already sets basic constraints, key usage and the serverAuth
        # EKU; only the names carry over from the original.
        builder = builder.add_extension(
            original.certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value,
            critical=False,
        )
        builder = builder.not_valid_before(
            CAPTURE_EPOCH + datetime.timedelta(days=not_before_days)
        ).not_valid_after(CAPTURE_EPOCH + datetime.timedelta(days=not_after_days))
        return IssuedCertificate(
            certificate=builder.sign(self.root.private_key, hashes.SHA256()),
            private_key=key,
        )

    # -- helpers for the TLS fixture server --------------------------------
    def write_chain(
        self, leaf: IssuedCertificate, directory: Path, *, via_intermediate: bool = False
    ) -> tuple[Path, Path]:
        """Write a leaf (plus intermediate) chain and its key. Returns paths."""
        directory.mkdir(parents=True, exist_ok=True)
        chain = leaf.pem
        if via_intermediate:
            chain += self.intermediate.pem
        chain_path = directory / "chain.pem"
        key_path = directory / "key.pem"
        chain_path.write_bytes(chain)
        key_path.write_bytes(leaf.key_pem)
        return chain_path, key_path

    @property
    def root_pem(self) -> bytes:
        return self.root.pem
