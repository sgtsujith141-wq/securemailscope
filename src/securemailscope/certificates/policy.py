"""A documented cryptographic policy for describing certificate algorithms.

These are *factual statements with a citation*, not scores.  "This certificate
is signed with SHA-1, which RFC 9155 deprecates" is an observation an analyst
can check; "this certificate scores 40/100" is a judgement, and judgements are
M4's job.

References
----------
* RFC 9155 -- deprecating MD5 and SHA-1 signatures in TLS
* RFC 9325 §3.2 -- TLS recommendations on certificate key strength
* NIST SP 800-57 Part 1 Rev. 5 -- comparable security strengths
"""

from __future__ import annotations

from typing import Final

__all__ = ["POLICY_NAME", "POLICY_REFERENCES", "describe_signature", "describe_public_key"]

POLICY_NAME: Final = "securemailscope-observational-policy"
POLICY_REFERENCES: Final[tuple[str, ...]] = (
    "RFC 9155",
    "RFC 9325 §3.2",
    "NIST SP 800-57 Part 1 Rev. 5",
)

#: Hashes whose collision resistance is broken or too weak for signatures.
_DEPRECATED_HASHES: Final[dict[str, str]] = {
    "md5": "RFC 9155 prohibits MD5 in TLS signatures; MD5 collisions are practical.",
    "sha1": "RFC 9155 deprecates SHA-1 in TLS signatures; SHA-1 collisions are practical.",
}

#: RFC 9325 §3.2 recommends at least 2048-bit RSA/DSA keys.
_MIN_RSA_BITS: Final = 2048
#: NIST SP 800-57: a 224-bit curve is the minimum for 112-bit security.
_MIN_EC_BITS: Final = 224


def describe_signature(algorithm: str, hash_name: str | None) -> tuple[str, ...]:
    """Factual notes about a certificate's signature algorithm."""
    notes: list[str] = []
    if hash_name:
        message = _DEPRECATED_HASHES.get(hash_name.lower())
        if message:
            notes.append(f"Signature hash {hash_name.upper()}: {message}")
    if "md5" in algorithm.lower():
        notes.append(
            "The signature algorithm name references MD5, which RFC 9155 prohibits."
        )
    return tuple(notes)


def describe_public_key(
    algorithm: str, size_bits: int | None, curve: str | None
) -> tuple[str, ...]:
    """Factual notes about a certificate's subject public key."""
    notes: list[str] = []
    if algorithm == "RSA" and size_bits is not None and size_bits < _MIN_RSA_BITS:
        notes.append(
            f"RSA modulus is {size_bits} bits; RFC 9325 §3.2 recommends at least "
            f"{_MIN_RSA_BITS} bits."
        )
    if algorithm == "DSA" and size_bits is not None and size_bits < _MIN_RSA_BITS:
        notes.append(
            f"DSA key is {size_bits} bits; RFC 9325 §3.2 recommends at least "
            f"{_MIN_RSA_BITS} bits."
        )
    if algorithm == "EC" and size_bits is not None and size_bits < _MIN_EC_BITS:
        notes.append(
            f"Elliptic curve {curve or 'unknown'} has a {size_bits}-bit field; NIST SP "
            f"800-57 places the minimum for 112-bit security at {_MIN_EC_BITS} bits."
        )
    if algorithm in {"Ed25519", "Ed448"}:
        notes.append(
            "Edwards-curve keys have fixed parameters, so no variable key length is "
            "reported for them."
        )
    return tuple(notes)
