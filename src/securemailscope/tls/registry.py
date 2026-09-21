"""Versioned registries for TLS code points.

Every table here is a transcription of an IANA registry or an RFC, with the
source named.  Nothing is guessed: a code point that is not in a table is
reported by its exact numeric value with status ``UNKNOWN`` rather than being
approximated from a neighbouring entry or from the shape of its name.

References
----------
* RFC 5246 §A.5 and RFC 8446 §B.4 -- cipher suite code points
* RFC 8446 §4.2.7 -- supported groups (named groups)
* RFC 8446 §4.2.3 -- signature schemes
* RFC 8701 -- GREASE values, which must be ignored rather than parsed
* IANA "Transport Layer Security (TLS) Parameters" registry
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, NamedTuple

__all__ = [
    "REGISTRY_SOURCE",
    "REGISTRY_REVISION",
    "KeyExchangeFamily",
    "AuthenticationFamily",
    "CipherSuiteInfo",
    "lookup_cipher_suite",
    "lookup_named_group",
    "lookup_signature_scheme",
    "lookup_version",
    "is_grease",
    "TLS_VERSIONS",
    "NamedGroupInfo",
]

REGISTRY_SOURCE: Final = "IANA TLS Parameters; RFC 5246, RFC 8446, RFC 7905, RFC 8422"
#: Bumped whenever a table below changes, so a report can name the table it used.
REGISTRY_REVISION: Final = "2026-09-21"


class KeyExchangeFamily(StrEnum):
    """How the session key is established, per the negotiated suite."""

    #: Static RSA: the client encrypts the premaster secret to the server's
    #: certificate key. No forward secrecy. Removed in TLS 1.3.
    RSA = "RSA"
    #: Ephemeral finite-field Diffie-Hellman.
    DHE = "DHE"
    #: Ephemeral elliptic-curve Diffie-Hellman.
    ECDHE = "ECDHE"
    #: Static (non-ephemeral) Diffie-Hellman. Historic.
    DH_STATIC = "DH_STATIC"
    #: Static elliptic-curve Diffie-Hellman. Historic.
    ECDH_STATIC = "ECDH_STATIC"
    #: Pre-shared key with no ephemeral contribution.
    PSK = "PSK"
    #: Pre-shared key combined with ephemeral (EC)DHE.
    PSK_EPHEMERAL = "PSK_EPHEMERAL"
    #: Anonymous -- no server authentication at all.
    ANON = "ANON"
    #: TLS 1.3: the cipher suite does not encode key exchange at all.
    NOT_ENCODED_IN_SUITE = "NOT_ENCODED_IN_SUITE"
    UNKNOWN = "UNKNOWN"


class AuthenticationFamily(StrEnum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    DSS = "DSS"
    PSK = "PSK"
    ANONYMOUS = "ANONYMOUS"
    #: TLS 1.3: authentication comes from the signature_algorithms extension
    #: and the certificate, not from the cipher suite.
    NOT_ENCODED_IN_SUITE = "NOT_ENCODED_IN_SUITE"
    UNKNOWN = "UNKNOWN"


class CipherSuiteInfo(NamedTuple):
    value: int
    name: str
    key_exchange: KeyExchangeFamily
    authentication: AuthenticationFamily
    encryption: str
    mac_or_prf: str
    aead: bool
    #: True only for TLS 1.3 suites, whose semantics differ fundamentally.
    tls13_only: bool = False


def _s(
    value: int,
    name: str,
    kx: KeyExchangeFamily,
    auth: AuthenticationFamily,
    enc: str,
    mac: str,
    aead: bool,
    tls13: bool = False,
) -> tuple[int, CipherSuiteInfo]:
    return value, CipherSuiteInfo(value, name, kx, auth, enc, mac, aead, tls13)


K = KeyExchangeFamily
A = AuthenticationFamily

#: Cipher suites we can name. Anything absent is reported numerically.
_CIPHER_SUITES: Final[dict[int, CipherSuiteInfo]] = dict(
    [
        # --- TLS 1.3 (RFC 8446 §B.4). These encode AEAD + hash ONLY. -------
        _s(0x1301, "TLS_AES_128_GCM_SHA256", K.NOT_ENCODED_IN_SUITE, A.NOT_ENCODED_IN_SUITE, "AES_128_GCM", "SHA256", True, True),
        _s(0x1302, "TLS_AES_256_GCM_SHA384", K.NOT_ENCODED_IN_SUITE, A.NOT_ENCODED_IN_SUITE, "AES_256_GCM", "SHA384", True, True),
        _s(0x1303, "TLS_CHACHA20_POLY1305_SHA256", K.NOT_ENCODED_IN_SUITE, A.NOT_ENCODED_IN_SUITE, "CHACHA20_POLY1305", "SHA256", True, True),
        _s(0x1304, "TLS_AES_128_CCM_SHA256", K.NOT_ENCODED_IN_SUITE, A.NOT_ENCODED_IN_SUITE, "AES_128_CCM", "SHA256", True, True),
        _s(0x1305, "TLS_AES_128_CCM_8_SHA256", K.NOT_ENCODED_IN_SUITE, A.NOT_ENCODED_IN_SUITE, "AES_128_CCM_8", "SHA256", True, True),
        # --- ECDHE + ECDSA (RFC 8422, RFC 5289, RFC 7905) ------------------
        _s(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", K.ECDHE, A.ECDSA, "AES_128_GCM", "SHA256", True),
        _s(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", K.ECDHE, A.ECDSA, "AES_256_GCM", "SHA384", True),
        _s(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", K.ECDHE, A.ECDSA, "AES_128_CBC", "SHA256", False),
        _s(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", K.ECDHE, A.ECDSA, "AES_256_CBC", "SHA384", False),
        _s(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", K.ECDHE, A.ECDSA, "AES_128_CBC", "SHA1", False),
        _s(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", K.ECDHE, A.ECDSA, "AES_256_CBC", "SHA1", False),
        _s(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", K.ECDHE, A.ECDSA, "CHACHA20_POLY1305", "SHA256", True),
        # --- ECDHE + RSA ---------------------------------------------------
        _s(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", K.ECDHE, A.RSA, "AES_128_GCM", "SHA256", True),
        _s(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", K.ECDHE, A.RSA, "AES_256_GCM", "SHA384", True),
        _s(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", K.ECDHE, A.RSA, "AES_128_CBC", "SHA256", False),
        _s(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", K.ECDHE, A.RSA, "AES_256_CBC", "SHA384", False),
        _s(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", K.ECDHE, A.RSA, "AES_128_CBC", "SHA1", False),
        _s(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", K.ECDHE, A.RSA, "AES_256_CBC", "SHA1", False),
        _s(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", K.ECDHE, A.RSA, "CHACHA20_POLY1305", "SHA256", True),
        # --- DHE + RSA -----------------------------------------------------
        _s(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", K.DHE, A.RSA, "AES_128_GCM", "SHA256", True),
        _s(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", K.DHE, A.RSA, "AES_256_GCM", "SHA384", True),
        _s(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", K.DHE, A.RSA, "AES_128_CBC", "SHA256", False),
        _s(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", K.DHE, A.RSA, "AES_256_CBC", "SHA256", False),
        _s(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", K.DHE, A.RSA, "AES_128_CBC", "SHA1", False),
        _s(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", K.DHE, A.RSA, "AES_256_CBC", "SHA1", False),
        _s(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", K.DHE, A.RSA, "CHACHA20_POLY1305", "SHA256", True),
        # --- static RSA key exchange: no forward secrecy --------------------
        _s(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", K.RSA, A.RSA, "AES_128_GCM", "SHA256", True),
        _s(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", K.RSA, A.RSA, "AES_256_GCM", "SHA384", True),
        _s(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", K.RSA, A.RSA, "AES_128_CBC", "SHA256", False),
        _s(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", K.RSA, A.RSA, "AES_256_CBC", "SHA256", False),
        _s(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", K.RSA, A.RSA, "AES_128_CBC", "SHA1", False),
        _s(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", K.RSA, A.RSA, "AES_256_CBC", "SHA1", False),
        _s(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", K.RSA, A.RSA, "3DES_EDE_CBC", "SHA1", False),
        _s(0x0005, "TLS_RSA_WITH_RC4_128_SHA", K.RSA, A.RSA, "RC4_128", "SHA1", False),
        _s(0x0004, "TLS_RSA_WITH_RC4_128_MD5", K.RSA, A.RSA, "RC4_128", "MD5", False),
        _s(0x003B, "TLS_RSA_WITH_NULL_SHA256", K.RSA, A.RSA, "NULL", "SHA256", False),
        # --- anonymous: no server authentication ----------------------------
        _s(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", K.DHE, A.ANONYMOUS, "AES_128_CBC", "SHA1", False),
        _s(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", K.ECDHE, A.ANONYMOUS, "AES_128_CBC", "SHA1", False),
        # --- PSK families ----------------------------------------------------
        _s(0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256", K.PSK, A.PSK, "AES_128_CBC", "SHA256", False),
        _s(0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", K.PSK_EPHEMERAL, A.PSK, "AES_128_GCM", "SHA256", True),
        _s(0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", K.PSK_EPHEMERAL, A.PSK, "AES_128_CBC", "SHA1", False),
        # --- signalling ------------------------------------------------------
        _s(0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", K.UNKNOWN, A.UNKNOWN, "NONE", "NONE", False),
        _s(0x5600, "TLS_FALLBACK_SCSV", K.UNKNOWN, A.UNKNOWN, "NONE", "NONE", False),
    ]
)


class NamedGroupInfo(NamedTuple):
    value: int
    name: str
    #: "ECDHE", "FFDHE" or "HYBRID" (post-quantum hybrids).
    family: str
    #: Approximate classical security level in bits, or None when it is not a
    #: meaningful representation for this group.
    security_bits: int | None


#: RFC 8446 §4.2.7 plus RFC 7919 finite-field groups.
_NAMED_GROUPS: Final[dict[int, NamedGroupInfo]] = {
    0x0017: NamedGroupInfo(0x0017, "secp256r1", "ECDHE", 128),
    0x0018: NamedGroupInfo(0x0018, "secp384r1", "ECDHE", 192),
    0x0019: NamedGroupInfo(0x0019, "secp521r1", "ECDHE", 256),
    0x001D: NamedGroupInfo(0x001D, "x25519", "ECDHE", 128),
    0x001E: NamedGroupInfo(0x001E, "x448", "ECDHE", 224),
    0x0100: NamedGroupInfo(0x0100, "ffdhe2048", "FFDHE", 103),
    0x0101: NamedGroupInfo(0x0101, "ffdhe3072", "FFDHE", 125),
    0x0102: NamedGroupInfo(0x0102, "ffdhe4096", "FFDHE", 150),
    0x0103: NamedGroupInfo(0x0103, "ffdhe6144", "FFDHE", 175),
    0x0104: NamedGroupInfo(0x0104, "ffdhe8192", "FFDHE", 192),
    0x11EC: NamedGroupInfo(0x11EC, "X25519MLKEM768", "HYBRID", None),
    0x6399: NamedGroupInfo(0x6399, "X25519Kyber768Draft00", "HYBRID", None),
}

#: RFC 8446 §4.2.3. The name encodes signature algorithm and hash.
_SIGNATURE_SCHEMES: Final[dict[int, str]] = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
}

#: Wire code points for protocol versions.
TLS_VERSIONS: Final[dict[int, str]] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

#: RFC 8701. A peer MUST ignore these; treating one as a real code point would
#: produce a fabricated "unknown cipher suite" or "unknown group" finding.
_GREASE: Final[frozenset[int]] = frozenset(
    {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
     0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
)


def is_grease(value: int) -> bool:
    """True for RFC 8701 GREASE code points, which carry no meaning."""
    return value in _GREASE


def lookup_cipher_suite(value: int) -> CipherSuiteInfo | None:
    return _CIPHER_SUITES.get(value)


def lookup_named_group(value: int) -> NamedGroupInfo | None:
    return _NAMED_GROUPS.get(value)


def lookup_signature_scheme(value: int) -> str | None:
    return _SIGNATURE_SCHEMES.get(value)


def lookup_version(value: int) -> str | None:
    return TLS_VERSIONS.get(value)
