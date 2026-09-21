"""Cryptographic fingerprints (M5).

A fingerprint is a versioned digest of the cryptographic parameters a *server*
was observed to choose, plus the certificate it presented. It is an **index for
grouping**, never an identity: two servers running the same distribution's
defaults produce the same fingerprint and are not the same machine.

Three rules govern what goes in:

1. **Only server-attributable evidence.** What the client offered describes the
   client. Including it would make the "server fingerprint" change when the
   client changed, which is precisely the confusion this milestone exists to
   avoid.
2. **Nothing incidental.** Source ports, packet timestamps and session
   identifiers are excluded: they vary per connection, so including them would
   make every session unique and the fingerprint useless for grouping.
3. **Absences are recorded, not hidden.** A component that could not be
   observed appears in the canonical form as ``<ABSENT>`` and in
   ``missing_components``. A TLS 1.3 session encrypts its Certificate message,
   so it *cannot* produce certificate components without decryption material
   this tool will never accept -- and it must not appear to.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Final

from ..models.intelligence import (
    FINGERPRINT_ALGORITHM_VERSION,
    CryptographicFingerprint,
    EndpointRef,
    FingerprintComparison,
    FingerprintCompleteness,
    FingerprintComponent,
    FingerprintMatch,
    FingerprintSource,
)

if TYPE_CHECKING:
    from ..models.tcp import TCPSession
    from ..models.tls import TLSSessionAnalysis

__all__ = [
    "FINGERPRINT_ALGORITHM_VERSION",
    "COMPONENT_NAMES",
    "CONFIGURATION_COMPONENTS",
    "ABSENT",
    "build_fingerprint",
    "canonical_form",
    "configuration_fingerprint",
    "compare_fingerprints",
]

#: The marker written into the canonical form for a component that was not
#: observed. A literal, so the canonical form stays a total function of the
#: component list and the digest can be recomputed by hand from the report.
ABSENT: Final = "<ABSENT>"

#: Fixed order, so the canonical form does not depend on dictionary iteration.
#: Adding or removing a name requires bumping FINGERPRINT_ALGORITHM_VERSION.
COMPONENT_NAMES: Final = (
    "tls_version",
    "cipher_suite",
    "key_exchange_group",
    "alpn_selected",
    "certificate_sha256",
    "certificate_spki_sha256",
    "certificate_issuer",
)

#: A fingerprint means nothing without these two: they are the server's
#: actual selection. Without them there was no observed negotiation at all.
_CORE: Final = frozenset({"tls_version", "cipher_suite"})

#: The negotiated *settings*, with the certificate left out.
#:
#: Two servers can be configured identically and still present different
#: certificates -- which is the normal case, since a certificate names a host.
#: Including the certificate in a "same configuration" test would make it fire
#: only when the certificate matched too, at which point it would be a weaker
#: restatement of SHARED_CERTIFICATE rather than an independent signal.
CONFIGURATION_COMPONENTS: Final = (
    "tls_version",
    "cipher_suite",
    "key_exchange_group",
    "alpn_selected",
)


def _component(
    name: str,
    value: str | None,
    source: FingerprintSource,
    explanation: str,
    refs: tuple = (),
) -> FingerprintComponent:
    return FingerprintComponent(
        name=name,
        value=value,
        source=source if value is not None else FingerprintSource.UNKNOWN,
        present=value is not None,
        explanation=explanation,
        evidence_refs=refs if value is not None else (),
    )


def _components(tls: TLSSessionAnalysis | None) -> list[FingerprintComponent]:
    """Read every defined component out of one session's TLS analysis."""
    if tls is None:
        return [
            _component(
                name,
                None,
                FingerprintSource.UNKNOWN,
                "The session carried no TLS, so no cryptographic parameters exist.",
            )
            for name in COMPONENT_NAMES
        ]

    version = tls.version.selected_version
    suite = tls.cipher_suite.selected
    group = tls.key_exchange.selected_group
    leaf = next(
        (
            certificate
            for certificate in tls.certificates.certificates
            if certificate.chain_position == 0
        ),
        None,
    )

    out = [
        _component(
            "tls_version",
            version.name or version.hex_value if version else None,
            FingerprintSource.SERVER_SELECTED,
            "The version the server selected. For TLS 1.3 this is read from the "
            "supported_versions extension, never from the legacy field.",
            tls.version.evidence_refs,
        ),
        _component(
            "cipher_suite",
            suite.name or suite.hex_value if suite else None,
            FingerprintSource.SERVER_SELECTED,
            "The suite the server chose from those the client offered. The "
            "offered list is a client capability and is deliberately excluded.",
            tls.cipher_suite.evidence_refs,
        ),
        _component(
            "key_exchange_group",
            group.name or group.hex_value if group else None,
            FingerprintSource.SERVER_SELECTED,
            "The named group the server selected, where one was observable.",
            tls.key_exchange.evidence_refs,
        ),
        _component(
            "alpn_selected",
            tls.alpn_selected,
            FingerprintSource.SERVER_SELECTED,
            "The protocol the server selected via ALPN, if any was negotiated.",
            tls.version.evidence_refs,
        ),
    ]

    if leaf is None:
        note = (
            "No certificate was visible. Under TLS 1.3 the Certificate message "
            "is encrypted, so this is expected and is not a fault."
            if version is not None and version.value == 0x0304
            else "No certificate was observed in plaintext in this session."
        )
        out += [
            _component(name, None, FingerprintSource.CERTIFICATE_OBSERVED, note)
            for name in ("certificate_sha256", "certificate_spki_sha256", "certificate_issuer")
        ]
        return out

    out += [
        _component(
            "certificate_sha256",
            leaf.sha256_fingerprint,
            FingerprintSource.CERTIFICATE_OBSERVED,
            "SHA-256 over the end-entity certificate's DER bytes.",
            leaf.packet_refs,
        ),
        _component(
            "certificate_spki_sha256",
            leaf.public_key.spki_sha256,
            FingerprintSource.CERTIFICATE_OBSERVED,
            "SHA-256 over the DER SubjectPublicKeyInfo. Identifies the key "
            "pair, so a renewal that kept the key is distinguishable from a "
            "rekey.",
            leaf.packet_refs,
        ),
        _component(
            "certificate_issuer",
            leaf.issuer,
            FingerprintSource.CERTIFICATE_OBSERVED,
            "The issuer distinguished name as it appears in the certificate.",
            leaf.packet_refs,
        ),
    ]
    return out


def canonical_form(components: list[FingerprintComponent]) -> str:
    """The exact string that is hashed.

    One ``name=value`` per line in the fixed ``COMPONENT_NAMES`` order, with
    the algorithm version on the first line so digests from different versions
    can never collide. Absent components are written explicitly, which is what
    keeps an incomplete fingerprint from colliding with a complete one that
    happens to share the components it does have.
    """
    by_name = {component.name: component for component in components}
    lines = [f"version={FINGERPRINT_ALGORITHM_VERSION}"]
    for name in COMPONENT_NAMES:
        component = by_name.get(name)
        value = component.value if component is not None and component.present else None
        lines.append(f"{name}={value if value is not None else ABSENT}")
    return "\n".join(lines)


def configuration_fingerprint(fingerprint: CryptographicFingerprint) -> str | None:
    """A digest of the negotiated settings alone, ignoring the certificate.

    Returns ``None`` when the server's core selection was not observed, so an
    unobserved negotiation never matches another unobserved one.
    """
    by_name = {c.name: c for c in fingerprint.components}
    if not all(
        by_name.get(name) is not None and by_name[name].present for name in _CORE
    ):
        return None
    lines = [f"version={FINGERPRINT_ALGORITHM_VERSION}", "scope=configuration"]
    for name in CONFIGURATION_COMPONENTS:
        component = by_name.get(name)
        value = component.value if component is not None and component.present else None
        lines.append(f"{name}={value if value is not None else ABSENT}")
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    return f"{FINGERPRINT_ALGORITHM_VERSION}/cfg:{digest}"


def _completeness(
    components: list[FingerprintComponent],
) -> tuple[FingerprintCompleteness, tuple[str, ...]]:
    present = {component.name for component in components if component.present}
    missing = tuple(name for name in COMPONENT_NAMES if name not in present)
    if not present >= _CORE:
        return FingerprintCompleteness.INSUFFICIENT, missing
    if missing:
        return FingerprintCompleteness.PARTIAL, missing
    return FingerprintCompleteness.COMPLETE, ()


def build_fingerprint(
    session: TCPSession,
    tls: TLSSessionAnalysis | None,
    capture_id: str,
) -> CryptographicFingerprint:
    """Fingerprint one session's server-observable cryptography."""
    components = _components(tls)
    form = canonical_form(components)
    digest = hashlib.sha256(form.encode("utf-8")).hexdigest()[:16]
    completeness, missing = _completeness(components)

    limitations = [
        "A fingerprint groups configurations. It is not a globally unique "
        "identity: two unrelated servers running the same defaults produce the "
        "same value.",
    ]
    if completeness is FingerprintCompleteness.PARTIAL:
        limitations.append(
            "Incomplete: "
            + ", ".join(missing)
            + " were not observed. Agreement with another fingerprint cannot "
            "establish that the two endpoints are the same server."
        )
    if completeness is FingerprintCompleteness.INSUFFICIENT:
        limitations.append(
            "No server selection was observed, so this fingerprint supports no "
            "comparison at all."
        )

    return CryptographicFingerprint(
        fingerprint_id=f"{FINGERPRINT_ALGORITHM_VERSION}:{digest}",
        algorithm_version=FINGERPRINT_ALGORITHM_VERSION,
        canonical_form=form,
        components=tuple(components),
        completeness=completeness,
        missing_components=missing,
        capture_id=capture_id,
        session_id=session.session_id,
        endpoint=EndpointRef(ip=session.flow.server.ip, port=session.flow.server.port),
        limitations=tuple(limitations),
    )


def compare_fingerprints(
    left: CryptographicFingerprint, right: CryptographicFingerprint
) -> FingerprintComparison:
    """Compare two fingerprints component by component.

    An exact match requires identical digests *and* both sides complete. Two
    TLS 1.3 sessions that agree on everything observable still only reach
    ``PARTIAL_AGREEMENT``, because the certificate components neither of them
    could see might have differed.
    """
    if FingerprintCompleteness.INSUFFICIENT in (left.completeness, right.completeness):
        return FingerprintComparison(
            match=FingerprintMatch.INSUFFICIENT_EVIDENCE,
            explanation=(
                "At least one side has no observed server selection, so there is "
                "nothing to compare."
            ),
            limitations=("Absence of a comparison is not evidence of difference.",),
        )

    left_by_name = {c.name: c for c in left.components}
    right_by_name = {c.name: c for c in right.components}
    agreeing: list[str] = []
    conflicting: list[str] = []
    missing: list[str] = []
    for name in COMPONENT_NAMES:
        a, b = left_by_name.get(name), right_by_name.get(name)
        if a is None or b is None or not a.present or not b.present:
            missing.append(name)
        elif a.value == b.value:
            agreeing.append(name)
        else:
            conflicting.append(name)

    if conflicting:
        match = FingerprintMatch.CONFLICTING_COMPONENTS
        explanation = (
            f"{len(conflicting)} component(s) present in both differ: "
            f"{', '.join(conflicting)}."
        )
    elif missing:
        match = FingerprintMatch.PARTIAL_AGREEMENT
        explanation = (
            f"Every component present in both agrees ({', '.join(agreeing)}), but "
            f"{', '.join(missing)} was not observed on at least one side."
        )
    else:
        match = FingerprintMatch.EXACT_MATCH
        explanation = "Every defined component was observed on both sides and agrees."

    limitations: list[str] = []
    if match is FingerprintMatch.PARTIAL_AGREEMENT:
        limitations.append(
            "Partial agreement is not proof that two endpoints are the same "
            "server. The unobserved components may have differed."
        )
    if match is FingerprintMatch.EXACT_MATCH:
        limitations.append(
            "An exact match establishes identical observable configuration. Two "
            "unrelated servers with the same defaults match exactly."
        )
    return FingerprintComparison(
        match=match,
        agreeing_components=tuple(agreeing),
        conflicting_components=tuple(conflicting),
        missing_components=tuple(missing),
        explanation=explanation,
        limitations=tuple(limitations),
    )
