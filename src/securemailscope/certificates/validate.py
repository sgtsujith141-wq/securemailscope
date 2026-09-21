"""Five independent certificate validation checks.

Parsing a certificate is not validating it, and each of these questions has
its own answer:

======================= ====================================================
Check                   Question
======================= ====================================================
certificate_observed    Was a certificate actually visible in this capture?
validity_dates_checked  Was it within its validity window *at capture time*?
chain_verified          Does it chain to an explicitly configured anchor?
hostname_verified       Does it name the identity the analyst expected?
revocation_checked      Was it revoked?  (Never performed -- see below.)
======================= ====================================================

**Chain and hostname are deliberately separated.**  The installed library
exposes them together through ``ServerVerifier``, so each is isolated by
neutralising the other:

* For the **chain** check the subject is taken from the leaf's own first DNS
  SAN, so the name always matches and any failure is a trust-path failure.
* For the **hostname** check the store is the presented chain itself, so the
  path always succeeds and any failure is a name mismatch.

This is a deviation from "use one established API call" and is documented
because the alternative -- a hand-written RFC 6125 matcher -- would be a
second, unverified implementation of the rule that matters most.

**Revocation is never performed.**  No OCSP or CRL is fetched, because the
engine makes no network requests at all.  A successful chain verification is
not evidence of non-revocation and is never reported as such.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..models.certificates import (
    AssessmentMode,
    CertificateObservation,
    CertificateValidation,
    TrustStoreInfo,
    ValidationCheck,
    ValidationStatus,
)
from .parse import CRYPTOGRAPHY_AVAILABLE
from .truststore import NO_TRUST_STORE, LoadedTrustStore, build_store

__all__ = ["validate_chain", "REVOCATION_EXPLANATION"]

REVOCATION_EXPLANATION = (
    "No revocation check was performed. SecureMailScope makes no network requests, so "
    "OCSP and CRL retrieval are out of scope by design. A successful chain verification "
    "is not evidence that a certificate has not been revoked."
)

_NOT_OBSERVED_EXPLANATION = (
    "No certificate was available to check, so this question cannot be answered."
)


def _check(
    name: str,
    status: ValidationStatus,
    explanation: str,
    *,
    detail: str | None = None,
    reference_time: datetime | None = None,
    mode: AssessmentMode | None = None,
    limitations: tuple[str, ...] = (),
) -> ValidationCheck:
    return ValidationCheck(
        name=name,
        status=status,
        explanation=explanation,
        detail=detail,
        reference_time=reference_time,
        assessment_mode=mode,
        limitations=limitations,
    )


def _first_dns_name(observation: CertificateObservation) -> str | None:
    for entry in observation.subject_alternative_names:
        if entry.startswith("DNS:"):
            return entry[4:]
    return None


def _dates(
    leaf: CertificateObservation,
    capture_time: datetime | None,
    *,
    also_current: bool,
) -> ValidationCheck:
    if capture_time is None:
        return _check(
            "validity_dates_checked",
            ValidationStatus.NOT_AVAILABLE,
            "The capture carries no timestamp, so validity at the time of the traffic "
            "cannot be assessed. The current clock is deliberately not substituted.",
        )
    within = leaf.not_valid_before <= capture_time <= leaf.not_valid_after
    limitations: list[str] = []
    if also_current:
        now = datetime.now(tz=UTC)
        current = leaf.not_valid_before <= now <= leaf.not_valid_after
        limitations.append(
            f"At analysis time ({now.isoformat()}) the certificate is "
            f"{'within' if current else 'outside'} its validity window. This is a "
            "separate assessment from the capture-time one above."
        )
    if within:
        return _check(
            "validity_dates_checked",
            ValidationStatus.PASSED,
            f"The end-entity certificate was within its validity window at the capture "
            f"timestamp ({capture_time.isoformat()}).",
            reference_time=capture_time,
            mode=AssessmentMode.CAPTURE_TIME,
            limitations=tuple(limitations),
        )
    reason = (
        "had already expired"
        if capture_time > leaf.not_valid_after
        else "was not yet valid"
    )
    return _check(
        "validity_dates_checked",
        ValidationStatus.FAILED,
        f"The end-entity certificate {reason} at the capture timestamp "
        f"({capture_time.isoformat()}); it is valid from "
        f"{leaf.not_valid_before.isoformat()} to {leaf.not_valid_after.isoformat()}.",
        reference_time=capture_time,
        mode=AssessmentMode.CAPTURE_TIME,
        limitations=tuple(limitations),
    )


def _chain(
    certificates: list[Any],
    observations: list[CertificateObservation],
    trust_store: LoadedTrustStore,
    capture_time: datetime | None,
) -> ValidationCheck:
    if not trust_store.usable:
        return _check(
            "chain_verified",
            ValidationStatus.NOT_AVAILABLE,
            "No trust store is configured, so there is nothing to verify against. "
            "SecureMailScope never falls back to a system trust store, because a report "
            "must be able to name the anchors it used.",
            detail=trust_store.error,
            limitations=(
                "Configure a PEM trust store to enable this check. Intermediates are "
                "never fetched from the network.",
            ),
        )
    if capture_time is None:
        return _check(
            "chain_verified",
            ValidationStatus.NOT_AVAILABLE,
            "The capture carries no timestamp, so path validation has no reference time.",
        )

    leaf_name = _first_dns_name(observations[0])
    if leaf_name is None:
        return _check(
            "chain_verified",
            ValidationStatus.NOT_AVAILABLE,
            "The end-entity certificate has no dNSName subjectAltName, so the installed "
            "verification API cannot be driven without also imposing a name constraint.",
            limitations=(
                "Chain verification is isolated by using the leaf's own name as the "
                "subject; a certificate without one cannot be checked this way.",
            ),
        )

    from cryptography.x509.verification import (
        DNSName,
        PolicyBuilder,
        VerificationError,
    )

    intermediates = certificates[1:]
    assert trust_store.store is not None  # guaranteed by LoadedTrustStore.usable
    try:
        chain = (
            PolicyBuilder()
            .store(trust_store.store)
            .time(capture_time)
            .build_server_verifier(DNSName(leaf_name))
            .verify(certificates[0], intermediates)
        )
    except VerificationError as error:
        incomplete = _looks_incomplete(observations, trust_store.info)
        explanation = (
            "The presented chain could not be built to a configured trust anchor. "
            + (
                "The chain appears incomplete: the end-entity certificate's issuer is "
                "neither among the certificates the server presented nor among the "
                "configured anchors, which is a different condition from a chain that "
                "was built and found invalid."
                if incomplete
                else "A complete path was available but did not validate."
            )
        )
        return _check(
            "chain_verified",
            ValidationStatus.FAILED,
            explanation,
            detail=str(error),
            reference_time=capture_time,
            mode=AssessmentMode.CAPTURE_TIME,
            limitations=(REVOCATION_EXPLANATION,),
        )
    except Exception as error:
        return _check(
            "chain_verified",
            ValidationStatus.ERROR,
            "Chain verification raised an unexpected error and produced no result.",
            detail=f"{type(error).__name__}: {error}",
        )

    return _check(
        "chain_verified",
        ValidationStatus.PASSED,
        f"The certificate chains to a configured trust anchor at the capture timestamp "
        f"({capture_time.isoformat()}); the validated path is {len(chain)} certificate(s) "
        "long.",
        reference_time=capture_time,
        mode=AssessmentMode.CAPTURE_TIME,
        limitations=(REVOCATION_EXPLANATION,),
    )


def _looks_incomplete(
    observations: list[CertificateObservation], store: TrustStoreInfo
) -> bool:
    """True when the leaf's issuer is absent from everything we hold."""
    if not observations:
        return True
    issuer = observations[0].issuer
    presented = {observation.subject for observation in observations[1:]}
    return issuer not in presented and store.anchor_count > 0 and len(observations) == 1


def _hostname(
    certificates: list[Any],
    observations: list[CertificateObservation],
    trust_store: LoadedTrustStore,
    capture_time: datetime | None,
    reference_identity: str | None,
) -> ValidationCheck:
    if reference_identity is None:
        return _check(
            "hostname_verified",
            ValidationStatus.NOT_AVAILABLE,
            "No expected server identity was supplied. The destination IP address is "
            "never used as one, and an observed SNI value is the client's request "
            "rather than an authorised expectation, so this check cannot be performed.",
            limitations=(
                "Supply an expected identity to enable this check, or explicitly elect "
                "to trust the observed SNI.",
            ),
        )
    if capture_time is None:
        return _check(
            "hostname_verified",
            ValidationStatus.NOT_AVAILABLE,
            "The capture carries no timestamp, so the verification API has no reference "
            "time.",
        )

    from cryptography.x509.verification import (
        DNSName,
        PolicyBuilder,
        VerificationError,
    )

    # Neutralise the path question: trust exactly what was presented, plus any
    # configured anchors, so the only remaining failure mode is the name.
    anchors = list(certificates) + list(trust_store.anchors)
    isolated = build_store(anchors, source_kind="IN_MEMORY")
    if not isolated.usable:  # pragma: no cover - anchors is non-empty here
        return _check(
            "hostname_verified",
            ValidationStatus.ERROR,
            "The presented certificates could not be assembled into a verification store.",
            detail=isolated.error,
        )
    assert isolated.store is not None  # guaranteed by LoadedTrustStore.usable
    try:
        PolicyBuilder().store(isolated.store).time(capture_time).build_server_verifier(
            DNSName(reference_identity)
        ).verify(certificates[0], certificates[1:])
    except VerificationError as error:
        return _check(
            "hostname_verified",
            ValidationStatus.FAILED,
            f"The certificate does not name the expected identity "
            f"'{reference_identity}'. Presented names: "
            f"{', '.join(observations[0].subject_alternative_names) or 'none'}.",
            detail=str(error),
            reference_time=capture_time,
            mode=AssessmentMode.CAPTURE_TIME,
            limitations=(
                "This check isolates the name question by trusting the presented chain; "
                "it says nothing about whether that chain is trustworthy.",
            ),
        )
    except Exception as error:
        return _check(
            "hostname_verified",
            ValidationStatus.ERROR,
            "Hostname verification raised an unexpected error and produced no result.",
            detail=f"{type(error).__name__}: {error}",
        )
    return _check(
        "hostname_verified",
        ValidationStatus.PASSED,
        f"The certificate names the expected identity '{reference_identity}'.",
        reference_time=capture_time,
        mode=AssessmentMode.CAPTURE_TIME,
        limitations=(
            "This check isolates the name question by trusting the presented chain; it "
            "says nothing about whether that chain is trustworthy.",
        ),
    )


def validate_chain(
    observations: list[CertificateObservation],
    certificates: list[Any],
    *,
    capture_time: datetime | None,
    trust_store: LoadedTrustStore,
    reference_identity: str | None,
    reference_identity_source: str,
    observed_sni: str | None,
    assess_current_time: bool = False,
) -> CertificateValidation:
    """Run the five checks. Each answers only its own question."""
    if not observations or not certificates:
        unavailable = _check(
            "unavailable", ValidationStatus.NOT_AVAILABLE, _NOT_OBSERVED_EXPLANATION
        )
        return CertificateValidation(
            certificate_observed=_check(
                "certificate_observed",
                ValidationStatus.FAILED,
                "No certificate was extracted from this session, so nothing could be "
                "validated. This is not itself a certificate error -- see the "
                "inventory's visibility field for why none was available.",
            ),
            validity_dates_checked=unavailable.model_copy(
                update={"name": "validity_dates_checked"}
            ),
            chain_verified=unavailable.model_copy(update={"name": "chain_verified"}),
            hostname_verified=unavailable.model_copy(update={"name": "hostname_verified"}),
            revocation_checked=_check(
                "revocation_checked", ValidationStatus.NOT_AVAILABLE, REVOCATION_EXPLANATION
            ),
            trust_store=trust_store.info if trust_store.usable else NO_TRUST_STORE,
            reference_identity=reference_identity,
            reference_identity_source=reference_identity_source,
            observed_sni=observed_sni,
            capture_time=capture_time,
        )

    if not CRYPTOGRAPHY_AVAILABLE:  # pragma: no cover
        unavailable = _check(
            "unavailable",
            ValidationStatus.NOT_AVAILABLE,
            "The cryptography library is not installed, so no validation is possible.",
        )
        return CertificateValidation(
            certificate_observed=_check(
                "certificate_observed", ValidationStatus.PASSED, "A certificate was observed."
            ),
            validity_dates_checked=unavailable.model_copy(
                update={"name": "validity_dates_checked"}
            ),
            chain_verified=unavailable.model_copy(update={"name": "chain_verified"}),
            hostname_verified=unavailable.model_copy(update={"name": "hostname_verified"}),
            revocation_checked=_check(
                "revocation_checked", ValidationStatus.NOT_AVAILABLE, REVOCATION_EXPLANATION
            ),
            trust_store=NO_TRUST_STORE,
            reference_identity=reference_identity,
            reference_identity_source=reference_identity_source,
            observed_sni=observed_sni,
            capture_time=capture_time,
        )

    return CertificateValidation(
        certificate_observed=_check(
            "certificate_observed",
            ValidationStatus.PASSED,
            f"{len(observations)} certificate(s) were observed in a plaintext Certificate "
            "message and decoded.",
        ),
        validity_dates_checked=_dates(
            observations[0], capture_time, also_current=assess_current_time
        ),
        chain_verified=_chain(certificates, observations, trust_store, capture_time),
        hostname_verified=_hostname(
            certificates, observations, trust_store, capture_time, reference_identity
        ),
        revocation_checked=_check(
            "revocation_checked", ValidationStatus.NOT_AVAILABLE, REVOCATION_EXPLANATION
        ),
        trust_store=trust_store.info,
        reference_identity=reference_identity,
        reference_identity_source=reference_identity_source,
        observed_sni=observed_sni,
        capture_time=capture_time,
        limitations=(
            "Chain and hostname verification are independent: neither implies the other, "
            "and neither implies anything about revocation.",
        ),
    )
