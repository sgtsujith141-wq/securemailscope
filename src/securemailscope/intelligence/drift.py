"""Cryptographic drift across captures (M5).

Drift compares one *endpoint's* observable configuration between two captures.
Two rules do most of the work, and both are refusals:

**Absence is not change.** If a parameter was observed in the first capture and
not in the second, the answer is ``NOT_COMPARABLE``. Reporting it as a change
would turn a short or truncated second capture into a false alarm about a
server that never moved.

**A different selection is not necessarily a different server.** TLS
negotiation is a function of two inputs. A server that selected AES-128-GCM for
one client and AES-256-GCM for another may be configured identically and simply
answering two different offers. So when the negotiated value differs, this
module compares what the *clients* offered: only if the offers were the same is
the server implicated, and the result is ``OBSERVED_CHANGE``. Otherwise it is
``INCONCLUSIVE``, with the differing offers recorded.

Certificate comparisons are not subject to the second rule -- a server presents
its certificate regardless of what was offered -- so a changed certificate
fingerprint is an ``OBSERVED_CHANGE`` directly.

Posture-score drift is kept apart from cryptographic drift and is only reported
when the two captures were assessed under the **same policy fingerprint**. A
score that moved because a threshold was changed is not a security change, and
presenting it as one would be the most misleading thing this module could do.
"""

from __future__ import annotations

import hashlib
from itertools import pairwise
from typing import TYPE_CHECKING, Final, NamedTuple

from ..models.intelligence import (
    DriftEvent,
    DriftKind,
    DriftObservation,
    DriftStatus,
)

if TYPE_CHECKING:
    from ..models.intelligence import ServerEntity

__all__ = ["SessionSnapshot", "compare_snapshots", "drift_for_entity"]


class SessionSnapshot(NamedTuple):
    """One session's comparable values, extracted once by the engine."""

    capture_id: str
    session_id: str
    timestamp: object
    timestamp_ns: int | None
    values: dict[str, str | None]
    evidence: dict[str, tuple]
    #: The client's offered suites and versions, canonicalised. Two snapshots
    #: with equal offer signatures asked the server the same question.
    client_offer_signature: str | None
    client_offer_summary: str | None
    policy_fingerprint: str | None
    posture_score: int | None
    coverage_ratio: float | None


#: Which value each drift kind reads, and whether the client's offer can
#: explain a difference in it.
_KINDS: Final = (
    (DriftKind.NEGOTIATED_VERSION, "tls_version", True),
    (DriftKind.NEGOTIATED_CIPHER_SUITE, "cipher_suite", True),
    (DriftKind.KEY_EXCHANGE_GROUP, "key_exchange_group", True),
    (DriftKind.CERTIFICATE_FINGERPRINT, "certificate_sha256", False),
    (DriftKind.CERTIFICATE_PUBLIC_KEY, "certificate_spki_sha256", False),
    (DriftKind.CERTIFICATE_VALIDITY, "certificate_validity", False),
)

_NEGOTIATION_LIMITATION: Final = (
    "A negotiated value is chosen from what the client offered. Comparing two "
    "sessions compares two negotiations, not two server configurations."
)


def _drift_id(entity_id: str, kind: DriftKind, before: str, after: str) -> str:
    material = f"{entity_id}|{kind.value}|{before}|{after}"
    return "drift-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def compare_snapshots(
    entity_id: str,
    before: SessionSnapshot,
    after: SessionSnapshot,
    kind: DriftKind,
    field: str,
    *,
    offer_sensitive: bool,
) -> DriftEvent:
    """Compare one property between two sessions on the same endpoint."""
    before_value = before.values.get(field)
    after_value = after.values.get(field)
    before_obs = DriftObservation(
        capture_id=before.capture_id,
        session_id=before.session_id,
        value=before_value,
        observed=before_value is not None,
        timestamp=before.timestamp,  # type: ignore[arg-type]
        timestamp_ns=before.timestamp_ns,
        evidence_refs=before.evidence.get(field, ()),
    )
    after_obs = DriftObservation(
        capture_id=after.capture_id,
        session_id=after.session_id,
        value=after_value,
        observed=after_value is not None,
        timestamp=after.timestamp,  # type: ignore[arg-type]
        timestamp_ns=after.timestamp_ns,
        evidence_refs=after.evidence.get(field, ()),
    )

    # Only meaningful where a different offer could explain a different
    # answer. Left as None elsewhere rather than reporting a check that was
    # never relevant.
    offers_comparable: bool | None = None
    offer_context: str | None = None
    if offer_sensitive:
        offers_comparable = (
            before.client_offer_signature is not None
            and before.client_offer_signature == after.client_offer_signature
        )
        offer_context = (
            f"before: {before.client_offer_summary or 'not observed'}; "
            f"after: {after.client_offer_summary or 'not observed'}"
        )

    if before_value is None or after_value is None:
        missing = "the earlier" if before_value is None else "the later"
        return DriftEvent(
            drift_id=_drift_id(entity_id, kind, str(before_value), str(after_value)),
            kind=kind,
            status=DriftStatus.NOT_COMPARABLE,
            entity_id=entity_id,
            before=before_obs,
            after=after_obs,
            client_offer_context=offer_context,
            client_offers_comparable=offers_comparable,
            explanation=(
                f"This property was not observed in {missing} capture, so the two "
                "cannot be compared. Absence of an observation is not a change."
            ),
            limitations=(
                "A parameter missing from one capture is an evidence gap, never "
                "evidence that it changed.",
            ),
        )

    if before_value == after_value:
        return DriftEvent(
            drift_id=_drift_id(entity_id, kind, before_value, after_value),
            kind=kind,
            status=DriftStatus.UNCHANGED_WITH_EVIDENCE,
            entity_id=entity_id,
            before=before_obs,
            after=after_obs,
            client_offer_context=offer_context,
            client_offers_comparable=offers_comparable,
            explanation=(
                f"Observed as {before_value} in both captures. This is positive "
                "evidence of stability, not merely an absence of change."
            ),
            limitations=(_NEGOTIATION_LIMITATION,) if offer_sensitive else (),
        )

    if offer_sensitive and not offers_comparable:
        return DriftEvent(
            drift_id=_drift_id(entity_id, kind, before_value, after_value),
            kind=kind,
            status=DriftStatus.INCONCLUSIVE,
            entity_id=entity_id,
            before=before_obs,
            after=after_obs,
            client_offer_context=offer_context,
            client_offers_comparable=False,
            explanation=(
                f"The negotiated value differs ({before_value} then {after_value}), "
                "but the two clients did not offer the same thing. A server "
                "answering different questions differently has not been shown to "
                "have changed."
            ),
            limitations=(
                "To attribute a negotiated difference to the server, capture two "
                "sessions whose clients offer the same suites and versions.",
                _NEGOTIATION_LIMITATION,
            ),
        )

    return DriftEvent(
        drift_id=_drift_id(entity_id, kind, before_value, after_value),
        kind=kind,
        status=DriftStatus.OBSERVED_CHANGE,
        entity_id=entity_id,
        before=before_obs,
        after=after_obs,
        client_offer_context=offer_context,
        client_offers_comparable=offers_comparable,
        explanation=(
            f"Changed from {before_value} to {after_value} on the same observed "
            "endpoint."
            + (
                " The clients offered the same suites and versions, so the "
                "difference is attributable to the server."
                if offer_sensitive
                else " A certificate is presented regardless of what the client "
                "offered, so this difference is attributable to the server."
            )
        ),
        limitations=(
            "Attributed to an observed (ip, port). If that endpoint is a "
            "load-balanced pool, two different backends may have answered.",
        ),
    )


def _score_drift(
    entity_id: str, before: SessionSnapshot, after: SessionSnapshot
) -> DriftEvent | None:
    """Compare posture scores, but only across compatible policies."""
    if before.posture_score is None and after.posture_score is None:
        # Neither side was scored. There is nothing to report, and inventing
        # an event would only add noise.
        return None
    if before.posture_score is None or after.posture_score is None:
        # One side was scored and the other was not -- most often because
        # coverage fell below the floor. Reporting nothing would leave a
        # reader diffing two reports to notice the score had vanished and
        # guess why, so this is reported as explicitly incomparable.
        missing = "the earlier" if before.posture_score is None else "the later"
        return DriftEvent(
            drift_id=_drift_id(
                entity_id,
                DriftKind.POSTURE_SCORE,
                str(before.posture_score),
                str(after.posture_score),
            ),
            kind=DriftKind.POSTURE_SCORE,
            status=DriftStatus.NOT_COMPARABLE,
            entity_id=entity_id,
            before=DriftObservation(
                capture_id=before.capture_id,
                session_id=before.session_id,
                value=None if before.posture_score is None else str(before.posture_score),
                observed=before.posture_score is not None,
                timestamp=before.timestamp,  # type: ignore[arg-type]
                timestamp_ns=before.timestamp_ns,
            ),
            after=DriftObservation(
                capture_id=after.capture_id,
                session_id=after.session_id,
                value=None if after.posture_score is None else str(after.posture_score),
                observed=after.posture_score is not None,
                timestamp=after.timestamp,  # type: ignore[arg-type]
                timestamp_ns=after.timestamp_ns,
            ),
            explanation=(
                f"No score was available for {missing} capture, so the two cannot "
                "be compared. A score is withheld when coverage is too low for it "
                "to mean anything, which is an evidence gap, not a change."
            ),
            limitations=(
                "Compare coverage before concluding anything from a score that "
                "appeared or disappeared between two captures.",
            ),
        )
    before_obs = DriftObservation(
        capture_id=before.capture_id,
        session_id=before.session_id,
        value=str(before.posture_score),
        observed=True,
        timestamp=before.timestamp,  # type: ignore[arg-type]
        timestamp_ns=before.timestamp_ns,
    )
    after_obs = DriftObservation(
        capture_id=after.capture_id,
        session_id=after.session_id,
        value=str(after.posture_score),
        observed=True,
        timestamp=after.timestamp,  # type: ignore[arg-type]
        timestamp_ns=after.timestamp_ns,
    )
    coverage = (
        f"coverage {before.coverage_ratio} then {after.coverage_ratio}"
        if before.coverage_ratio is not None and after.coverage_ratio is not None
        else "coverage not reported on both sides"
    )

    if before.policy_fingerprint != after.policy_fingerprint:
        return DriftEvent(
            drift_id=_drift_id(
                entity_id, DriftKind.POSTURE_SCORE, str(before.posture_score),
                str(after.posture_score),
            ),
            kind=DriftKind.POSTURE_SCORE,
            status=DriftStatus.NOT_COMPARABLE,
            entity_id=entity_id,
            before=before_obs,
            after=after_obs,
            explanation=(
                "The two captures were assessed under different policy "
                f"fingerprints ({before.policy_fingerprint} then "
                f"{after.policy_fingerprint}), so their scores are not "
                "comparable. A score that moved because a threshold changed is "
                "not a security change."
            ),
            limitations=(
                "Re-run both captures under one policy to compare scores.",
            ),
        )

    if before.posture_score == after.posture_score:
        status, explanation = (
            DriftStatus.UNCHANGED_WITH_EVIDENCE,
            f"Score unchanged at {before.posture_score} under the same policy ({coverage}).",
        )
    else:
        status, explanation = (
            DriftStatus.OBSERVED_CHANGE,
            f"Score moved from {before.posture_score} to {after.posture_score} "
            f"under the same policy ({coverage}).",
        )
    return DriftEvent(
        drift_id=_drift_id(
            entity_id, DriftKind.POSTURE_SCORE, str(before.posture_score),
            str(after.posture_score),
        ),
        kind=DriftKind.POSTURE_SCORE,
        status=status,
        entity_id=entity_id,
        before=before_obs,
        after=after_obs,
        explanation=explanation,
        limitations=(
            "Score drift is a policy judgement moving, not by itself a "
            "cryptographic change. The cryptographic drift events are reported "
            "separately and are the evidence.",
            "Scores computed over different coverage describe different "
            "populations of controls.",
        ),
    )


def drift_for_entity(
    entity: ServerEntity, snapshots: list[SessionSnapshot]
) -> list[DriftEvent]:
    """Compare consecutive captures for one endpoint, in chronological order.

    Sessions are grouped by capture and compared capture-to-capture. Within a
    capture the earliest session is used, so a capture with several sessions to
    one endpoint does not produce a combinatorial explosion of comparisons.
    """
    by_capture: dict[str, SessionSnapshot] = {}
    for snapshot in sorted(
        snapshots, key=lambda s: (s.timestamp_ns or 0, s.capture_id, s.session_id)
    ):
        by_capture.setdefault(snapshot.capture_id, snapshot)
    ordered = sorted(
        by_capture.values(), key=lambda s: (s.timestamp_ns or 0, s.capture_id)
    )
    if len(ordered) < 2:
        return []

    events: list[DriftEvent] = []
    for before, after in pairwise(ordered):
        for kind, field, offer_sensitive in _KINDS:
            events.append(
                compare_snapshots(
                    entity.entity_id,
                    before,
                    after,
                    kind,
                    field,
                    offer_sensitive=offer_sensitive,
                )
            )
        score_event = _score_drift(entity.entity_id, before, after)
        if score_event is not None:
            events.append(score_event)
    return events
