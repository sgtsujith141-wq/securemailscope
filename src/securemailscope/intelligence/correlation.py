"""Cross-session correlation (M5).

A correlation groups sessions that share an *observation*. It never groups them
by an actor, a campaign or an intent, because a packet capture contains no
evidence of any of those.

What this module will not say, and why:

* **Not "a coordinated attack".** Two servers negotiating TLS 1.0 is two
  servers with old configuration. Nothing in the bytes distinguishes that from
  anything else.
* **Not "the same organisation".** Sharing a certificate or an address is what
  shared hosting looks like. Concluding common ownership from it would be
  wrong far more often than right.
* **Not a network topology.** We observe endpoints, not the paths or
  infrastructure between them.

Findings correlated across captures may have been produced under different
assessment policies. Where they were, the correlation says so: a group that
mixes policy versions is a group whose members were judged by different
criteria.

Grouping is done by **indexing on the shared value**, never by comparing every
session with every other one. That keeps the work linear in the number of
sessions rather than quadratic, which matters once a batch holds thousands.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Final

from ..models.evidence import PacketReference
from ..models.intelligence import CorrelationType, SessionCorrelation

__all__ = ["correlate", "SHARED_LIMITATIONS"]

#: Attached to every correlation. These are the claims a reader might
#: otherwise make from a grouping, and none of them follows from it.
SHARED_LIMITATIONS: Final = (
    "A correlation groups shared observations. It does not establish common "
    "ownership, common administration or a common cause.",
    "No attacker, campaign or intent is inferred. This tool observes "
    "configuration, not adversaries.",
    "Scoped to the analysed captures only. Sessions that were not captured "
    "are not represented here and are not implied to be unaffected.",
)

#: Rules whose repetition is worth reporting as its own pattern, beyond the
#: generic shared-rule-failure grouping.
_PATTERN_RULES: Final = {
    "TLS-PROTO-001": (
        CorrelationType.REPEATED_OBSOLETE_TLS,
        "an obsolete TLS version was negotiated",
    ),
    "TLS-CIPHER-003": (
        CorrelationType.REPEATED_WEAK_CIPHER,
        "a prohibited cipher was negotiated",
    ),
    "TLS-CIPHER-001": (
        CorrelationType.REPEATED_WEAK_CIPHER,
        "a cipher suite providing no encryption was negotiated",
    ),
    "MAIL-001": (
        CorrelationType.AUTHENTICATION_EXPOSURE,
        "credentials were submitted over an unencrypted session",
    ),
    "MAIL-002": (
        CorrelationType.AUTHENTICATION_EXPOSURE,
        "credentials were submitted before the TLS upgrade took effect",
    ),
}


def _correlation_id(
    kind: CorrelationType,
    basis: str,
    session_ids: list[str],
    capture_ids: list[str],
) -> str:
    """Stable across runs, independent of input order, and scoped to members.

    The identifier covers the correlation's type, its shared value **and the
    identities of its members**. Type and basis alone are not enough: two
    investigations that each contain sessions failing ``TLS-PROTO-001`` would
    otherwise produce the same identifier for two entirely disjoint groups,
    and anyone diffing the reports would read them as the same correlation.

    Including the members keeps the property that actually matters -- the same
    grouping, analysed twice, carries the same identifier -- while making a
    different grouping a different correlation. Members are sorted, so the id
    does not depend on the order captures were supplied in.
    """
    material = "|".join(
        (
            kind.value,
            basis,
            "sessions=" + ",".join(sorted(session_ids)),
            "captures=" + ",".join(sorted(capture_ids)),
        )
    )
    return "corr-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _build(
    kind: CorrelationType,
    basis: str,
    members: list[dict[str, Any]],
    *,
    extra_limitations: tuple[str, ...] = (),
) -> SessionCorrelation:
    sessions = sorted({member["session_id"] for member in members})
    captures = sorted({member["capture_id"] for member in members})
    findings = sorted({f for member in members for f in member.get("finding_ids", ())})
    entities = sorted({member["entity_id"] for member in members if member.get("entity_id")})
    policies = sorted({p for member in members if (p := member.get("policy_version"))})

    # De-duplicate evidence by (packet number, timestamp): one finding backed
    # by several records must not look like several findings.
    seen: set[tuple[int, int]] = set()
    evidence: list[PacketReference] = []
    for member in members:
        for reference in member.get("evidence", ()):
            key = (reference.packet_number, reference.timestamp_ns)
            if key not in seen:
                seen.add(key)
                evidence.append(reference)
    evidence.sort(key=lambda reference: (reference.timestamp_ns, reference.packet_number))

    stamps = [
        member["timestamp"] for member in members if member.get("timestamp") is not None
    ]
    limitations = SHARED_LIMITATIONS + extra_limitations
    if len(policies) > 1:
        limitations += (
            "These findings were produced under more than one assessment policy "
            f"version ({', '.join(policies)}). They were judged by different "
            "criteria and are grouped only by the condition they describe.",
        )

    return SessionCorrelation(
        correlation_id=_correlation_id(kind, basis, sessions, captures),
        correlation_type=kind,
        related_session_ids=tuple(sessions),
        related_capture_ids=tuple(captures),
        related_finding_ids=tuple(findings),
        related_entity_ids=tuple(entities),
        supporting_evidence=tuple(evidence),
        relationship_basis=basis,
        policy_versions=tuple(policies),
        first_observed=min(stamps) if stamps else None,
        last_observed=max(stamps) if stamps else None,
        limitations=limitations,
    )


def correlate(
    finding_members: list[dict[str, Any]],
    session_members: list[dict[str, Any]],
    *,
    max_correlations: int,
) -> tuple[list[SessionCorrelation], bool]:
    """Group sessions by shared observations.

    ``finding_members`` carries one entry per (finding, session);
    ``session_members`` one entry per session with its observable identifiers.
    Both are assembled by the engine so this module needs no analysis imports.

    Returns the correlations and whether the ``max_correlations`` limit
    truncated them. A truncated result that did not say so would be read as a
    complete one.
    """
    groups: list[tuple[CorrelationType, str, list[dict[str, Any]], tuple[str, ...]]] = []

    # A rule that failed in more than one session.
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for member in finding_members:
        by_rule[member["rule_id"]].append(member)
    for rule_id, members in sorted(by_rule.items()):
        if len({member["session_id"] for member in members}) < 2:
            continue
        groups.append(
            (
                CorrelationType.SHARED_RULE_FAILURE,
                f"rule_id={rule_id}",
                members,
                (
                    "The same rule failing in several sessions means the same "
                    "condition was observed in each. It does not mean one cause.",
                ),
            )
        )
        pattern = _PATTERN_RULES.get(rule_id)
        if pattern is not None:
            kind, description = pattern
            groups.append(
                (
                    kind,
                    f"rule_id={rule_id}",
                    members,
                    (f"In each of these sessions, {description}.",),
                )
            )

    # Sessions sharing an observed certificate or public key.
    for attribute, kind, label, note in (
        (
            "certificates",
            CorrelationType.SHARED_CERTIFICATE,
            "certificate_sha256",
            "The same certificate was presented. This is what a load-balanced "
            "pool and a shared-hosting tenant both look like.",
        ),
        (
            "public_keys",
            CorrelationType.SHARED_PUBLIC_KEY,
            "certificate_spki_sha256",
            "The same key pair was presented, possibly under different "
            "certificates, which is what a renewal that kept its key looks like.",
        ),
    ):
        index: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for member in session_members:
            for value in member.get(attribute, ()):
                index[value].append(member)
        for value, members in sorted(index.items()):
            if len({member["session_id"] for member in members}) < 2:
                continue
            groups.append((kind, f"{label}={value}", members, (note,)))

    # Sessions on one observed endpoint.
    by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for member in session_members:
        if member.get("entity_id"):
            by_entity[member["entity_id"]].append(member)
    for entity_id, members in sorted(by_entity.items()):
        if len({member["session_id"] for member in members}) < 2:
            continue
        groups.append(
            (
                CorrelationType.SHARED_ENDPOINT,
                f"entity_id={entity_id}",
                members,
                (
                    "The same (ip, port) was observed. Whether that endpoint is "
                    "one machine or a pool is not observable.",
                ),
            )
        )
        # Divergent configuration on one endpoint is worth its own entry: it
        # is the observation that a pool is not uniformly configured.
        # Settings, not certificates: a renewed certificate is not a
        # configuration divergence, and reporting it as one would bury the
        # cases where a pool really is inconsistently configured.
        configurations = {
            member["configuration_fingerprint"]
            for member in members
            if member.get("configuration_fingerprint")
        }
        if len(configurations) > 1:
            groups.append(
                (
                    CorrelationType.ENDPOINT_CONFIGURATION_DIVERGENCE,
                    f"entity_id={entity_id}",
                    members,
                    (
                        f"{len(configurations)} distinct negotiated configurations "
                        "were observed on one endpoint. Differing client offers "
                        "alone can produce this; see the drift events, which "
                        "account for the offers before attributing a change.",
                    ),
                )
            )

    built = [
        _build(kind, basis, members, extra_limitations=extra)
        for kind, basis, members, extra in groups
    ]
    built.sort(key=lambda item: (item.correlation_type.value, item.relationship_basis))
    truncated = len(built) > max_correlations
    return built[:max_correlations], truncated
