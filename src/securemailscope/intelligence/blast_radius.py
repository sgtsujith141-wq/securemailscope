"""Blast-radius analysis (M5).

How far a condition was *observed* to reach. Not how far it might reach, not
how far it probably reaches, and emphatically not how far it reaches across an
enterprise nobody captured.

The counting rules exist because each has an obvious wrong alternative:

* **Endpoints are counted by ``(ip, port)``.** A client that opened eight
  connections from eight ephemeral source ports contacted one endpoint. Counting
  eight would inflate every number in this module by whatever the client's
  connection pool happened to be.
* **Captures are counted by content hash.** The same file submitted twice, or
  under two names, is one capture. Counting it twice would double a blast
  radius by re-reading the same evidence.
* **Sessions are counted by session id**, which is already unique per capture.
* **Findings are counted by finding id**, which is stable and policy-bound, so
  one condition reported once per session counts once per session and not once
  per supporting evidence record.

Every result carries the scope statement verbatim, because the number is
meaningless without it:

    Observed within analyzed captures only.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Final

from ..models.intelligence import BlastRadius

__all__ = ["COUNTING_METHOD", "SCOPE_STATEMENT", "blast_radius_for", "build_blast_radius"]

SCOPE_STATEMENT: Final = "Observed within analyzed captures only."

COUNTING_METHOD: Final = (
    "Sessions counted by distinct session id. Endpoints counted by distinct "
    "(server ip, server port), so multiple source ports to one service count "
    "once. Captures counted by distinct capture content hash, so a file "
    "submitted twice counts once. Findings counted by distinct finding id."
)

_LIMITATIONS: Final = (
    SCOPE_STATEMENT,
    "Sessions that were not captured are not represented and are not implied "
    "to be unaffected. Absence from this count is absence of observation.",
    "No claim is made about hosts, users or services outside the captures.",
    "An endpoint may be a single machine, a load-balanced pool or a virtual "
    "host. A capture does not distinguish them, so the endpoint count is a "
    "count of observed network endpoints, not of physical servers.",
    "Business criticality is not represented. None is inferred from an "
    "address, a port or a hostname.",
)


def blast_radius_for(
    subject: str,
    subject_kind: str,
    members: list[dict[str, Any]],
) -> BlastRadius:
    """Count the observed reach of one condition."""
    sessions = sorted({member["session_id"] for member in members})
    entities = sorted({member["entity_id"] for member in members if member.get("entity_id")})
    captures = sorted({member["capture_id"] for member in members})
    findings = sorted({f for member in members for f in member.get("finding_ids", ())})
    protocols = Counter(
        member["protocol"] for member in members if member.get("protocol")
    )
    stamps = [m["timestamp"] for m in members if m.get("timestamp") is not None]

    return BlastRadius(
        subject=subject,
        subject_kind=subject_kind,
        affected_session_ids=tuple(sessions),
        affected_entity_ids=tuple(entities),
        affected_capture_ids=tuple(captures),
        related_finding_ids=tuple(findings),
        session_count=len(sessions),
        entity_count=len(entities),
        capture_count=len(captures),
        finding_count=len(findings),
        protocol_distribution=dict(sorted(protocols.items())),
        first_observed=min(stamps) if stamps else None,
        last_observed=max(stamps) if stamps else None,
        scope_statement=SCOPE_STATEMENT,
        counting_method=COUNTING_METHOD,
        limitations=_LIMITATIONS,
    )


def build_blast_radius(finding_members: list[dict[str, Any]]) -> list[BlastRadius]:
    """One blast radius per rule that produced a finding anywhere."""
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for member in finding_members:
        by_rule.setdefault(member["rule_id"], []).append(member)
    return [
        blast_radius_for(rule_id, "RULE", members)
        for rule_id, members in sorted(by_rule.items())
    ]
