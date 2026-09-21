"""Server identity resolution (M5).

The central decision in this module is what it refuses to do: **entities are
never merged.**

A :class:`ServerEntity` is one observed ``(ip, port)``. That is the only
equality this module performs, because it is the only one the evidence
supports. Every weaker signal -- a shared certificate, a shared key, a shared
SNI, an identical configuration -- becomes a typed
:class:`IdentityRelationship` between two entities that remain separate.

Why the naive merges are wrong:

* **Same certificate is not the same server.** A load-balanced pool presents
  one certificate from many machines; a hosting provider presents one SAN
  certificate for many unrelated tenants. Merging on certificate would fuse a
  customer's mail server with a stranger's.
* **Same IP is not the same application.** One address commonly serves SMTP on
  25, submission on 587 and IMAP on 993, which are three services that can be
  configured, and misconfigured, independently.
* **Same SNI is not the same infrastructure.** SNI is what the *client* asked
  for. Anycast, CDNs and DNS round-robin all answer one name from many places.
* **Same TLS fingerprint is not the same host.** Two servers installed from the
  same distribution package have identical fingerprints on day one.

So the report can say "these two endpoints presented the same certificate"
without ever saying "these two endpoints are the same server", and a reader is
left with the evidence rather than with our guess about it.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Any, Final

from ..models.intelligence import (
    EndpointRef,
    IdentityRelation,
    IdentityRelationship,
    ServerEntity,
)

__all__ = ["entity_id_for", "build_entities", "relate_entities"]

#: A relationship needs at least this many distinct supporting observations
#: before it is worth reporting at all. One shared value is enough for the
#: strong relations; POSSIBLE_RELATION needs corroboration.
_POSSIBLE_RELATION_SIGNALS: Final = 2


def entity_id_for(ip: str, port: int) -> str:
    """A stable identifier for one observed endpoint.

    Derived from the endpoint alone, so it does not depend on which capture
    happened to be processed first or on the order of command-line arguments.
    """
    digest = hashlib.sha256(f"{ip}|{port}".encode()).hexdigest()[:12]
    return f"entity-{digest}"


class _Accumulator:
    """Mutable working state for one endpoint while captures are walked."""

    def __init__(self, endpoint: EndpointRef) -> None:
        self.endpoint = endpoint
        self.session_ids: list[str] = []
        self.capture_ids: list[str] = []
        self.snis: set[str] = set()
        self.certificates: set[str] = set()
        self.public_keys: set[str] = set()
        self.fingerprints: set[str] = set()
        self.configurations: set[str] = set()
        self.protocols: set[str] = set()
        self.first_ns: int | None = None
        self.last_ns: int | None = None
        self.first: datetime | None = None
        self.last: datetime | None = None

    def observe_time(self, timestamp: datetime | None, timestamp_ns: int | None) -> None:
        if timestamp is None or timestamp_ns is None:
            return
        if self.first_ns is None or timestamp_ns < self.first_ns:
            self.first_ns, self.first = timestamp_ns, timestamp
        if self.last_ns is None or timestamp_ns > self.last_ns:
            self.last_ns, self.last = timestamp_ns, timestamp


def build_entities(
    observations: list[dict[str, Any]],
) -> dict[str, ServerEntity]:
    """Group session observations into endpoint entities.

    ``observations`` is a list of plain dicts so this module does not need to
    import the whole analysis surface; the engine assembles them. Each carries
    ``ip``, ``port``, ``session_id``, ``capture_id`` and the observable
    identifiers for that session.

    Output is keyed by ``entity_id`` and every collection inside is sorted, so
    two runs over the same captures in different argument orders produce
    identical entities.
    """
    accumulators: dict[str, _Accumulator] = {}
    for item in observations:
        endpoint = EndpointRef(ip=item["ip"], port=item["port"])
        key = entity_id_for(endpoint.ip, endpoint.port)
        accumulator = accumulators.get(key)
        if accumulator is None:
            accumulator = accumulators[key] = _Accumulator(endpoint)
        accumulator.session_ids.append(item["session_id"])
        accumulator.capture_ids.append(item["capture_id"])
        if item.get("sni"):
            accumulator.snis.add(item["sni"])
        for value in item.get("certificates", ()):
            accumulator.certificates.add(value)
        for value in item.get("public_keys", ()):
            accumulator.public_keys.add(value)
        if item.get("fingerprint_id"):
            accumulator.fingerprints.add(item["fingerprint_id"])
        if item.get("configuration_fingerprint"):
            accumulator.configurations.add(item["configuration_fingerprint"])
        if item.get("protocol"):
            accumulator.protocols.add(item["protocol"])
        accumulator.observe_time(item.get("first_timestamp"), item.get("first_timestamp_ns"))
        accumulator.observe_time(item.get("last_timestamp"), item.get("last_timestamp_ns"))

    entities: dict[str, ServerEntity] = {}
    for key, accumulator in accumulators.items():
        entities[key] = ServerEntity(
            entity_id=key,
            endpoint=accumulator.endpoint,
            session_ids=tuple(sorted(set(accumulator.session_ids))),
            capture_ids=tuple(sorted(set(accumulator.capture_ids))),
            observed_snis=tuple(sorted(accumulator.snis)),
            certificate_fingerprints=tuple(sorted(accumulator.certificates)),
            public_key_fingerprints=tuple(sorted(accumulator.public_keys)),
            fingerprint_ids=tuple(sorted(accumulator.fingerprints)),
            configuration_fingerprints=tuple(sorted(accumulator.configurations)),
            protocols=tuple(sorted(accumulator.protocols)),
            first_observed=accumulator.first,
            last_observed=accumulator.last,
            limitations=(
                "An entity is one observed (ip, port). Sessions from different "
                "source ports are the same endpoint and are counted once.",
                "Whether this endpoint is one machine, a load-balanced pool or a "
                "virtual host is not observable from a capture.",
            ),
        )
    return dict(sorted(entities.items()))


def _shared(
    entities: dict[str, ServerEntity],
    attribute: str,
) -> dict[str, list[str]]:
    """Index entity ids by each value of a multi-valued attribute."""
    index: dict[str, list[str]] = defaultdict(list)
    for entity_id, entity in entities.items():
        for value in getattr(entity, attribute):
            index[value].append(entity_id)
    return {value: sorted(ids) for value, ids in index.items() if len(ids) > 1}


_RELATION_SPECS: Final = (
    (
        "certificate_fingerprints",
        IdentityRelation.SHARED_CERTIFICATE,
        "certificate_sha256",
        (
            "A shared certificate establishes a shared certificate. It does not "
            "establish a shared machine: load-balanced pools and shared hosting "
            "both present one certificate from many servers.",
        ),
    ),
    (
        "public_key_fingerprints",
        IdentityRelation.SHARED_PUBLIC_KEY,
        "certificate_spki_sha256",
        (
            "A shared public key means the same key pair was presented. This is "
            "what a certificate renewal that kept its key looks like; it is also "
            "what a deliberately shared key looks like.",
        ),
    ),
    (
        "observed_snis",
        IdentityRelation.OBSERVED_SNI,
        "server_name_indication",
        (
            "SNI is what the client asked for, not what answered. One name is "
            "routinely served from many addresses by DNS round-robin, anycast or "
            "a CDN.",
        ),
    ),
    (
        "configuration_fingerprints",
        IdentityRelation.CONFIGURATION_MATCH,
        "configuration_fingerprint",
        (
            "Identical observable configuration. Two unrelated servers installed "
            "from the same distribution defaults match here on day one.",
        ),
    ),
)


def relate_entities(entities: dict[str, ServerEntity]) -> dict[str, ServerEntity]:
    """Attach typed relationships without merging anything.

    Each relationship names the exact property that matched and carries the
    limitation that stops it being read as an identity. Where two entities are
    linked by several weak signals at once, an additional
    ``POSSIBLE_RELATION`` is recorded -- explicitly for a human to consider,
    never as a conclusion.
    """
    found: dict[str, list[IdentityRelationship]] = defaultdict(list)
    weak_signals: dict[tuple[str, str], list[str]] = defaultdict(list)

    for attribute, relation, label, limitations in _RELATION_SPECS:
        for value, ids in sorted(_shared(entities, attribute).items()):
            for entity_id in ids:
                for other in ids:
                    if other == entity_id:
                        continue
                    found[entity_id].append(
                        IdentityRelationship(
                            relation=relation,
                            entity_id=other,
                            basis=f"{label}={value}",
                            supporting_session_ids=entities[other].session_ids,
                            supporting_capture_ids=entities[other].capture_ids,
                            limitations=limitations,
                        )
                    )
                    if relation in (
                        IdentityRelation.OBSERVED_SNI,
                        IdentityRelation.CONFIGURATION_MATCH,
                    ):
                        weak_signals[(entity_id, other)].append(relation.value)

    for (entity_id, other), signals in sorted(weak_signals.items()):
        if len(set(signals)) < _POSSIBLE_RELATION_SIGNALS:
            continue
        already_strong = any(
            relationship.entity_id == other
            and relationship.relation
            in (IdentityRelation.SHARED_CERTIFICATE, IdentityRelation.SHARED_PUBLIC_KEY)
            for relationship in found[entity_id]
        )
        if already_strong:
            continue
        found[entity_id].append(
            IdentityRelationship(
                relation=IdentityRelation.POSSIBLE_RELATION,
                entity_id=other,
                basis="corroborating weak signals: " + ", ".join(sorted(set(signals))),
                supporting_session_ids=entities[other].session_ids,
                supporting_capture_ids=entities[other].capture_ids,
                limitations=(
                    "Several weak signals agreeing is still weak evidence. This is "
                    "reported for a human to consider and is not an identity claim.",
                    "No certificate or public key links these endpoints.",
                ),
            )
        )

    return {
        entity_id: entity.model_copy(
            update={
                "relationships": tuple(
                    sorted(
                        found.get(entity_id, ()),
                        key=lambda item: (item.relation.value, item.entity_id, item.basis),
                    )
                )
            }
        )
        for entity_id, entity in entities.items()
    }
