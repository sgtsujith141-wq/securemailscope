"""Evidence timeline (M5).

A timeline of what the captures actually show, anchored to packets.

Three honesty constraints shape it:

**No invented timestamps.** An event whose timing the capture does not
establish gets ``timestamp=None`` rather than a plausible-looking guess. File
modification times are never substituted for capture timestamps: a file copied
between machines carries the copy's mtime, which has nothing to do with when
the traffic happened.

**Packet order is not world chronology.** Within one capture, timestamps come
from one clock and their order is meaningful. *Across* captures taken on
different machines, the clocks are independent and may be skewed by an unknown
amount. The timeline therefore distinguishes capture-local ordering from
globally comparable ordering, and says which it is offering.

**Derived events name their sources.** An event that was computed rather than
observed -- a security finding, a drift event -- carries ``derived_from``
listing the observations behind it, so a reader can always reach the packets.

Equal timestamps are broken deterministically by ``(capture_id, session_id,
event type, packet number)``, so two runs over the same captures emit the same
order. Ties are common: several handshake messages routinely arrive in one
packet and therefore share a timestamp exactly.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final

from ..models.intelligence import TimelineEvent, TimelineEventType

__all__ = ["CLOCK_LIMITATIONS", "build_timeline", "event_id_for"]

CLOCK_LIMITATIONS: Final = (
    "Timestamps are the capture's own, taken by the capturing host's clock. "
    "Within one capture their order is meaningful.",
    "Across captures taken on different hosts the clocks are independent. No "
    "synchronisation is assumed, measured or corrected for, so cross-capture "
    "ordering may not reflect real-world chronology.",
    "A packet's capture timestamp is when the capturing host saw it, not when "
    "the sender sent it. Network and capture-stack delay are not measured.",
    "File modification times are never used. Only timestamps recorded inside "
    "the capture are.",
)

#: Ordering rank for events sharing a timestamp, so a handshake reads in
#: protocol order rather than in whatever order the analysis produced it.
_TYPE_RANK: Final[dict[TimelineEventType, int]] = {
    TimelineEventType.SESSION_FIRST_PACKET: 0,
    TimelineEventType.PROTOCOL_IDENTIFIED: 1,
    TimelineEventType.UPGRADE_ADVERTISED: 2,
    TimelineEventType.UPGRADE_REQUESTED: 3,
    TimelineEventType.UPGRADE_ACCEPTED: 4,
    TimelineEventType.UPGRADE_REJECTED: 4,
    TimelineEventType.AUTHENTICATION_OBSERVED: 5,
    TimelineEventType.CLIENT_HELLO: 6,
    TimelineEventType.SERVER_HELLO: 7,
    TimelineEventType.CRYPTO_PARAMETERS_SELECTED: 8,
    TimelineEventType.CERTIFICATE_OBSERVED: 9,
    TimelineEventType.TLS_ALERT: 10,
    TimelineEventType.SECURITY_FINDING: 11,
    TimelineEventType.CONFIGURATION_DRIFT: 12,
}


def event_id_for(
    capture_id: str, session_id: str | None, event_type: TimelineEventType, anchor: str
) -> str:
    """A stable identifier derived from what the event is, not when it was emitted."""
    material = f"{capture_id}|{session_id or ''}|{event_type.value}|{anchor}"
    return "evt-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _sort_key(item: dict[str, Any]) -> tuple:
    """Deterministic total order.

    Events with no timestamp sort last rather than at the epoch: placing an
    event of unknown time at 1970 would be an invented chronology.
    """
    timestamp_ns = item.get("timestamp_ns")
    packets = item.get("packet_refs", ())
    first_packet = packets[0].packet_number if packets else 0
    return (
        timestamp_ns is None,
        timestamp_ns if timestamp_ns is not None else 0,
        item["capture_id"],
        item.get("session_id") or "",
        _TYPE_RANK.get(item["event_type"], 99),
        first_packet,
        item["description"],
    )


def build_timeline(
    raw_events: list[dict[str, Any]], *, max_events: int
) -> tuple[list[TimelineEvent], bool]:
    """Order raw events deterministically and assign dense order indices.

    Returns the events and whether ``max_events`` truncated them. Truncation is
    reported rather than silently applied, because a timeline that stops early
    without saying so reads as a complete account of what happened.
    """
    ordered = sorted(raw_events, key=_sort_key)
    truncated = len(ordered) > max_events
    kept = ordered[:max_events]
    return [
        TimelineEvent(
            event_id=event_id_for(
                item["capture_id"],
                item.get("session_id"),
                item["event_type"],
                item.get("anchor", item["description"]),
            ),
            event_type=item["event_type"],
            timestamp=item.get("timestamp"),
            timestamp_ns=item.get("timestamp_ns"),
            capture_id=item["capture_id"],
            session_id=item.get("session_id"),
            entity_id=item.get("entity_id"),
            description=item["description"],
            packet_refs=tuple(item.get("packet_refs", ())),
            stream_offsets=tuple(item.get("stream_offsets", ())),
            evidence_status=item.get("evidence_status", "OBSERVED"),
            derived_from=tuple(item.get("derived_from", ())),
            order_index=index,
        )
        for index, item in enumerate(kept)
    ], truncated
