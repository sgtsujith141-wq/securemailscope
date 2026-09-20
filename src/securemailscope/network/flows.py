"""Flow identity: normalising endpoint pairs without losing direction."""

from __future__ import annotations

import hashlib

from ..models.tcp import Endpoint

__all__ = ["FlowKey", "normalize", "flow_id_for", "session_id_for"]

#: Order-independent identity of a 5-tuple: ((ip, port), (ip, port), transport).
FlowKey = tuple[tuple[str, int], tuple[str, int], str]


def normalize(a: Endpoint, b: Endpoint, transport: str = "TCP") -> FlowKey:
    """Return an order-independent key for the endpoint pair.

    Direction is *not* encoded here on purpose: the key answers "is this the
    same 5-tuple?", while direction is carried separately by each packet.  A
    single key can therefore host several successive connections, which is
    exactly what makes port reuse detectable instead of silently merged.
    """
    left = (a.ip, a.port)
    right = (b.ip, b.port)
    if left <= right:
        return left, right, transport
    return right, left, transport


def flow_id_for(key: FlowKey) -> str:
    left, right, transport = key
    material = f"{transport}|{left[0]}:{left[1]}|{right[0]}:{right[1]}"
    return "flow-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def session_id_for(capture_id: str, flow_id: str, instance: int) -> str:
    """Deterministic session identifier.

    Derived from the capture identity, so re-analysing the same file always
    produces the same session ids and a report can be diffed across runs.
    """
    material = f"{capture_id}|{flow_id}|{instance}"
    return "sess-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
