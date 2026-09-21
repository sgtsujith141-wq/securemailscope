"""Port-derived protocol *hints*.

These are hints, never identifications.  A TCP service on port 25 is very
likely SMTP, but nothing in a port number proves it: the only thing actually
observed is the port.  Every hint is therefore emitted as an
``INFERRED`` :class:`~securemailscope.models.evidence.Observation` carrying the
limitation text verbatim, and the value is prefixed to make accidental
promotion to a confirmed fact obvious in any downstream display.

Payload-based confirmation (SMTP/IMAP/POP3 banner and command grammar) is M2
and is deliberately not attempted here.
"""

from __future__ import annotations

from typing import Final

from ..models.evidence import EvidenceStatus, Observation, PacketReference

__all__ = ["EMAIL_SERVICE_PORTS", "SERVICE_PORTS", "hint_for_port", "is_service_port"]

#: Ports whose IANA assignment is an email submission/retrieval protocol.
EMAIL_SERVICE_PORTS: Final[dict[int, str]] = {
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    465: "SMTPS (implicit TLS)",
    587: "SMTP submission",
    993: "IMAPS (implicit TLS)",
    995: "POP3S (implicit TLS)",
    2525: "SMTP (alternate submission)",
}

#: Superset used only for inferring which endpoint is the server.
SERVICE_PORTS: Final[frozenset[int]] = frozenset(EMAIL_SERVICE_PORTS) | frozenset(
    {21, 22, 53, 80, 443, 8080, 8443}
)

_LIMITATIONS: Final[tuple[str, ...]] = (
    "Derived from the TCP port number alone; no application payload was parsed.",
    "A different protocol may be running on this port, and the real protocol may "
    "run on a non-standard port.",
    "This is NOT a confirmed protocol identification. Payload-based confirmation "
    "is not implemented (planned for M2).",
)


#: Which email protocol a conventional port suggests. A hint, never proof.
PORT_PROTOCOL: Final[dict[int, str]] = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    2525: "SMTP",
    110: "POP3",
    995: "POP3",
    143: "IMAP",
    993: "IMAP",
}

#: Ports whose conventional use is TLS from the first byte, with no plaintext
#: phase and therefore no observable application protocol.
IMPLICIT_TLS_PORTS: Final[frozenset[int]] = frozenset({465, 993, 995})


def protocol_for_port(port: int) -> str | None:
    """The protocol a port conventionally carries, or ``None``."""
    return PORT_PROTOCOL.get(port)


def is_service_port(port: int) -> bool:
    return port in SERVICE_PORTS


def hint_for_port(
    port: int,
    *,
    capture_id: str,
    session_id: str,
    packet_ref: PacketReference | None = None,
) -> Observation[str] | None:
    """Return a labelled hint for ``port``, or ``None`` when there is none."""
    name = EMAIL_SERVICE_PORTS.get(port)
    if name is None:
        return None
    return Observation[str](
        value=f"HINT:{name}",
        status=EvidenceStatus.INFERRED,
        capture_id=capture_id,
        session_id=session_id,
        packet_refs=(packet_ref,) if packet_ref else (),
        observed_at=packet_ref.timestamp if packet_ref else None,
        observed_until=packet_ref.timestamp if packet_ref else None,
        basis="SERVER_PORT",
        limitations=_LIMITATIONS,
    )
