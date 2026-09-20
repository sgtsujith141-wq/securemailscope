"""Hard guarantee that Scapy never touches the network.

SecureMailScope is a passive tool.  Scapy, however, is primarily a *packet
crafting* library: assembling an ``Ether()`` layer whose destination MAC is
unset makes it emit a live ARP or Neighbour Solicitation to resolve it.  That
is a real observed behaviour, not a hypothetical -- it was hit while building
this module's fixtures.

Importing :mod:`securemailscope` installs the guard below, which replaces
Scapy's neighbour resolver with one that raises.  Any code path that would
have put a packet on the wire fails loudly instead of succeeding quietly.
"""

from __future__ import annotations

import logging
from typing import Any, NoReturn

__all__ = ["PassiveModeViolation", "install_passive_guard", "guard_installed"]

_installed = False


class PassiveModeViolation(RuntimeError):
    """Raised when a code path would have generated live network traffic."""


def _refuse(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise PassiveModeViolation(
        "SecureMailScope is passive: Scapy attempted a live neighbour resolution "
        "(ARP/NDP). Packets must be constructed with explicit link-layer addresses."
    )


def install_passive_guard() -> None:
    """Disable Scapy's live-traffic side effects. Idempotent."""
    global _installed
    if _installed:
        return

    import scapy.layers.inet6

    # ``conf.neighbor`` is populated when scapy.layers.l2 is imported, so the
    # import has to happen before the resolver can be replaced.
    import scapy.layers.l2  # noqa: F401
    from scapy.config import conf

    conf.verb = 0
    # Do not let Scapy open live capture handles.
    conf.use_pcap = False
    # Neighbour resolution is the one dissection-adjacent path that sends.
    if conf.neighbor is not None:
        conf.neighbor.resolve = _refuse  # type: ignore[method-assign]
    else:  # pragma: no cover - scapy always installs a neighbour cache
        raise PassiveModeViolation(
            "Scapy's neighbour cache is unavailable; refusing to run without the passive guard."
        )
    # Scapy's default logger is noisy on malformed input, which is our normal
    # input. Diagnostics are reported structurally instead.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    _installed = True


def guard_installed() -> bool:
    return _installed
