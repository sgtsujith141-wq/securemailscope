"""Deterministic synthetic packet construction.

Every field that Scapy would otherwise guess is set explicitly -- including
both MAC addresses, because an unset destination MAC makes Scapy perform a
*live* ARP or Neighbour Solicitation (see
:mod:`securemailscope.scapy_guard`).  Explicit fields also make the generated
bytes reproducible, which the fixture manifests depend on.

All addresses are from RFC 5737 / RFC 3849 documentation ranges and all
payloads are invented.  Nothing here was captured from a real system.
"""

from __future__ import annotations

from typing import Final

from ..scapy_guard import install_passive_guard

install_passive_guard()

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402

__all__ = [
    "CLIENT_MAC",
    "SERVER_MAC",
    "CLIENT_IP",
    "SERVER_IP",
    "CLIENT_IPV6",
    "SERVER_IPV6",
    "BASE_TIMESTAMP_NS",
    "ethernet_tcp",
]

CLIENT_MAC: Final = "02:00:00:00:00:01"
SERVER_MAC: Final = "02:00:00:00:00:02"
#: RFC 5737 documentation address blocks.
CLIENT_IP: Final = "192.0.2.10"
SERVER_IP: Final = "198.51.100.25"
#: RFC 3849 documentation prefix.
CLIENT_IPV6: Final = "2001:db8::10"
SERVER_IPV6: Final = "2001:db8:1::25"

#: 2024-01-01T00:00:00Z, chosen so fixture timestamps are obviously synthetic.
BASE_TIMESTAMP_NS: Final = 1_704_067_200_000_000_000


def ethernet_tcp(
    *,
    src_mac: str,
    dst_mac: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int = 0,
    flags: str = "A",
    payload: bytes = b"",
    ip_id: int = 0,
    ttl: int = 64,
    window: int = 64240,
    ipv6: bool = False,
) -> bytes:
    """Build one Ethernet/IP/TCP frame and return its bytes."""
    link = Ether(src=src_mac, dst=dst_mac)
    network: Packet = (
        IPv6(src=src_ip, dst=dst_ip, hlim=ttl)
        if ipv6
        else IP(src=src_ip, dst=dst_ip, id=ip_id, ttl=ttl, flags="DF")
    )
    transport = TCP(
        sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags, window=window
    )
    frame = link / network / transport
    if payload:
        frame = frame / Raw(load=payload)
    return bytes(frame)
