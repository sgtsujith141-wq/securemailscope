"""Link-layer stripping and IP/TCP dissection.

Two deliberate design points:

* **The link layer is stripped by hand.**  Ethernet, VLAN, loopback and Linux
  cooked headers are fixed-layout and trivial to walk, and doing it here keeps
  Scapy's packet-*building* machinery (which can emit live ARP/NDP, see
  :mod:`securemailscope.scapy_guard`) entirely out of the read path.
* **Payload length comes from the IP header, not from "whatever bytes are
  left".**  Ethernet padding on short frames would otherwise be injected into
  the reconstructed stream, and snapshot truncation would go unnoticed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from ..models.capture import LinkType
from ..models.tcp import AddressFamily
from ..scapy_guard import install_passive_guard
from .frames import RawFrame

install_passive_guard()

from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment  # noqa: E402
from scapy.packet import Packet  # noqa: E402

__all__ = [
    "TCPFlags",
    "ParsedPacket",
    "DissectionOutcome",
    "DissectionResult",
    "dissect",
]

_ETHERTYPE_IPV4: Final = 0x0800
_ETHERTYPE_IPV6: Final = 0x86DD
_VLAN_ETHERTYPES: Final = frozenset({0x8100, 0x88A8, 0x9100, 0x9200})
_MAX_VLAN_TAGS: Final = 3
_IPPROTO_TCP: Final = 6


class TCPFlags:
    FIN: Final = 0x01
    SYN: Final = 0x02
    RST: Final = 0x04
    PSH: Final = 0x08
    ACK: Final = 0x10
    URG: Final = 0x20
    ECE: Final = 0x40
    CWR: Final = 0x80


class DissectionOutcome(StrEnum):
    TCP = "TCP"
    NOT_IP = "NOT_IP"
    NOT_TCP = "NOT_TCP"
    MALFORMED = "MALFORMED"
    IP_FRAGMENT = "IP_FRAGMENT"
    UNSUPPORTED_LINK_TYPE = "UNSUPPORTED_LINK_TYPE"


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    packet_number: int
    timestamp_ns: int
    address_family: AddressFamily
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    #: True when the capture's snapshot length cut this segment's payload
    #: short. The bytes present are still genuine; the missing tail becomes a
    #: reassembly gap rather than silently shortening the stream.
    payload_truncated: bool
    #: Payload length the IP header says this segment carried.
    declared_payload_length: int
    #: BLAKE2b-128 of the whole captured frame. Used only to tell a frame that
    #: was captured twice from a genuine retransmission; never reported.
    frame_digest: bytes

    @property
    def has_flag(self) -> bool:  # pragma: no cover - convenience
        return bool(self.flags)

    def flag(self, mask: int) -> bool:
        return bool(self.flags & mask)

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def sequence_span(self) -> int:
        """Sequence numbers this segment consumes (SYN and FIN each take one)."""
        span = len(self.payload)
        if self.flags & TCPFlags.SYN:
            span += 1
        if self.flags & TCPFlags.FIN:
            span += 1
        return span


@dataclass(frozen=True, slots=True)
class DissectionResult:
    outcome: DissectionOutcome
    packet: ParsedPacket | None = None
    detail: str = ""


def _strip_link_layer(frame: RawFrame) -> tuple[int | None, bytes] | None:
    """Return ``(ethertype_or_None, network_layer_bytes)``.

    ``None`` as the ethertype means "decide from the IP version nibble".
    Returns ``None`` when the header is too short to walk.
    """
    data = frame.data
    link = frame.link_type

    if link is LinkType.ETHERNET:
        if len(data) < 14:
            return None
        offset = 12
        ethertype = struct.unpack("!H", data[offset : offset + 2])[0]
        offset += 2
        tags = 0
        while ethertype in _VLAN_ETHERTYPES and tags < _MAX_VLAN_TAGS:
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
            tags += 1
        return ethertype, data[offset:]

    if link is LinkType.RAW_IP:
        return None, data

    if link in (LinkType.NULL, LinkType.LOOP):
        # 4-byte address-family header; the family's byte order varies by
        # platform, so the IP version nibble that follows is authoritative.
        if len(data) < 4:
            return None
        return None, data[4:]

    if link is LinkType.LINUX_SLL:
        if len(data) < 16:
            return None
        return struct.unpack("!H", data[14:16])[0], data[16:]

    if link is LinkType.LINUX_SLL2:
        if len(data) < 20:
            return None
        return struct.unpack("!H", data[0:2])[0], data[20:]

    return None


def _family_from_nibble(payload: bytes) -> AddressFamily | None:
    if not payload:
        return None
    version = payload[0] >> 4
    if version == 4:
        return AddressFamily.IPV4
    if version == 6:
        return AddressFamily.IPV6
    return None


def _build(
    frame: RawFrame,
    family: AddressFamily,
    ip_layer: Packet,
    tcp: Packet,
    declared_payload_length: int,
    available_payload: bytes,
) -> DissectionResult:
    truncated = len(available_payload) < declared_payload_length
    src = str(ip_layer.src)
    dst = str(ip_layer.dst)
    packet = ParsedPacket(
        packet_number=frame.packet_number,
        timestamp_ns=frame.timestamp_ns,
        address_family=family,
        src_ip=src,
        dst_ip=dst,
        src_port=int(tcp.sport),
        dst_port=int(tcp.dport),
        seq=int(tcp.seq),
        ack=int(tcp.ack),
        flags=int(tcp.flags),
        window=int(tcp.window),
        payload=available_payload,
        payload_truncated=truncated,
        declared_payload_length=declared_payload_length,
        frame_digest=hashlib.blake2b(frame.data, digest_size=16).digest()
        if available_payload
        else b"",
    )
    return DissectionResult(DissectionOutcome.TCP, packet)


def dissect(frame: RawFrame) -> DissectionResult:
    """Turn one captured frame into a :class:`ParsedPacket`, or say why not."""
    if frame.link_type is LinkType.UNSUPPORTED:
        return DissectionResult(
            DissectionOutcome.UNSUPPORTED_LINK_TYPE,
            detail=f"link type {frame.link_type_code}",
        )

    stripped = _strip_link_layer(frame)
    if stripped is None:
        return DissectionResult(
            DissectionOutcome.MALFORMED, detail="link layer header is shorter than required"
        )
    ethertype, ip_bytes = stripped
    if not ip_bytes:
        return DissectionResult(DissectionOutcome.MALFORMED, detail="no bytes after link layer")

    if ethertype is None:
        family = _family_from_nibble(ip_bytes)
        if family is None:
            return DissectionResult(
                DissectionOutcome.NOT_IP, detail=f"IP version nibble {ip_bytes[0] >> 4}"
            )
    elif ethertype == _ETHERTYPE_IPV4:
        family = AddressFamily.IPV4
    elif ethertype == _ETHERTYPE_IPV6:
        family = AddressFamily.IPV6
    else:
        return DissectionResult(DissectionOutcome.NOT_IP, detail=f"ethertype 0x{ethertype:04x}")

    if family is AddressFamily.IPV4:
        return _dissect_ipv4(frame, ip_bytes)
    return _dissect_ipv6(frame, ip_bytes)


def _dissect_ipv4(frame: RawFrame, ip_bytes: bytes) -> DissectionResult:
    if len(ip_bytes) < 20:
        return DissectionResult(DissectionOutcome.MALFORMED, detail="IPv4 header truncated")
    ip = IP(ip_bytes)
    if not isinstance(ip, IP) or int(ip.version) != 4:
        return DissectionResult(DissectionOutcome.MALFORMED, detail="not a valid IPv4 header")
    header_len = int(ip.ihl) * 4
    if header_len < 20 or header_len > len(ip_bytes):
        return DissectionResult(
            DissectionOutcome.MALFORMED, detail=f"IPv4 IHL {ip.ihl} is inconsistent"
        )
    if int(ip.frag) != 0 or (int(ip.flags) & 0x01):
        return DissectionResult(
            DissectionOutcome.IP_FRAGMENT,
            detail=f"IPv4 fragment (offset {int(ip.frag) * 8}, MF={bool(int(ip.flags) & 1)})",
        )
    if int(ip.proto) != _IPPROTO_TCP:
        return DissectionResult(DissectionOutcome.NOT_TCP, detail=f"IP protocol {int(ip.proto)}")

    tcp = ip.getlayer(TCP)
    if tcp is None or not hasattr(tcp, "original"):
        return DissectionResult(
            DissectionOutcome.MALFORMED, detail="TCP header could not be dissected"
        )
    tcp_header_len = int(tcp.dataofs) * 4
    if tcp_header_len < 20:
        return DissectionResult(
            DissectionOutcome.MALFORMED, detail=f"TCP data offset {tcp.dataofs} is below minimum"
        )

    total_length = int(ip.len)
    declared = total_length - header_len - tcp_header_len
    if declared < 0:
        return DissectionResult(
            DissectionOutcome.MALFORMED,
            detail=f"IPv4 total length {total_length} is smaller than its headers",
        )
    tcp_bytes: bytes = bytes(tcp.original)
    available = tcp_bytes[tcp_header_len : tcp_header_len + declared]
    return _build(frame, AddressFamily.IPV4, ip, tcp, declared, available)


def _dissect_ipv6(frame: RawFrame, ip_bytes: bytes) -> DissectionResult:
    if len(ip_bytes) < 40:
        return DissectionResult(DissectionOutcome.MALFORMED, detail="IPv6 header truncated")
    ip6 = IPv6(ip_bytes)
    if not isinstance(ip6, IPv6) or int(ip6.version) != 6:
        return DissectionResult(DissectionOutcome.MALFORMED, detail="not a valid IPv6 header")
    if ip6.getlayer(IPv6ExtHdrFragment) is not None:
        return DissectionResult(DissectionOutcome.IP_FRAGMENT, detail="IPv6 fragment header")

    tcp = ip6.getlayer(TCP)
    if tcp is None or not hasattr(tcp, "original"):
        return DissectionResult(
            DissectionOutcome.NOT_TCP, detail=f"IPv6 next header {int(ip6.nh)}"
        )
    tcp_header_len = int(tcp.dataofs) * 4
    if tcp_header_len < 20:
        return DissectionResult(
            DissectionOutcome.MALFORMED, detail=f"TCP data offset {tcp.dataofs} is below minimum"
        )

    tcp_bytes = bytes(tcp.original)
    # Bytes of extension headers between the fixed IPv6 header and TCP.
    ext_bytes = len(bytes(ip6.original)) - len(tcp_bytes) - 40
    declared = int(ip6.plen) - max(ext_bytes, 0) - tcp_header_len
    if declared < 0:
        return DissectionResult(
            DissectionOutcome.MALFORMED,
            detail=f"IPv6 payload length {int(ip6.plen)} is smaller than its headers",
        )
    available = tcp_bytes[tcp_header_len : tcp_header_len + declared]
    return _build(frame, AddressFamily.IPV6, ip6, tcp, declared, available)
