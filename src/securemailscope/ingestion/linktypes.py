"""Link type allowlist.

SecureMailScope dissects only link layers it can decode without guessing.
Anything else is reported as ``UNSUPPORTED_LINK_TYPE`` and its packets are
skipped -- fabricating a session from bytes we cannot interpret would be worse
than reporting nothing.
"""

from __future__ import annotations

from typing import Final

from ..models.capture import LinkType

__all__ = ["DLT_TO_LINK_TYPE", "resolve_link_type"]

#: DLT / LINKTYPE_ values, per https://www.tcpdump.org/linktypes.html
DLT_TO_LINK_TYPE: Final[dict[int, LinkType]] = {
    0: LinkType.NULL,  # LINKTYPE_NULL (BSD loopback, 4-byte AF header)
    1: LinkType.ETHERNET,  # LINKTYPE_ETHERNET
    101: LinkType.RAW_IP,  # LINKTYPE_RAW
    108: LinkType.LOOP,  # LINKTYPE_LOOP (OpenBSD loopback, big-endian AF)
    113: LinkType.LINUX_SLL,  # LINKTYPE_LINUX_SLL
    228: LinkType.RAW_IP,  # LINKTYPE_IPV4
    229: LinkType.RAW_IP,  # LINKTYPE_IPV6
    276: LinkType.LINUX_SLL2,  # LINKTYPE_LINUX_SLL2
}


def resolve_link_type(code: int) -> LinkType:
    return DLT_TO_LINK_TYPE.get(code, LinkType.UNSUPPORTED)
