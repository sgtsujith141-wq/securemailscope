"""Byte-deterministic pcap and pcapng writers.

Written by hand rather than delegated to a library so that regenerating a
fixture produces the *same bytes* every time.  That matters because fixture
manifests record the capture's SHA-256: if the writer embedded a host name, a
library version or a wall-clock timestamp, every checkout would produce a
different hash and the committed manifests would be worthless.

Only what the fixtures need is implemented: one section, one interface, and
Enhanced Packet Blocks with explicit timestamps.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from typing import Final

__all__ = [
    "PCAP_MAGIC_USEC",
    "PCAP_MAGIC_NSEC",
    "write_pcap",
    "write_pcapng",
]

PCAP_MAGIC_USEC: Final = 0xA1B2C3D4
PCAP_MAGIC_NSEC: Final = 0xA1B23C4D

#: (timestamp in epoch nanoseconds, captured bytes, original wire length)
CapturedPacket = tuple[int, bytes, int]


def _normalise(
    packets: Iterable[tuple[int, bytes] | CapturedPacket],
) -> list[CapturedPacket]:
    result: list[CapturedPacket] = []
    for item in packets:
        if len(item) == 2:
            timestamp_ns, data = item
            result.append((timestamp_ns, data, len(data)))
        else:
            timestamp_ns, data, original_length = item
            result.append((timestamp_ns, data, original_length))
    return result


def write_pcap(
    packets: Iterable[tuple[int, bytes] | CapturedPacket],
    *,
    link_type: int = 1,
    snaplen: int = 262144,
    nanosecond: bool = False,
    endian: str = "<",
) -> bytes:
    """Serialise packets into a classic libpcap file.

    ``packets`` entries are ``(timestamp_ns, data)`` or
    ``(timestamp_ns, data, original_wire_length)``; supplying a wire length
    larger than ``len(data)`` produces a snapshot-truncated record.
    """
    magic = PCAP_MAGIC_NSEC if nanosecond else PCAP_MAGIC_USEC
    divisor = 1 if nanosecond else 1000
    out = bytearray()
    out += struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, link_type)
    for timestamp_ns, data, original_length in _normalise(packets):
        seconds, remainder = divmod(timestamp_ns, 1_000_000_000)
        out += struct.pack(
            endian + "IIII", seconds, remainder // divisor, len(data), original_length
        )
        out += data
    return bytes(out)


def _block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    padding = (-len(body)) % 4
    total = 12 + len(body) + padding
    return (
        struct.pack(endian + "II", block_type, total)
        + body
        + b"\x00" * padding
        + struct.pack(endian + "I", total)
    )


def _option(code: int, value: bytes, endian: str = "<") -> bytes:
    return (
        struct.pack(endian + "HH", code, len(value))
        + value
        + b"\x00" * ((-len(value)) % 4)
    )


def write_pcapng(
    packets: Iterable[tuple[int, bytes] | CapturedPacket],
    *,
    link_type: int = 1,
    snaplen: int = 262144,
    tsresol_exponent: int = 9,
    interface_name: str = "synthetic0",
    endian: str = "<",
) -> bytes:
    """Serialise packets into a single-section, single-interface pcapng file.

    ``tsresol_exponent`` is the ``if_tsresol`` value: 6 for microseconds, 9
    for nanoseconds.  Timestamps are supplied in nanoseconds regardless and
    converted to the declared resolution.
    """
    if not 0 <= tsresol_exponent <= 9:
        raise ValueError("tsresol_exponent must be between 0 and 9")
    ticks_per_ns = 10 ** (9 - tsresol_exponent)

    shb_body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_body += _option(0, b"", endian)
    out = bytearray(_block(0x0A0D0D0A, shb_body, endian))

    idb_body = struct.pack(endian + "HHI", link_type, 0, snaplen)
    idb_body += _option(2, interface_name.encode("ascii"), endian)  # if_name
    idb_body += _option(9, bytes([tsresol_exponent]), endian)  # if_tsresol
    idb_body += _option(0, b"", endian)
    out += _block(0x00000001, idb_body, endian)

    for timestamp_ns, data, original_length in _normalise(packets):
        ticks = timestamp_ns // ticks_per_ns
        epb_body = struct.pack(
            endian + "IIIII",
            0,
            (ticks >> 32) & 0xFFFFFFFF,
            ticks & 0xFFFFFFFF,
            len(data),
            original_length,
        )
        epb_body += data + b"\x00" * ((-len(data)) % 4)
        out += _block(0x00000006, epb_body, endian)

    return bytes(out)


def truncate(data: bytes, keep_bytes: int) -> bytes:
    """Return the first ``keep_bytes`` bytes -- used to build damaged fixtures."""
    if keep_bytes < 0 or keep_bytes > len(data):
        raise ValueError("keep_bytes out of range")
    return data[:keep_bytes]


def concat(chunks: Sequence[bytes]) -> bytes:  # pragma: no cover - trivial helper
    return b"".join(chunks)
