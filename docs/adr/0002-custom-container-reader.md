# ADR 0002: Parse pcap/pcapng framing directly; use Scapy for dissection

- **Status:** Accepted
- **Date:** 2026-09-21
- **Milestone:** M1

## Context

Scapy ships `PcapReader` and `PcapNgReader`, which handle both container
formats. Using them is the obvious choice and would have removed roughly 400
lines from this repository.

Three requirements made that a bad trade for this project.

**Truncation must be a diagnostic, not an exception.** A damaged capture is
normal input for a forensic tool. The requirement is to analyse the intact
prefix and report the damage precisely — which record, how many bytes were
expected, how many were present. A library that raises mid-iteration forces the
caller into a broad `except`, which is exactly the "broad exception swallowing"
this project's quality bar forbids.

**Limits must be enforced before allocation.** A record declaring four
gigabytes must be refused *on the header*, before any read is attempted. That
requires control of the read loop.

**Container damage and undissectable packets are different findings.** "This
file is damaged at byte 254" and "packet 7 is not IP" mean different things to
an analyst. Keeping the container layer separate from the dissection layer
keeps the two diagnostics distinct by construction.

A fourth reason emerged during development: Scapy's packet-building machinery
can emit **live ARP and Neighbour Solicitation traffic** when a link-layer
address is unresolved. Keeping Scapy out of the container and link layers
narrows the surface where that can happen. See `SECURITY.md`.

## Decision

Parse pcap and pcapng **framing** directly (`ingestion/pcap_reader.py`,
`ingestion/pcapng_reader.py`). Strip link-layer headers directly
(`ingestion/dissect.py`). Use **Scapy for IP and TCP dissection**, where its
option parsing, extension-header handling and layer model genuinely earn their
place.

The hand-written layers cover:

- All four libpcap magic variants (both endiannesses, microsecond and
  nanosecond timestamps).
- pcapng SHB / IDB / EPB / SPB, multiple sections, per-interface link types and
  `if_tsresol`, with a 64 MiB ceiling on any single block.
- Ethernet with up to three VLAN tags, raw IPv4/IPv6, BSD and OpenBSD loopback,
  Linux cooked v1 and v2.
- An explicit link-type allowlist; anything else is a diagnostic, never a guess.

Deliberately **not** covered, because Scapy does it better: IPv4 options, IPv6
extension header chains, TCP options, and fragment detection.

## Consequences

**Good.**

- Every structural failure produces a typed `WarningCode` with the exact byte
  counts involved, and parsing stops cleanly at that point.
- `max_packet_bytes` is checked against the declared length before the read.
- Nanosecond timestamp resolution is preserved end to end, which
  `tests/test_ingestion.py::test_pcapng_preserves_nanosecond_precision` proves
  by asserting a deliberate 987 ns offset survives.
- Packet numbering is ours, so it is guaranteed stable and 1-based.
- Fixture writers (`testing/writers.py`) and readers are independent
  implementations, so a bug in one does not mask a bug in the other.

**Costs.**

- Roughly 400 lines of container parsing to own and maintain.
- Exotic pcapng features are unsupported: compression, decryption blocks,
  Name Resolution Blocks, custom blocks. They are skipped with an explicit
  `UNSUPPORTED_BLOCK_TYPE` note rather than failing.
- Any future format (ERF, snoop) is work rather than a library upgrade.

## Alternatives rejected

**Use Scapy's readers and catch exceptions.** Produces a coarse "the file is
bad somewhere" result and requires broad exception handling.

**Use `dpkt`.** Lower level and closer to what we need, but adds a dependency
for something already small, and its pcapng support is weaker than its pcap
support.

**Shell out to `editcap` / `capinfos`.** Introduces subprocess invocation with
user-controlled filenames, an external dependency, and version-dependent output
parsing. Rejected on all three counts.

## Related

- [0001-engine-independent-of-web-stack.md](0001-engine-independent-of-web-stack.md)
- [../threat-model.md](../threat-model.md) (T1, T2, T5, T8)
