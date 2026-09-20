# Test strategy

The point of this test suite is to make it hard for the engine to be *wrong in
a way that looks right*. Coverage is a means; the goal is that a regression in
reconstruction correctness causes a failure rather than a quietly different
number.

## The central rule: expectations are hand-derived

Fixture manifests are **not** recordings of engine output. Every byte count,
offset, gap boundary and packet number in `tests/fixtures/manifests/*.json` was
worked out from the TCP semantics of the scenario and written into
`src/securemailscope/testing/fixtures.py` by hand.

This matters. A suite that snapshots whatever the code produced will pass
forever, including after the code breaks. When the engine and a manifest
disagree, one of them is wrong and a human has to decide which — that has
already happened twice during M1 (see the M0/M1 report).

## Determinism

Generation is byte-deterministic:

- Fixed synthetic timestamps anchored at 2024-01-01T00:00:00Z.
- Explicit MAC addresses, IP IDs, TTLs and window sizes — nothing left to a
  library default that might change between versions.
- pcap and pcapng writers are hand-written (`testing/writers.py`) so no host
  name, library version or wall-clock value is embedded in the container.
- RFC 5737 / RFC 3849 documentation addresses and invented payloads only.

Each manifest records the capture's SHA-256. `tests/conftest.py` regenerates
every capture into a temporary directory at session start and asserts the hash
matches before any other assertion runs. A generator that stops being
deterministic fails loudly instead of silently invalidating every expectation.

`tests/test_cli.py::test_committed_manifests_match_regenerated_ones` further
asserts the committed manifests have not drifted from the generator.

## Captures are never committed

`tests/fixtures/generated/` is gitignored. The **generator** and the
**manifests** are committed. Anyone can reproduce the captures byte for byte
with `make fixtures`, and no capture data — even synthetic — enters git
history. This keeps the habit correct for when real captures are involved.

## Fixture inventory

| Fixture | Scenario | Principally verifies |
|---|---|---|
| A | Complete connection, payload both ways | Baseline reconstruction, handshake, teardown |
| B | Same payload in three ordered segments | Segmentation yields the identical byte stream |
| C | Three segments delivered 1, 3, 2 | Out-of-order reassembly; offset-ordered provenance |
| D | The data frame captured twice, byte-identical | Duplicate detection; bytes not doubled |
| E | Same bytes resent in a new frame (different IP ID) | Retransmission vs duplicate distinction |
| F | Seven bytes in the middle never captured | Gap detection, two runs, no concatenation |
| G | Two independent connections, interleaved | Connection separation, no byte leakage |
| H | Two segments overlap by five bytes, disagreeing | `FIRST_OBSERVED_WINS`, conflict preserved with both digests |
| I1 | Fixture A cut off inside packet 4 | Graceful truncation, partial results, diagnostic |
| I2 | A `.pcap` that is not a capture | Content-based rejection |
| I3 | Valid header, no packets | Zero-packet handling |
| J | Two connections reusing one 5-tuple | Never merged; one flow id, two session ids |
| K | Fixture A as pcapng, `if_tsresol=9` | pcapng support; nanosecond precision preserved |
| L | Complete IPv6 connection | IPv6 dissection and reassembly |
| M | Capture starting midstream, no SYN | `MIDSTREAM`, `INFERRED` roles and base |
| N | pcap declaring link type 105 | Unsupported link type → diagnostic, zero sessions |
| O | Data frame stored with a short snaplen | `NOT_CAPTURED` gap; `ACKED_DATA_NOT_CAPTURED` |

No fixture contains a TLS handshake or a certificate. Inventing one would put
fabricated cryptographic evidence into the suite; real TLS fixtures belong to
M3.

## Test files

| File | Scope |
|---|---|
| `test_formats.py` | Magic-number detection; extension is proved irrelevant |
| `test_seqspace.py` | 32→64-bit projection, wraparound, retransmission anchoring |
| `test_ingestion.py` | Packet numbering, timestamps, capture id, rejection paths, all eight limits |
| `test_reassembly.py` | Manifest-driven reconstruction, literal byte comparison, provenance |
| `test_sessions.py` | Flow normalisation, separation, tuple reuse, role inference |
| `test_report.py` | JSON contract, payload absence, path absence, honest stage status |
| `test_cli.py` | End-to-end subprocess invocation, exit codes, reproducibility |
| `test_passive.py` | No socket, no subprocess, Scapy neighbour resolution blocked |

## What "verified" means here

Assertions are specific, not existential:

- **Payload:** literal `assert data == bytes.fromhex(expected)` against the
  manifest, plus a SHA-256 comparison of each reported run.
- **Provenance:** exact packet-number lists in stream-offset order —
  `[4, 6, 5]` for fixture C, not "segments is non-empty". Duplicate provenance
  is asserted per offset.
- **Gaps:** offset, length, reason, and the packet numbers on both sides.
- **Conflicts:** both packet numbers, both digests, and the policy name.
- **Warnings:** set *equality* against the manifest, so an unexpected new
  diagnostic fails the test rather than slipping through.
- **Timestamps:** the full nanosecond list, compared element by element against
  the manifest.

## Running

```bash
make test               # everything
make test-unit          # excludes CLI subprocess tests
make test-integration   # only the CLI tests
make check              # lint + typecheck + test
```

## Known gaps in the test suite

Stated rather than papered over:

- No property-based or fuzz testing. `hypothesis` over the reassembler and a
  fuzzer over the container readers would both be valuable and are recommended
  follow-ups.
- No performance or large-capture benchmark. Nothing in this repository claims
  a throughput figure, because none has been measured.
- Sequence wraparound is unit-tested in `test_seqspace.py` but no end-to-end
  fixture wraps 2³², since that would require a 4 GiB stream.
- VLAN, Linux cooked and loopback link types are implemented but have no
  dedicated fixture; only Ethernet and raw IP are exercised end to end.
- No test yet asserts behaviour on a capture with multiple pcapng sections or
  multiple interfaces.
