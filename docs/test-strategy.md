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

### M2 protocol fixtures

| Fixture | Scenario | Principally verifies |
|---|---|---|
| P_A | SMTP STARTTLS accepted, command segment retransmitted | Baseline upgrade; retransmission does not double the request |
| P_B | SMTP STARTTLS refused with 454 | Temporary failure distinguished from permanent; plaintext parsing continues |
| P_C | Multiline 220 acceptance | The reply completes only at its final line; boundary measured there |
| P_D | IMAP STARTTLS accepted, CAPABILITY delivered out of order | Tag matching; TCP reordering resolved before the parser sees it |
| P_E | IMAP tagged OK with the **wrong** tag | An unrelated completion never accepts STARTTLS |
| P_F | POP3 STLS accepted after a multiline CAPA | Dot-terminated capability parsing; STLS acceptance |
| P_G | POP3 STLS refused with -ERR | Rejection recorded as an observation, not a verdict |
| P_H | SMTP on port 8025 | CONFIRMED with no port hint at all |
| P_I | POP3 dialogue on port 143 | Payload beats the port; disagreement reported |
| P_J | STARTTLS with no server response | Outcome unknown, never success |
| P_K | Server response missing (TCP gap) then TLS bytes | A hole voids the conclusion even when TLS bytes follow |
| P_L | 220 acceptance and ServerHello in ONE TCP payload | Boundary mid-payload; trailing TLS bytes preserved |
| P_M | AUTH LOGIN with a two-round base64 exchange, no TLS | Continuation counting; credentials never recorded |
| P_N | Fake plaintext `AUTH PLAIN <token>` **after** the boundary | Parsing never resumes; the token never leaks |
| P_O | Port 993, truncated ClientHello | Implicit TLS framing observed; identity stays PORT_HINT |
| P_P | DATA body containing "STARTTLS" and a fake 220 | Message content is never parsed as protocol |
| P_Q | IMAP literal containing a full fake STARTTLS exchange | Literals skipped by declared length |
| P_R | POP3 RETR body containing "STLS" and a fake +OK | Dot-terminated body skipped; dot-stuffing handled |
| P_S | EHLO, its reply and STARTTLS split across segments, CRLF split | Reassembly restores records before the line reader |
| P_T | Capture starting midstream, no greeting | Detection falls to PROBABLE; no capability claimed |

No fixture contains a real TLS handshake or a certificate. The TLS records in
P_A, P_C, P_D, P_F, P_L, P_N, P_O, P_S and P_T are synthetic, structurally
valid record/handshake headers built byte by byte
(`securemailscope.testing.tls_blobs`) so the framing detector has something
genuine to validate. They carry no cryptographic meaning, and nothing in the
suite claims a handshake was analysed.

## Test files

| File | Scope |
|---|---|
| `test_formats.py` | Magic-number detection; extension is proved irrelevant |
| `test_seqspace.py` | 32→64-bit projection, wraparound, retransmission anchoring |
| `test_ingestion.py` | Packet numbering, timestamps, capture id, rejection paths, all eight limits |
| `test_reassembly.py` | Manifest-driven reconstruction, literal byte comparison, provenance |
| `test_sessions.py` | Flow normalisation, separation, tuple reuse, role inference |
| `test_report.py` | JSON contract, payload absence, path absence, honest stage status |
| `test_cli.py` | End-to-end subprocess invocation, exit codes, reproducibility, M2 report shape |
| `test_passive.py` | No socket, no subprocess, Scapy neighbour resolution blocked |
| `test_protocols.py` | Manifest-driven M2: detection, upgrade state, boundaries, events, auth, warnings, credential absence |
| `test_protocol_reader.py` | Line reader bounds and gap safety, redaction filters, TLS record framing |
| `test_protocol_behaviour.py` | Command/response matching, malformed input, limits, the upgrade boundary |
| `test_tshark_crosscheck.py` | Optional cross-validation against an independent dissector |

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

## Credential-absence testing

Fixtures that carry authentication use recognisable dummy values
(`dummy-user@example.invalid`, `NotARealPassword123`, and their base64 forms)
and list them in the manifest's `forbidden_strings`. Two tests then assert
those strings appear nowhere:

* `test_protocols.py::test_no_credential_material_reaches_the_report` checks
  the serialised report, every warning message, every warning `details` blob
  and every event `detail` string.
* `test_cli.py::test_analyze_never_emits_credentials` checks the report file
  plus the CLI's stdout and stderr, because a stray print is as much of a leak
  as a stray field.

`test_protocol_behaviour.py::test_unrecognised_command_token_is_not_echoed`
covers the subtler case: a base64 blob sitting in command position must not be
quoted back as an "unknown verb".

## Optional cross-validation against TShark

`test_tshark_crosscheck.py` compares packet counts, TCP stream counts and
SMTP/IMAP/POP3 dissection against TShark. It is **skipped unless** `tshark` is
on `PATH` *and* `SECUREMAILSCOPE_TSHARK=1` is set, so an ordinary test run has
no external dependency. TShark is invoked strictly offline (`-r` on a local
file, `-n` to disable name resolution).

```bash
SECUREMAILSCOPE_TSHARK=1 make test   # with tshark installed
```

Any deviation found must be recorded in the milestone report rather than
worked around.

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
- The TShark cross-check has not been executed in this environment because
  TShark is not installed here. The tests are written and skip cleanly; they
  have not been observed passing.
- No fixture yet combines a protocol dialogue with an overlapping-segment
  conflict. The reader's ambiguity handling is unit-tested directly
  (`test_bytes_from_an_overlap_conflict_are_flagged_ambiguous`) but not end to
  end from a capture.
- Running three parsers per session is O(3n) in dialogue length. No
  performance measurement has been taken, and none is claimed.
