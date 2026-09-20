# M0 + M1 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Implementation commit:** `1ac2e979a76e164d3f2f1e19a0efdbcb85f37ded`
- **Remote:** `https://github.com/sgtsujith141-wq/securemailscope` (**private**)
- **Python:** 3.12.14

---

## 1. Executive summary

M0 and the M1 vertical slice are complete and verified. The repository contains
a working, tested forensic engine that takes a PCAP or PCAPNG file and produces
a provenanced TCP session inventory as JSON, plus the architectural
documentation that constrains everything built on top of it.

**What works today.** A capture is validated, hashed, format-detected from its
contents, streamed under eight hard resource limits, dissected, and
reconstructed into bidirectional TCP sessions. The reconstruction handles
in-order, out-of-order, segmented, duplicated, retransmitted, missing,
overlapping and *conflicting* data, and distinguishes connections that reuse
the same 5-tuple. Every reconstructed byte range names the packet that carried
it. Every gap is explicit and its contents stay `UNKNOWN`.

**What deliberately does not exist.** No SMTP, IMAP or POP3 parsing. No
STARTTLS detection. No TLS analysis. No certificate handling. No scoring, no
correlation, no ML, no backend, no UI. Five packages exist as documented
placeholders containing only a docstring stating `NOT IMPLEMENTED` and the
milestone that owns them. **The engine emits no TLS or certificate finding of
any kind**, and every report embeds a `stage_status` block so a reader can tell
"not found" from "not looked for".

**Verification.** 168 tests pass. `ruff` and `mypy` are clean over 41 source
files. All commands and their real output are recorded in section 8.

M2 was not started.

---

## 2. Files created

88 files, 10,384 lines, all created in this milestone (the repository was
empty).

### Repository foundation
`README.md`, `SECURITY.md`, `.gitignore`, `.env.example`, `pyproject.toml`,
`Makefile`, `scripts/generate_fixtures.py`, `scripts/check_staged.sh`,
`backend/README.md`, `frontend/README.md`, `submission/README.md`

### M0 documentation
`docs/architecture.md`, `docs/evidence-model.md`, `docs/threat-model.md`,
`docs/limitations.md`, `docs/test-strategy.md`, `docs/requirements-matrix.md`,
`docs/adr/README.md`, `docs/adr/0001-engine-independent-of-web-stack.md`,
`docs/adr/0002-custom-container-reader.md`

### Engine (`src/securemailscope/`)

| Module | Lines | Purpose |
|---|---|---|
| `models/evidence.py` | 195 | `EvidenceStatus`, `PacketReference`, `Observation`, `AnalysisWarning`, `WarningCode` |
| `models/capture.py` | 92 | `CaptureMetadata`, `InterfaceInfo`, `LinkType`, `CaptureFormat` |
| `models/tcp.py` | 320 | `TCPFlow`, `TCPSession`, `ReassembledSegment`, `ReassemblyGap`, `OverlapConflict`, `ByteRun`, `DirectionalStream` |
| `models/analysis.py` | 128 | `AnalysisResult`, `SessionInventory`, `AnalysisLimits`, `ToolInfo`, stage status |
| `config.py` | 118 | `AnalysisConfig` — eight limits, env overrides, validation |
| `errors.py` | 46 | Typed exception hierarchy |
| `diagnostics.py` | 96 | `WarningSink` with per-code emission cap |
| `scapy_guard.py` | 63 | Blocks Scapy's live neighbour resolution |
| `ingestion/formats.py` | 80 | Magic-number format detection |
| `ingestion/frames.py` | 38 | `RawFrame` container record |
| `ingestion/linktypes.py` | 37 | Link-type allowlist |
| `ingestion/pcap_reader.py` | 158 | Streaming libpcap reader, all four magic variants |
| `ingestion/pcapng_reader.py` | 330 | Streaming pcapng reader, SHB/IDB/EPB/SPB |
| `ingestion/reader.py` | 160 | Validation, SHA-256 identity, bounded iteration |
| `ingestion/dissect.py` | 290 | Manual link-layer stripping; Scapy IP/TCP dissection |
| `network/seqspace.py` | 78 | 32→64-bit sequence projection with wraparound |
| `network/budget.py` | 38 | Non-refundable byte allowances |
| `network/flows.py` | 52 | 5-tuple normalisation, flow and session ids |
| `network/reassembly.py` | 540 | Interval store, overlap policy, gaps, provenance |
| `network/sessions.py` | 400 | Connection lifecycle, roles, tuple reuse, limits |
| `protocols/hints.py` | 72 | Port-derived hints, always `INFERRED` |
| `reporting/json_report.py` | 72 | Payload-free deterministic serialisation |
| `pipeline.py` | 265 | Orchestration; `analyze_capture`, `analyze_capture_with_payloads` |
| `cli.py` | 250 | `analyze`, `fixtures`, `status` |
| `testing/writers.py` | 145 | Byte-deterministic pcap/pcapng writers |
| `testing/packets.py` | 90 | Deterministic synthetic frame construction |
| `testing/manifest.py` | 105 | Expectation record types |
| `testing/fixtures.py` | 880 | 17 fixtures with hand-derived expectations |
| `tls/`, `certificates/`, `assessment/`, `intelligence/`, `ml/` | 5 × ~12 | Docstring-only placeholders stating `NOT IMPLEMENTED` |

### Tests
`tests/conftest.py`, `test_formats.py`, `test_seqspace.py`, `test_ingestion.py`,
`test_reassembly.py`, `test_sessions.py`, `test_report.py`, `test_cli.py`,
`test_passive.py`, plus 17 committed manifests under
`tests/fixtures/manifests/`.

No files outside this project directory were created or modified.

---

## 3. Architectural decisions

### 3.1 The engine is independent of the web stack and of any LLM (ADR 0001)

Two runtime dependencies: `scapy` and `pydantic`. `fastapi`, `cryptography` and
`scikit-learn` are declared as optional extras and are neither installed nor
imported. `analyze_capture(path, config)` is a pure function. The CLI is the
reference interface. No result is produced, validated or explained by a
language model.

The reasoning is in the ADR: building the API first reliably produces a
convincing dashboard on top of analysis nobody can verify, and an LLM cannot
cite a packet number it did not compute.

### 3.2 Container framing is parsed directly; Scapy dissects IP/TCP (ADR 0002)

pcap and pcapng framing is hand-written so that truncation becomes a typed
diagnostic rather than an exception, so `max_packet_bytes` can be checked
against a declared length *before* any read, and so container damage stays
distinguishable from an undissectable packet. Scapy handles IP and TCP, where
its option and extension-header parsing earn their place.

### 3.3 Bytes are keyed on extended sequence numbers, rebased at finalisation

The interval store is keyed on 64-bit extended sequence numbers; stream offsets
are computed once, at the end. This is what makes a midstream capture correct
when its first observed segment happens to be out of order — anchoring on that
segment would push the genuinely earlier one to a negative offset.

### 3.4 One interval per contributing packet

Overlapping segments are clipped and only their novel ranges are stored, each
still attributed to its own packet. Intervals are never merged in storage, only
when computing reported runs. This is what will let an M3 TLS finding name the
exact frame its evidence came from.

### 3.5 Overlap policy `FIRST_OBSERVED_WINS`, with the conflict preserved

Overlapping-segment disagreement is a deliberate IDS-evasion primitive, so the
ambiguity is the evidence. The first observation stays in the stream; the
disagreement is recorded with both SHA-256 digests and both packet numbers, the
session drops to `PARTIAL`, and a note says the reconstruction is one possible
interpretation. Only digests are stored, never the competing bytes.

### 3.6 Payload bytes never reach a model

`AnalysisResult` carries counts, offsets, digests and packet references.
Reconstructed bytes live only in the reassembler and are handed out explicitly
via `analyze_capture_with_payloads`. Serialising a report therefore *cannot*
emit application data — this is a structural property, not a filter.

### 3.7 A hard passive-mode guard around Scapy

Scapy is a packet *crafting* library first. Building an `Ether()` layer with an
unresolved destination MAC makes it emit a **live ARP or Neighbour
Solicitation**. This was hit during development of this project's own fixture
generator, not hypothesised. Importing `securemailscope` replaces Scapy's
neighbour resolver with one that raises, and the read path strips link-layer
headers by hand so the crafting machinery never runs during analysis.

### 3.8 Fixture expectations are hand-derived, not recorded

Every byte count, offset, gap boundary and packet number in the manifests was
worked out from TCP semantics and written by hand. A suite that snapshots
engine output passes forever, including after the engine breaks. This
distinction did real work twice during M1 — see section 10.4.

---

## 4. Implemented functionality

| Area | Detail |
|---|---|
| **PCAP** | All four magic variants (both endiannesses, µs and ns resolution) |
| **PCAPNG** | SHB, IDB, EPB, SPB; multiple sections; per-interface `if_tsresol`; 64 MiB block ceiling |
| **Format detection** | Magic bytes only; extension never consulted, proven by test |
| **Input validation** | Missing / directory / empty / oversized / non-capture each raise a distinct typed error |
| **Streaming** | One packet record resident at a time, independent of file size |
| **Capture identity** | `capture_id = "sha256:" + sha256(original file bytes)` |
| **Packet numbering** | 1-based capture order, matches Wireshark frame numbers |
| **Timestamps** | Nanosecond precision preserved; `datetime` is timezone-aware UTC |
| **Link layers** | Ethernet (≤3 VLAN tags), raw IPv4/IPv6, BSD/OpenBSD loopback, Linux cooked v1/v2 |
| **Unsupported link types** | Explicit diagnostic, packets skipped, zero fabricated sessions |
| **Dissection** | IPv4/IPv6 + TCP; payload length from the IP header, so Ethernet padding never enters the stream and snapshot truncation is detected |
| **Flow identity** | Order-independent 5-tuple normalisation with direction preserved |
| **Tuple reuse** | Successive connections share a `flow_id`, get distinct `session_id`s, never merged |
| **Roles** | `OBSERVED` from SYN/SYN-ACK; otherwise `INFERRED` from a service port or the first sender, with the basis recorded |
| **Reassembly** | In-order, out-of-order, segmentation, duplicates, retransmissions, gaps, overlaps, conflicts |
| **SYN/FIN sequence consumption** | Handled; stream offset 0 is ISN+1 |
| **Sequence wraparound** | 64-bit projection, exact within 2³¹ of the high-water mark |
| **Gaps** | Three reasons (`MISSING_SEGMENT`, `NOT_CAPTURED`, `LIMIT_EXCEEDED`), boundary packets recorded, contents `UNKNOWN` |
| **Completeness** | `COMPLETE` / `PARTIAL` / `MIDSTREAM` / `TRUNCATED` plus a note per contributing reason |
| **Limits** | Eight hard ceilings; each produces a diagnostic and marks the object truncated |
| **Diagnostics** | 30 stable warning codes, per-code emission cap with an explicit suppression record |
| **Evidence model** | Four statuses; `INFERRED` requires a basis and limitations |
| **Reporting** | Deterministic JSON, no payload, no filesystem paths, embedded stage status |
| **CLI** | `analyze`, `fixtures`, `status`; limit overrides; exit codes 0/1/2 |
| **Passive guarantee** | No socket, no subprocess, no telemetry, ARP/NDP blocked — all test-enforced |

---

## 5. Partial functionality

| Item | What exists | What is missing |
|---|---|---|
| **Protocol hints** | Port-derived hints for 8 email service ports, `INFERRED`, `HINT:`-prefixed, with three explicit limitations | No payload inspection. This is **not** protocol detection and is not claimed to be. (M2) |
| **Encapsulations** | VLAN, Linux cooked v1/v2 and BSD/OpenBSD loopback are implemented | No dedicated fixture; only Ethernet and IPv4/IPv6 are exercised end to end |
| **Forensic reporting** | Machine-readable JSON with full provenance | No narrative or human-facing forensic report (M4) |
| **Dependency pinning** | Exact versions in `pyproject.toml` | No hash-pinned lock file |

---

## 6. Unimplemented requirements

Tracked in full in [../requirements-matrix.md](../requirements-matrix.md):
**74 IMPLEMENTED, 3 PARTIAL, 23 NOT IMPLEMENTED** across 100 requirements.

Not implemented, and not claimed anywhere:

- SMTP, IMAP and POP3 identification or parsing (M2)
- STARTTLS / STLS detection; implicit TLS detection (M2–M3)
- TLS record framing, handshake reconstruction, cipher/version/extension extraction (M3)
- Certificate extraction and assessment (M3–M4)
- Security findings, posture scoring, explainability (M4)
- Cross-session evidence correlation (M5)
- ML-assisted analysis (M6)
- FastAPI backend, SQLite persistence (M7)
- React/TypeScript/Vite frontend (M8)
- IP fragment reassembly (detected and reported, not reassembled)
- Per-OS reassembly policy emulation
- TCP option interpretation (SACK, window scaling, timestamps)
- TCP/IP checksum validation
- Tunnel decapsulation (GRE, VXLAN, IP-in-IP, IPsec, PPPoE)
- Performance benchmarking — **no throughput figure is claimed anywhere in this repository because none has been measured**

---

## 7. Fixture inventory

17 deterministic synthetic fixtures. Captures are gitignored; the generator and
the hand-derived manifests are committed, so captures are reproducible byte for
byte without entering git history.

| Fixture | File | Bytes | SHA-256 (prefix) | Scenario |
|---|---|---|---|---|
| A | `a_complete_connection.pcap` | 839 | `acc9ebe5c4fb41f9` | Complete connection, payload both ways |
| B | `b_segmented_payload.pcap` | 979 | `99a59ed700178342` | Same payload in three ordered segments |
| C | `c_out_of_order.pcap` | 815 | `124aca0d6366f9d7` | Segments delivered 1, 3, 2 |
| D | `d_duplicate_segment.pcap` | 766 | `79e643d482b8ee85` | Data frame captured twice, byte-identical |
| E | `e_retransmission.pcap` | 766 | `e395656939f37d50` | Same bytes resent in a new frame |
| F | `f_missing_segment.pcap` | 738 | `52c425c72198c12a` | 7 bytes mid-stream never captured |
| G | `g_two_connections.pcap` | 1311 | `04a8304d3cd7ffe9` | Two independent connections, interleaved |
| H | `h_overlap_conflict.pcap` | 744 | `3a13647a2dece013` | 5-byte overlap with conflicting contents |
| I1 | `i1_truncated_capture.pcap` | 254 | `252dac5f8f6f9512` | Fixture A cut off inside packet 4 |
| I2 | `i2_not_a_capture.pcap` | 83 | `aafe01d591e8e1b0` | `.pcap` extension, not a capture |
| I3 | `i3_header_only.pcap` | 24 | `704e5e5b3234433c` | Valid header, zero packets |
| J | `j_tuple_reuse.pcap` | 1299 | `5cac8844e8fafa51` | Two connections reusing one 5-tuple |
| K | `k_pcapng_nanosecond.pcapng` | 1092 | `767afe4cf83f5fad` | Fixture A as pcapng, `if_tsresol=9` |
| L | `l_ipv6_connection.pcap` | 855 | `1819b513e6d2c531` | Complete IPv6 connection |
| M | `m_midstream.pcap` | 349 | `822ec887c490eb39` | Capture starting midstream, no SYN |
| N | `n_unsupported_link_type.pcap` | 80 | `035bf7e3a38fdaac` | Link type 105 (IEEE 802.11) |
| O | `o_snapshot_truncated.pcap` | 664 | `f59099d09444cb84` | Frame stored with a short snaplen |

Each manifest records: generation method, capture SHA-256, file size, expected
packet count, the full expected nanosecond timestamp list, expected sessions
(endpoints, completeness, handshake, termination, role status and basis,
protocol hint, first/last packet), and per direction the expected byte count,
base sequence, base status, runs with hex content, gaps with boundary packet
numbers, conflicts with both hex contents, segment packet numbers in
stream-offset order, duplicate provenance, and retransmission/duplicate/
out-of-order counts.

**No fixture contains a TLS handshake or a certificate.** Inventing one would
put fabricated cryptographic evidence into the test suite; real TLS fixtures
belong to M3.

All addresses are RFC 5737 / RFC 3849 documentation ranges; all payloads are
invented. Nothing was captured from a real system.

---

## 8. Test commands and actual results

Every command below was executed; the output is verbatim.

### 8.1 Dependency installation

```
$ .venv/bin/python -m pip install -e ".[dev]"
    Found existing installation: securemailscope 0.1.0
    Uninstalling securemailscope-0.1.0:
      Successfully uninstalled securemailscope-0.1.0
Successfully installed securemailscope-0.1.0
```

### 8.2 Package import verification

```
$ .venv/bin/python -c "import securemailscope; print(securemailscope.__version__)"
0.1.0
passive guard installed: True
```

### 8.3 Lint

```
$ .venv/bin/ruff check src tests scripts
All checks passed!
```

### 8.4 Type check

```
$ .venv/bin/mypy
Success: no issues found in 41 source files
```

### 8.5 Fixture regeneration

```
$ .venv/bin/python scripts/generate_fixtures.py
A_complete_connection       839 B  sha256:acc9ebe5c4fb41f9861ecb6a70dea1f556a253923899b5f2f1d6b37c4c939f0b
... (17 fixtures)
17 fixtures -> tests/fixtures/generated
17 manifests -> tests/fixtures/manifests
```

### 8.6 Full test suite

```
$ .venv/bin/python -m pytest -q
........................................................................ [ 42%]
........................................................................ [ 85%]
........................                                                 [100%]
168 passed in 13.54s
```

### 8.7 Unit tests only

```
$ .venv/bin/python -m pytest -q -m "not integration"
160 passed, 8 deselected in 1.71s
```

### 8.8 Integration tests only

```
$ .venv/bin/python -m pytest -q -m integration
8 passed, 160 deselected in 14.94s
```

**168 passed, 0 failed, 0 skipped, 0 xfailed.** No test is disabled, weakened
or skipped.

Breakdown by file:

| File | Tests | Covers |
|---|---|---|
| `test_formats.py` | 13 | Magic-number detection; extension irrelevance |
| `test_seqspace.py` | 10 | Projection, wraparound, retransmission anchoring |
| `test_ingestion.py` | 66 | Numbering, timestamps, capture id, rejections, all 8 limits |
| `test_reassembly.py` | 47 | Manifest-driven reconstruction, byte equality, provenance |
| `test_sessions.py` | 10 | Normalisation, separation, tuple reuse, role inference |
| `test_report.py` | 8 | JSON contract, payload absence, path absence, stage status |
| `test_cli.py` | 8 | End-to-end subprocess, exit codes, reproducibility |
| `test_passive.py` | 6 | No socket, no subprocess, ARP/NDP blocked |

---

## 9. Genuine CLI invocation and representative output

```
$ securemailscope analyze tests/fixtures/generated/a_complete_connection.pcap \
    --output out/a_complete_connection.json

report       : /Volumes/Volume/Projects/securemailscope/out/a_complete_connection.json
capture      : a_complete_connection.pcap
capture id   : sha256:acc9ebe5c4fb41f9861ecb6a70dea1f556a253923899b5f2f1d6b37c4c939f0b
format       : PCAP (little-endian)
packets      : 11 (11 TCP, 0 non-IP, 0 non-TCP, 0 malformed)
time range   : 2024-01-01T00:00:00+00:00 .. 2024-01-01T00:00:00.010000+00:00
sessions     : 1 (complete 1, partial 0, midstream 0, truncated 0)
reconstructed: 45 bytes, 0 gap(s), 0 overlap conflict(s)
  sess-3b04cd6af955ed43  192.0.2.10:49152 -> 198.51.100.25:25  COMPLETE  c2s=21B s2c=24B  [HINT:SMTP]
```

Report excerpt (analysis timestamps elided; everything else verbatim):

```json
{
  "tool": {
    "name": "securemailscope",
    "version": "0.1.0",
    "report_schema_version": "1.0.0",
    "passive_only": true
  },
  "stage_status": {
    "CAPTURE_INGESTION": "IMPLEMENTED",
    "TCP_REASSEMBLY": "IMPLEMENTED",
    "PROTOCOL_HINTS": "PARTIAL",
    "EMAIL_PROTOCOL_PARSING": "NOT_IMPLEMENTED",
    "TLS_ANALYSIS": "NOT_IMPLEMENTED",
    "CERTIFICATE_ASSESSMENT": "NOT_IMPLEMENTED",
    "RISK_ASSESSMENT": "NOT_IMPLEMENTED",
    "ML_ANALYSIS": "NOT_IMPLEMENTED"
  },
  "capture": {
    "capture_id": "sha256:acc9ebe5c4fb41f9861ecb6a70dea1f556a253923899b5f2f1d6b37c4c939f0b",
    "source_name": "a_complete_connection.pcap",
    "file_format": "PCAP",
    "byte_order": "little",
    "file_size_bytes": 839,
    "interfaces": [
      {"interface_id": 0, "link_type_code": 1, "link_type": "ETHERNET",
       "snap_length": 262144, "timestamp_resolution_ns": 1000}
    ],
    "packet_count": 11, "tcp_packet_count": 11,
    "non_ip_packet_count": 0, "non_tcp_packet_count": 0,
    "unsupported_link_packet_count": 0, "malformed_packet_count": 0,
    "first_packet_timestamp": "2024-01-01T00:00:00Z",
    "last_packet_timestamp": "2024-01-01T00:00:00.010000Z",
    "first_packet_timestamp_ns": 1704067200000000000,
    "last_packet_timestamp_ns": 1704067200010000000,
    "truncated": false,
    "warnings": []
  },
  "inventory": {
    "session_count": 1, "complete_session_count": 1,
    "midstream_session_count": 0, "partial_session_count": 0,
    "truncated_session_count": 0, "total_bytes_reconstructed": 45,
    "total_gap_count": 0, "total_overlap_conflict_count": 0,
    "tuple_reuse_count": 0
  },
  "sessions": [
    {
      "session_id": "sess-3b04cd6af955ed43",
      "flow": {
        "flow_id": "flow-bdb161d7eb6fb187",
        "transport": "TCP", "address_family": "IPv4",
        "client": {"ip": "192.0.2.10", "port": 49152},
        "server": {"ip": "198.51.100.25", "port": 25},
        "role_status": "OBSERVED", "role_basis": "TCP_SYN"
      },
      "flow_instance": 1,
      "packet_count": 11,
      "handshake": {
        "syn_observed": true, "syn_ack_observed": true, "ack_observed": true,
        "client_isn": 1000, "server_isn": 5000,
        "syn_packet": {"packet_number": 1, "timestamp": "2024-01-01T00:00:00Z",
                       "timestamp_ns": 1704067200000000000}
      },
      "termination": {
        "reason": "FIN_BOTH_DIRECTIONS",
        "client_fin": {"packet_number": 8, "timestamp_ns": 1704067200007000000},
        "server_fin": {"packet_number": 10, "timestamp_ns": 1704067200009000000}
      },
      "completeness": "COMPLETE",
      "completeness_notes": [],
      "client_to_server": {
        "direction": "CLIENT_TO_SERVER",
        "packet_count": 6, "payload_packet_count": 1,
        "stream_base_sequence": 1001,
        "base_status": "OBSERVED", "base_basis": "TCP_SYN",
        "bytes_reconstructed": 21, "highest_offset_observed": 21,
        "runs": [
          {"stream_offset": 0, "length": 21,
           "sha256": "cc149c6b71d199f11de74232a2158f09c1779dbde4a72d0b57275b07cdcb601a",
           "first_packet": {"packet_number": 4, "timestamp_ns": 1704067200003000000},
           "last_packet":  {"packet_number": 4, "timestamp_ns": 1704067200003000000}}
        ],
        "segments": [
          {"stream_offset": 0, "length": 21, "sequence_number": 1001,
           "source": {"packet_number": 4, "timestamp_ns": 1704067200003000000},
           "duplicates": [], "disposition": "ACCEPTED"}
        ],
        "gaps": [], "overlap_conflicts": [],
        "retransmission_count": 0, "duplicate_count": 0, "out_of_order_count": 0,
        "truncated_by_limit": false, "fin_observed": true, "rst_observed": false,
        "highest_ack_observed": 23
      },
      "protocol_hint": {
        "value": "HINT:SMTP",
        "status": "INFERRED",
        "basis": "SERVER_PORT",
        "limitations": [
          "Derived from the TCP port number alone; no application payload was parsed.",
          "A different protocol may be running on this port, and the real protocol may run on a non-standard port.",
          "This is NOT a confirmed protocol identification. Payload-based confirmation is not implemented (planned for M2)."
        ]
      },
      "warnings": []
    }
  ],
  "warnings": []
}
```

### A capture with a gap (fixture F)

```
$ securemailscope analyze tests/fixtures/generated/f_missing_segment.pcap -o out/f_missing_segment.json
sessions     : 1 (complete 0, partial 1, midstream 0, truncated 0)
reconstructed: 14 bytes, 1 gap(s), 0 overlap conflict(s)
  sess-dc32300f1ab45460  192.0.2.10:49152 -> 198.51.100.25:25  PARTIAL *  c2s=14B s2c=0B  [HINT:SMTP]
warnings     : 1 (see the JSON report)
```

The 21-byte client payload is reported as **two runs with a hole between
them**, not as 14 concatenated bytes:

```json
"runs": [
  {"stream_offset": 0,  "length": 5, "sha256": "df8ae0be0073bbb9..."},
  {"stream_offset": 12, "length": 9, "sha256": "b6aba40a7ba89b25..."}
],
"gaps": [
  {"stream_offset": 5, "length": 7, "reason": "MISSING_SEGMENT",
   "content_status": "UNKNOWN",
   "preceding_packet": {"packet_number": 4, "timestamp_ns": 1704067200003000000},
   "following_packet": {"packet_number": 5, "timestamp_ns": 1704067200004000000}}
]
```

### Rejection of a non-capture

```
$ securemailscope analyze tests/fixtures/generated/i2_not_a_capture.pcap ; echo "exit=$?"
securemailscope: input error: i2_not_a_capture.pcap is not a libpcap or pcapng capture (file contents did not match any supported magic number)
exit=2
```

---

## 10. Known technical limitations

Full treatment in [../limitations.md](../limitations.md). The ones that matter
most for reading an M1 result:

**10.1 Overlapping conflicts have no single correct answer.** Different
operating systems resolve overlapping segments differently — that is why the
technique exists. The engine applies `FIRST_OBSERVED_WINS` and reports every
conflict with both digests. The reconstructed stream in that case is *one
possible interpretation*, not necessarily what the real endpoint saw.

**10.2 Duplicate vs retransmission is an inference.** A frame captured twice
and a genuine retransmission can be byte-identical. Classification uses full
frame identity; where the two are genuinely indistinguishable passively, the
label may be wrong. Byte counts are unaffected either way.

**10.3 Midstream role assignment can be wrong.** Without a SYN, client and
server are inferred from a recognised service port, falling back to whoever
sent the first packet. Both heuristics can be wrong. The session is labelled
`MIDSTREAM`, `role_status` is `INFERRED`, and `role_basis` names the heuristic.

**10.4 A refused connection stays refused.** When `max_concurrent_sessions` is
reached, the refused flow key is remembered and its later packets are refused
too. This was a deliberate change made during M1: the original behaviour
admitted such a connection once capacity freed, producing a session that looked
midstream because of *our limit* rather than because of the capture. An
artificial `MIDSTREAM` label is worse than an honest refusal.

**10.5 Sequence wraparound is unit-tested only.** The projection is exact
within 2³¹ of the high-water mark. No end-to-end fixture wraps 2³², since that
needs a 4 GiB stream.

**10.6 No IP fragment reassembly.** Fragments are detected and reported as
`IP_FRAGMENT_NOT_REASSEMBLED`; their data is absent from the streams.

**10.7 No checksum validation.** Hardware offload makes checksums unreliable on
endpoint-taken captures anyway.

**10.8 Scapy's dissectors are not hardened.** IP and TCP dissection relies on
Scapy, which is Python code not written against adversarial input. Analyse
captures of unknown provenance in an isolated environment.

**10.9 No performance data.** No benchmark has been run and no throughput
figure is claimed anywhere in this repository.

**10.10 VLAN, SLL and loopback link types are untested end to end.**
Implemented, but only Ethernet and raw IPv4/IPv6 have fixtures.

---

## 11. Security and privacy checks

| Check | Result |
|---|---|
| Captures excluded from git | `.gitignore` covers `*.pcap`, `*.pcapng`, `*.cap`, `captures/`, `data/`, `samples/`, `evidence/`, `tests/fixtures/generated/` |
| Key material excluded | `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, TLS key logs |
| Environment files excluded | `.env`, `.env.*`, with `.env.example` explicitly re-included |
| Analysis output excluded | `out/`, `reports/`, `result.json`, `*.sqlite` |
| Staging inspected before commit | `scripts/check_staged.sh` → *"no capture data, key material or environment files staged"* |
| Published tree audited after push | 88 files; zero matches for capture, key, env, venv or output patterns |
| Local file count == remote file count | 88 == 88 |
| Repository visibility | **PRIVATE** (`gh repo view` reports `"visibility":"PRIVATE"`) |
| Licence | None added; no authorisation was given to add one |
| No network I/O in the engine | No HTTP client, socket or DNS lookup imported anywhere |
| Live ARP/NDP blocked | `scapy_guard` raises `PassiveModeViolation`; verified by test |
| No subprocess in the engine | Verified by monkeypatching `subprocess.Popen`/`run`/`call` during a full analysis |
| No socket in the engine | Verified by monkeypatching `socket.socket`/`create_connection`/`getaddrinfo` |
| Shell metacharacters in filenames | A capture named ``a; rm -rf $(echo x) `id`.pcap`` analyses normally |
| Reports carry no payload | Fixture payload text absent as text and as hex |
| Reports carry no paths | Only `path.name` is recorded |
| No telemetry, no cloud AI | None exists |
| External downloads at install | `scapy`, `pydantic`, `pytest`, `ruff`, `mypy` from PyPI — documented in `SECURITY.md`; the application itself transmits nothing |

**Note for the maintainer.** Commits are authored as
`sgtsujith141-wq <phantomdelux.o5@gmail.com>` from the local git config. If a
different authorship identity is preferred for a public release, change it
before the repository is made public.

---

## 12. Git and remote status

| Item | Value |
|---|---|
| Implementation commit | `1ac2e979a76e164d3f2f1e19a0efdbcb85f37ded` |
| Branch | `main` |
| Files / lines | 88 files, 10,384 insertions |
| Remote | `https://github.com/sgtsujith141-wq/securemailscope` |
| Visibility | **PRIVATE** |
| Push result | `* [new branch] main -> main`, exit 0, verified with `gh repo view` |
| Working tree at commit time | Clean; `main` tracking `origin/main` |

This report is committed separately, after the implementation commit, so that
it can record that commit's hash.

---

## 13. Recommended next milestone

**M2 — email protocol layer over the reconstructed streams.**

The TCP layer is the foundation everything else stands on, which is why M1
spent its effort there. M2 is the right next step because it consumes that
layer through `payload_runs()` without modifying it, and because it is what
turns a session inventory into something recognisably about *email*.

Scope:

1. **Line-oriented protocol reader** over per-direction runs that refuses to
   parse across a gap. A command split by a hole must be reported as
   indeterminate, not guessed.
2. **SMTP** — banner, `EHLO`/`HELO`, capability list, response codes.
   Identification becomes `OBSERVED` when the grammar matches, replacing the
   port hint; the hint stays visible when it disagrees.
3. **IMAP** — tagged commands and `CAPABILITY` responses.
4. **POP3** — `+OK`/`-ERR` and `CAPA`.
5. **STARTTLS / STLS** — record the capability advertisement, the client
   command, the server's acceptance, and the exact stream offset where
   plaintext ends. This offset is the input M3 needs.
6. **Credentials in plaintext** — detect that `AUTH PLAIN`/`LOGIN` occurred
   *without* recording the credential. Report the packet reference and the
   mechanism only.
7. **Fixtures** — real protocol dialogues, including a STARTTLS upgrade, a
   capability advertised but never used, a command split across a gap, and a
   session on a non-standard port that the port hint gets wrong.

Explicitly deferred past M2: any TLS parsing (M3), any scoring (M4), any UI.

### Smaller follow-ups worth doing alongside

- A hash-pinned lock file (NF13).
- Property-based tests over the reassembler and a fuzzer over the container
  readers (`docs/test-strategy.md` records both as gaps).
- Fixtures for VLAN, Linux cooked and loopback link types.
- A multi-section, multi-interface pcapng fixture.
- A measured performance baseline, so a figure can eventually be quoted
  honestly.
