# Architecture

## What this system is

SecureMailScope turns a packet capture into a provenanced, auditable statement
about how email traffic was transported. Its defining constraint is not
performance or feature count — it is that **every claim must be traceable back
to specific bytes in a specific file**, and that anything the capture does not
establish must be visibly absent rather than quietly filled in.

That constraint drives most of the design decisions below.

## Execution model

The engine is a **pure function of (capture file, configuration)**. It is a
single-process, single-threaded, streaming pipeline with no shared mutable
state between runs, no background workers, no queue and no cache. Running it
twice over the same file produces identical output apart from the two analysis
timestamps.

There is no daemon. There is no network listener. There is no I/O other than
reading the capture and writing the report.

## Data flow

```
                       capture file on local disk
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ ingestion/reader.py            CaptureSource                │
   │   1. path validation (regular file, readable, resolved)     │
   │   2. size check vs max_capture_bytes -- BEFORE parsing      │
   │   3. SHA-256 of original bytes  ->  capture_id              │
   │   4. content-based format detection (magic numbers only)    │
   └──────────────────────────────┬──────────────────────────────┘
                                  │  streaming, one record at a time
   ┌──────────────────────────────▼──────────────────────────────┐
   │ ingestion/pcap_reader.py  |  ingestion/pcapng_reader.py     │
   │   container framing, endianness, timestamp resolution,      │
   │   per-interface link types, truncation diagnostics          │
   │                          -> RawFrame                        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ ingestion/dissect.py                                        │
   │   link layer stripped by hand (Ethernet/VLAN/SLL/loopback)  │
   │   IP + TCP dissected with Scapy                             │
   │   payload length taken from the IP header, not "bytes left" │
   │                          -> ParsedPacket | diagnostic       │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ network/sessions.py            TCPSessionEngine             │
   │   normalised 5-tuple -> connection instance                 │
   │   client/server roles (OBSERVED from SYN, else INFERRED)    │
   │   tuple reuse detection, lifecycle, concurrency limits      │
   └──────────────────────────────┬──────────────────────────────┘
                                  │  one per direction
   ┌──────────────────────────────▼──────────────────────────────┐
   │ network/reassembly.py     DirectionalReassembler            │
   │   32->64 bit sequence projection (network/seqspace.py)      │
   │   interval store keyed by extended sequence                 │
   │   dedup, retransmission, overlap conflict, gaps, budgets    │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ protocols/hints.py   port-derived hints, always INFERRED    │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ models/*  typed result  ->  reporting/json_report.py  -> JSON│
   └─────────────────────────────────────────────────────────────┘
```

`pipeline.py` wires these together and is the only module that knows the whole
sequence. `diagnostics.py` collects structured warnings from every stage with a
per-code emission cap.

## Module boundaries

| Package | Responsibility | May import |
|---|---|---|
| `models/` | Typed data contracts | nothing from this project |
| `errors.py`, `config.py` | Exceptions, limits | `errors` only |
| `diagnostics.py` | Bounded warning collection | `models` |
| `ingestion/` | Container parsing and dissection | `models`, `config`, `diagnostics` |
| `network/` | Flows, sequence space, reassembly, sessions | `models`, `config`, `diagnostics`, `ingestion`, `protocols` |
| `protocols/` | Application protocol handling (hints in M1) | `models` |
| `reporting/` | Serialisation | `models` |
| `pipeline.py` | Orchestration | everything above |
| `cli.py` | Command line | `pipeline`, `reporting`, `config` |
| `testing/` | Deterministic fixture generation | `models`, Scapy |
| `tls/`, `certificates/`, `assessment/`, `intelligence/`, `ml/` | Empty; later milestones | — |

Dependencies point one way. `models/` imports nothing from the project, so a
data contract can never be bent by an implementation detail. `ingestion/` does
not know what a session is. `network/` does not know what a report is.

Five packages exist as documented placeholders with no code. They carry a
docstring stating `NOT IMPLEMENTED`, the planned milestone and the intended
scope. They were not filled with stub functions, because a stub that returns
`None` is indistinguishable from a feature that found nothing.

## Key design decisions

### Bytes are stored against extended sequence numbers, not stream offsets

The reassembler keys its interval store on 64-bit extended sequence numbers and
computes stream offsets once, at finalisation. This matters for midstream
captures: if the first segment observed happens to be out of order, anchoring
offsets on it would push a genuinely earlier segment to a negative offset.
Deferring the anchor lets the earliest observed byte define offset 0 regardless
of arrival order.

### One interval per contributing packet

A segment that partially overlaps stored data is clipped and only its novel
byte ranges are inserted — each still attributed to the packet that carried it.
Intervals are never merged in storage. That is what allows a future TLS or SMTP
finding to name the exact frame its evidence came from. Merging happens only
when computing the reported contiguous runs.

### Overlap policy: `FIRST_OBSERVED_WINS`, conflict preserved

When two packets claim the same offsets with different bytes, the first
observation stays in the stream and the disagreement is recorded as an
`OverlapConflict` with both SHA-256 digests and both packet numbers.
Overlapping-segment disagreement is a deliberate IDS-evasion primitive, so the
ambiguity *is* the evidence. Only digests are kept, never the competing bytes,
so a report can demonstrate the disagreement without carrying payload.

### Reconstructed data is runs, not a blob

`DirectionalStream.runs` is a tuple of contiguous byte ranges. Two runs mean
there is a hole. Consumers iterate runs and parse each independently; there is
no API that concatenates across a gap, because doing so would invent data.

### Payload bytes never reach a model

`AnalysisResult` and everything under it carry counts, offsets, digests and
packet references. The reconstructed bytes live only in the reassembler and are
handed out explicitly through `analyze_capture_with_payloads`. Serialising a
report therefore *cannot* emit application data.

### The container reader is hand-written; Scapy dissects

pcap and pcapng framing is parsed directly rather than through a library. See
[adr/0002-custom-container-reader.md](adr/0002-custom-container-reader.md).
Scapy handles IP and TCP dissection, where its option parsing and layer model
earn their keep.

### Link layers are stripped by hand

Ethernet, VLAN, Linux cooked and BSD loopback headers are fixed-layout and
trivial to walk. Doing it directly keeps Scapy's packet-*building* machinery —
which can emit live ARP and Neighbour Solicitation traffic — out of the read
path entirely. See [SECURITY.md](../SECURITY.md).

## Resource model

Eight hard limits bound a hostile capture (see `.env.example` and
`docs/threat-model.md`). Two byte budgets — one per session, one global — are
shared by the reassemblers; when a budget is exhausted the stream keeps the
prefix it already reconstructed, is marked `truncated_by_limit`, and the
dropped range is reported as a `LIMIT_EXCEEDED` gap. Nothing is silently
discarded and no limit raises.

Memory is bounded by `max_total_payload_bytes` for reconstructed data plus
`max_segments_per_direction` for provenance records. Container parsing is
streaming: one packet record is resident at a time regardless of file size.

## Planned evolution

The TCP layer is the foundation every later milestone stands on, which is why
M1 spent its effort there. Later stages attach to it without modifying it:

- **M2** consumes `payload_runs()` per direction to parse SMTP/IMAP/POP3
  command and response grammar, and to detect `STARTTLS` / `STLS` upgrade
  points. Each parsed element keeps the packet references of the run it came
  from.
- **M3** frames TLS records over the same runs, reconstructs handshakes and
  extracts negotiated parameters. A gap in a run means the record layer stops
  there rather than guessing.
- **M4–M6** add assessment, correlation and ML on top of those observations,
  never replacing them.
- **M7–M8** add a local FastAPI adapter and a React UI around the unchanged
  engine.
