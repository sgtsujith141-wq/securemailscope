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
   │ protocols/reader.py       gap-safe bounded line reader      │
   │   runs -> lines, never across a hole; oversized lines cut   │
   │   and resynchronised; overlap-conflict bytes flagged        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │  interleaved by capture order
   ┌──────────────────────────────▼──────────────────────────────┐
   │ protocols/smtp.py | imap.py | pop3.py                       │
   │   real state machines: outstanding-command queues, IMAP tag │
   │   matching, multiline replies, literals, DATA bodies        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ protocols/framing.py   TLS record framing (evidence only)   │
   │ protocols/analyzer.py  pick the winning parser on evidence  │
   │ protocols/hints.py     port hints, always INFERRED          │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ tls/records.py         TLS record framing over the runs     │
   │   stops at a hole: after missing bytes, record alignment is │
   │   unknowable, so framing never resynchronises on a guess    │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ tls/handshake.py    message reassembly across records       │
   │ tls/extensions.py   supported_versions, key_share, SNI, ... │
   │   appends only plaintext records: past the encryption       │
   │   boundary nothing enters the buffer                        │
   └──────────────────────────────┬──────────────────────────────┘
                                  │
   ┌──────────────────────────────▼──────────────────────────────┐
   │ tls/keyexchange.py  tls/forward_secrecy.py  tls/registry.py  │
   │ certificates/parse.py  truststore.py  validate.py  policy.py│
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
| `protocols/` | Line reading, SMTP/IMAP/POP3 parsing, TLS framing, detection | `models`, `config`, `diagnostics` |
| `reporting/` | Serialisation | `models` |
| `pipeline.py` | Orchestration | everything above |
| `cli.py` | Command line | `pipeline`, `reporting`, `config` |
| `testing/` | Deterministic fixture generation | `models`, Scapy |
| `tls/` | Record framing, handshake reassembly, version/cipher/key-exchange/forward-secrecy analysis | `models`, `config`, `diagnostics`, `protocols` |
| `certificates/` | X.509 decoding, trust store, the five validation checks | `models`, `certificates.policy`, `cryptography` |
| `assessment/`, `intelligence/`, `ml/` | Empty; later milestones | — |

Dependencies point one way. `models/` imports nothing from the project, so a
data contract can never be bent by an implementation detail. `ingestion/` does
not know what a session is. `network/` does not know what a report is.

Three packages exist as documented placeholders with no code. They carry a
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

## The application protocol layer (M2)

### Parsers are chosen by evidence, not by port

All three parsers run speculatively over the same reconstructed streams and
each reports how much application-level evidence it found: a conforming
greeting, commands matching its grammar, and commands matched to their
responses in capture order. The highest score wins. A port number only breaks
a genuine tie, and never lifts a detection to `CONFIRMED`.

This is what lets the engine identify SMTP on port 8025 and refuse to call a
session IMAP merely because it is on port 143. Losing parsers write their
diagnostics to a throwaway sink, so only the winner's warnings survive.

### Reading never crosses a hole

`protocols/reader.py` assembles lines from *within a single contiguous run*.
A run boundary ends the line as `complete=False`, and the next line reports
`preceded_by_gap` with the size of the hole. `skip_bytes` -- used for IMAP
literals -- stops at a run boundary and says so. Bytes overlapping an
unresolved TCP overlap conflict are flagged `ambiguous` and are never treated
as protocol evidence.

A hole while an upgrade command is outstanding clears the pending queue and
sets a flag that forces the upgrade state to `INCOMPLETE`. The engine will not
claim a successful negotiation it did not see.

### Command/response correlation

Each parser keeps a queue of outstanding commands. SMTP matches replies FIFO,
so with pipelined `EHLO`/`STARTTLS` a `220` answering `EHLO` cannot be read as
accepting `STARTTLS`. Intermediate replies (`354` for `DATA`, `334` for an AUTH
challenge) do not complete their command. IMAP matches on the client's tag, so
a tagged `OK` carrying a different tag never accepts `STARTTLS`. POP3 has no
tags, so a response is matched to the single command outstanding when it
arrived.

### Content that is not protocol

An SMTP `DATA` body, an IMAP literal and a POP3 dot-terminated response are
all *content*. They are skipped by terminator or by declared length and never
parsed as commands, which is why a message body containing the text
`STARTTLS` produces no upgrade. Only a line consisting of exactly `.` ends a
dot-terminated body -- `..stuffed` does not. Each skip is bounded; exceeding
the bound stops parsing rather than resuming at a guessed offset.

### The TLS transition

Client and server have independent boundaries and independent bases:

* The **server** boundary is the end of its success reply -- the final line of
  a multiline `220`, not the first.
* The **client** boundary is where TLS record framing actually validates. The
  end of the upgrade command is where it is *expected*, not where it is
  assumed; when no framing validates there, the boundary is reported
  `NOT_OBSERVED`.

TLS bytes arriving in the same TCP payload as the acceptance reply are
preserved and forwarded, not discarded. After an accepted upgrade, plaintext
parsing stops unconditionally -- a failure to decode the following bytes never
causes a fall back to plaintext parsing.

`UpgradeState` separates what was seen: `UPGRADE_ADVERTISED` (offered),
`UPGRADE_REQUESTED` (asked, no answer seen), `UPGRADE_ACCEPTED` (server said
yes), `TLS_BYTES_OBSERVED` (and TLS-framed bytes followed), `UPGRADE_REJECTED`,
and `INCOMPLETE`. None of these means a handshake completed;
`handshake_analyzed` is a constant `False` for the whole of M2.

## The TLS and certificate layer (M3)

### Record alignment is lost at a hole

A TLS record stream is self-delimiting only if every preceding byte was read.
After missing data, the first byte of the next run may be the middle of a
record body, so framing from there produces confident nonsense.
`tls/records.py` therefore stops at the gap with `ALIGNMENT_LOST_AT_GAP`.
Records that merely span *TCP segments* are unaffected: segments inside one
reassembled run are contiguous, so a record split across packets is read
normally and every contributing packet is recorded.

Bytes overlapping an unresolved TCP overlap conflict are framed and reported
but never parsed — an ambiguous byte cannot be evidence of a negotiated
parameter.

### Records and messages are independent framings

One handshake message may span several records (a Certificate message always
does) and one record may carry several messages. `tls/handshake.py`
concatenates record *bodies* per direction and parses messages out of the
concatenation, keeping a map from every buffer position back to its stream
offset, record index and packets. Because a message that is incomplete when
one record arrives may complete when the next lands, the buffer is re-parsed
on each append and a message is only interpreted once it is complete.

### The encryption boundary

This is the spine of the design. Everything before it is evidence; everything
after it is bytes we can frame but must not interpret.

| Protocol | Boundary | Reference |
|---|---|---|
| TLS 1.2 | The ChangeCipherSpec sent by that direction | RFC 5246 §7.1 |
| TLS 1.3 | Immediately after the ServerHello, both directions | RFC 8446 §2 |

A TLS 1.3 peer may emit a ChangeCipherSpec purely for middlebox
compatibility (RFC 8446 §D.4). It is recognised as such and is **never** read
as evidence of a TLS 1.2 handshake. An `application_data` record in a TLS 1.3
session carries encrypted handshake messages and is never parsed as plaintext.

### Version identification

RFC 8446 §4.2.1: a TLS 1.3 server signals the version in the ServerHello
`supported_versions` extension and leaves `legacy_version` at 0x0303.
Identifying TLS 1.3 from the legacy field or from the record-layer version is
therefore wrong, and the report records which source was used. A ClientHello
without a ServerHello yields offered versions and a selected version of
`UNKNOWN` — the highest offered version is never promoted.

### Cipher suites mean different things in 1.2 and 1.3

A TLS 1.2 suite encodes key exchange, authentication, cipher and MAC. A
TLS 1.3 suite encodes an AEAD and a hash and nothing else (RFC 8446 §B.4), so
`decomposition_applicable` is `false` and the key-exchange fields stay empty;
the real answer comes from `key_share` and `signature_algorithms`. Unknown
code points are reported by their exact numeric value, and RFC 8701 GREASE
values are marked rather than reported as unknown algorithms.

### Certificate validation is five independent questions

`certificates/validate.py` answers presence, dates, chain, hostname and
revocation separately. The installed library exposes chain and hostname
together through `ServerVerifier`, so each is isolated by neutralising the
other: the chain check uses the leaf's own first DNS SAN as the subject, and
the hostname check trusts the presented chain. That deviation from a single
API call is documented in the module, because the alternative — a
hand-written RFC 6125 matcher — would be a second, unverified implementation
of the rule that matters most.

There is **no default trust store**: without one, chain verification is
`NOT_AVAILABLE` rather than silently using a bundle the report cannot name.
There is **no default reference identity**: the destination IP is never used
as one, and an observed SNI is the client's request rather than an authorised
expectation. Revocation is never performed, because the engine makes no
network requests at all.

## The assessment layer (M4)

The first three milestones answer *what was observed*. M4 answers *what that
means*, and keeps the two kinds of statement in separate blocks of the report
so a reader can always tell which is which. Nothing in the assessment layer
modifies, replaces or summarises a forensic observation: the reconstructed
sessions, handshakes and certificates are byte-identical whether the layer runs
or not, which `--no-assessment` demonstrates directly.

### Four independent stages

```
                  forensic observations (M1-M3, unchanged)
                                 |
                                 v
        +------------------ rule evaluation ------------------+
        |  25 rules x each session -> FAIL/PASS/UNKNOWN/N.A.  |
        |  de-duplication: one weakness -> one charged unit   |
        +-----------------------------------------------------+
                                 |
             +-------------------+-------------------+
             |                   |                   |
             v                   v                   v
        posture scoring    prioritisation      remediation
        (weighted units)   (severity x         (catalogue lookup
                            confidence          from raised
                            matrix)             findings only)
```

The four are independent on purpose. Scoring never reads the priority order;
prioritisation never reads the score; remediation walks the *findings that were
raised*, never the rules that might have fired. A defect in one cannot silently
corrupt another, and each can be tested in isolation.

### Module boundaries

| Module | Responsibility |
| --- | --- |
| `assessment/policy.py` | The versioned, named policy: thresholds, weights, approved and prohibited algorithms, and the rationale for each. |
| `assessment/catalog.py` | Static metadata: 25 `RuleDefinition` and 12 `Remediation` entries, with typed standards citations. |
| `assessment/rules.py` | The 25 evaluators. Each takes a `SessionContext` and returns a `Verdict`. |
| `assessment/evaluator.py` | Runs the enabled rules, de-duplicates, derives finding identifiers. |
| `assessment/scoring.py` | Builds scoring units and computes the score and coverage. |
| `assessment/prioritization.py` | The severity x confidence matrix and the deterministic sort. |
| `assessment/remediation.py` | Selects catalogue entries for the findings that were raised. |
| `assessment/engine.py` | Orchestrates the above per session and per capture. |

### Constraints the layer holds to

- **It reads typed models only.** It never re-parses a capture and never
  inspects serialised JSON with regular expressions. Its entire input is the
  `AnalysisResult` the forensic layers produced.
- **It needs no LLM.** There is no model dependency anywhere in the package,
  and the output is deterministic.
- **It never turns `UNKNOWN` into `PASS`.** Missing evidence is reported as
  missing and excluded from the score arithmetic on both sides.
- **It never infers intent.** A weak configuration is a weak configuration; a
  refused STARTTLS is what a server with no TLS configured also does, and the
  finding says so.
- **It retains no credential material.** The redaction guarantees M2
  established hold through the new layer, and are re-asserted against it.

### Schema evolution

The report schema moved 1.2.0 -> **1.3.0**, additively. Every M1–M3 block is
present and unchanged; the `assessment` block is new and may be omitted
entirely. See [scoring-methodology.md](scoring-methodology.md) and
[security-policy.md](security-policy.md).

## Planned evolution

The TCP layer is the foundation every later milestone stands on, which is why
M1 spent its effort there. Later stages attach to it without modifying it:

- **M2 (done)** consumes `payload_runs()` per direction to parse SMTP/IMAP/POP3
  command and response grammar and to reconstruct `STARTTLS` / `STLS` state.
  Each parsed element keeps the packet references of the bytes it came from.
- **M3 (done)** reconstructs TLS records and handshakes starting from the
  boundaries M2 produced, extracts negotiated parameters, and decodes and
  validates certificates where they are visible in plaintext.
- **M4 (done)** evaluates 25 evidence-based rules against those observations
  and produces an explainable score, a priority order and remediation guidance,
  all in additive report blocks that never replace the observations.
- **M5–M6** add cross-session correlation and local ML on top, never replacing
  what came before.
- **M7–M8** add a local FastAPI adapter and a React UI around the unchanged
  engine.
