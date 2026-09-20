# Evidence model

Every statement SecureMailScope makes carries the evidence that supports it.
This document is the normative description of how that works; the code lives in
`src/securemailscope/models/evidence.py`.

The governing rule: **an inferred value is never presented as an observed one.**

## The four evidence statuses

| Status | Meaning | Value present? |
|---|---|---|
| `OBSERVED` | Read directly out of captured bytes. Reproducible from the capture file. | Yes |
| `INFERRED` | Derived by documented reasoning from observed data. Could be wrong if the capture is incomplete or the traffic was crafted adversarially. | Yes |
| `UNKNOWN` | The property is applicable, but this capture does not determine it. | No |
| `NOT_AVAILABLE` | The property cannot be determined by passive capture at all, or the analysis stage that would determine it is not implemented. | No |

The distinction between `UNKNOWN` and `NOT_AVAILABLE` matters to a reader
deciding what to do next. `UNKNOWN` says *get a better capture*.
`NOT_AVAILABLE` says *no capture will answer this* (or *this feature does not
exist yet*) — a longer capture will not help.

Consumers must branch on `status`, never on whether `value` is falsy. A
byte count of `0` is a perfectly good `OBSERVED` value.

## `PacketReference`

The atom of provenance. It points back into the capture at a specific frame.

```python
class PacketReference:
    packet_number: int      # 1-based, capture file order
    timestamp: datetime     # timezone-aware UTC
    timestamp_ns: int       # epoch nanoseconds, full precision
```

`packet_number` follows capture file order, so it matches the frame number
Wireshark shows for the same file — an analyst can jump straight to it.

Both timestamp fields are present on purpose. `datetime` stores only
microseconds, so a pcapng written with `if_tsresol=9` would silently lose
precision if `timestamp` were the only field. `timestamp_ns` carries the
original value exactly; `timestamp` is the timezone-aware form for display and
for public-facing output.

## `Observation[T]`

A value plus everything needed to audit it.

```python
class Observation[T]:
    value: T | None
    status: EvidenceStatus
    capture_id: str                      # "sha256:<hex>" of the capture file
    session_id: str | None               # when session-scoped
    packet_refs: tuple[PacketReference, ...]
    observed_at: datetime | None          # earliest supporting packet
    observed_until: datetime | None       # latest supporting packet
    basis: str | None                     # e.g. "TCP_SYN", "SERVER_PORT"
    limitations: tuple[str, ...]          # what this does NOT establish
```

Required content by status:

- `OBSERVED` — must carry at least one `PacketReference` and a `basis`.
- `INFERRED` — must carry a `basis` **and** a non-empty `limitations` tuple.
  An inference that cannot state what it fails to establish is not fit to
  report.
- `UNKNOWN` / `NOT_AVAILABLE` — `value` is `None`; `limitations` explains why.

### Worked example: the protocol hint

The only `Observation` M1 produces is the port-derived protocol hint. It is
deliberately conservative:

```json
{
  "value": "HINT:SMTP",
  "status": "INFERRED",
  "capture_id": "sha256:acc9ebe5...",
  "session_id": "sess-3b04cd6af955ed43",
  "packet_refs": [{"packet_number": 1, "timestamp": "2024-01-01T00:00:00Z",
                   "timestamp_ns": 1704067200000000000}],
  "basis": "SERVER_PORT",
  "limitations": [
    "Derived from the TCP port number alone; no application payload was parsed.",
    "A different protocol may be running on this port, and the real protocol may run on a non-standard port.",
    "This is NOT a confirmed protocol identification. Payload-based confirmation is not implemented (planned for M2)."
  ]
}
```

Three things make this honest. The status is `INFERRED`. The value is prefixed
`HINT:` so it cannot be mistaken for a confirmed identification even if a
display drops the status field. And the limitations say plainly what was *not*
done.

## Provenance in the TCP layer

The TCP models carry provenance structurally rather than wrapping every scalar
in an `Observation`, which would triple the size of a report for no gain.

| Type | Provenance it carries |
|---|---|
| `ReassembledSegment` | `source` packet, plus `duplicates` — every later packet that re-delivered the same bytes |
| `ByteRun` | `first_packet` and `last_packet` of the contributing intervals, plus `sha256` of the run's content |
| `ReassemblyGap` | `preceding_packet` and `following_packet`, plus `reason` and `content_status: UNKNOWN` |
| `OverlapConflict` | Both packet references and both SHA-256 digests of the competing bytes |
| `HandshakeInfo` | `syn_packet`, `syn_ack_packet`, both initial sequence numbers |
| `TerminationInfo` | `client_fin`, `server_fin`, `reset_packet` |
| `DirectionalStream` | `base_status` and `base_basis` — whether offset 0 was fixed by an observed SYN or inferred from the lowest observed sequence |
| `TCPFlow` | `role_status` and `role_basis` — how client and server were decided |
| `AnalysisWarning` | `code`, `packet_refs`, `session_id`, structured `details` |

### Gaps are observed; their contents are not

A `ReassemblyGap` is itself an observed fact: we saw byte 4 and byte 12 and
nothing between them. Its `content_status` is always `UNKNOWN`. The engine
never fills a gap, never elides it, and offers no API that concatenates across
one.

`GapReason` distinguishes three causes, because they mean different things:

| Reason | Meaning |
|---|---|
| `MISSING_SEGMENT` | Data between two observed ranges was never captured |
| `NOT_CAPTURED` | A packet *declared* these bytes but the capture's snapshot length cut them off — they are known to have existed |
| `LIMIT_EXCEEDED` | A configured limit stopped us storing them; a larger limit would recover them |

## Capture identity

`capture_id` is `"sha256:"` plus the SHA-256 of the **original file bytes**.
Every session, observation and warning carries it. Two analyses of the same
file always agree, a report can be tied to the exact artefact it came from, and
a report about a *different* file can never be mistaken for one about this one.

`session_id` is derived deterministically from `(capture_id, flow_id,
instance)`, so re-running an analysis reproduces the same identifiers and two
reports can be diffed.

## Diagnostics are evidence too

`AnalysisWarning` uses the same discipline. A malformed packet or an exceeded
limit changes how the rest of the report must be read, so it is not log noise —
it is a structured record with a stable `code`, a severity, packet references
and typed `details`. Warning codes are part of the output contract and are not
renamed without a schema version bump.

To keep a hostile capture from generating millions of identical records, the
sink caps emissions per code and replaces the overflow with one explicit
`WARNINGS_SUPPRESSED` record stating the true total. The count is never lost.

## Rules for future milestones

These apply to every stage added after M1:

1. A value with no packet backing it is `INFERRED` at best.
2. An `INFERRED` value without `limitations` must not be emitted.
3. No analysis stage may upgrade another stage's status. ML output in
   particular is always `INFERRED` and never promotes an observation.
4. A property that passive capture cannot determine is `NOT_AVAILABLE`, not
   `UNKNOWN`, and not omitted. TLS 1.3 certificate details are the canonical
   example — see [limitations.md](limitations.md).
5. Absence of a finding is never evidence of absence of the condition. Reports
   carry `stage_status` so a reader can tell "not found" from "not looked for".
