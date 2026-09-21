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

## The application protocol layer (M2)

### Detection has its own ladder

`DetectionStatus` sits alongside `EvidenceStatus` because "which protocol is
this?" needs a finer answer than four evidence statuses give:

| Status | Requires | `evidence_status` |
|---|---|---|
| `CONFIRMED` | A conforming greeting plus at least one command matched to its response, or two matched exchanges without a greeting | `OBSERVED` |
| `PROBABLE` | Real but incomplete application evidence | `INFERRED` |
| `PORT_HINT` | Nothing but the TCP port | `INFERRED` |
| `UNKNOWN` | Neither | `UNKNOWN` |

**A port number can never reach `CONFIRMED`.** `confidence_basis` records
exactly which rung was used (`GREETING_AND_MATCHED_EXCHANGE`,
`SINGLE_MATCHED_EXCHANGE`, `SERVER_PORT_ONLY`, ...), and `port_hint_agrees`
says whether the payload and the port told the same story. When they disagree,
the payload wins and the disagreement is stated in `limitations`.

### Text that may appear in a report

No bytes from a capture become report text unless they pass
`protocols/redaction.py`:

| Field | Rule |
|---|---|
| `command_verb` | Matched against a closed per-protocol vocabulary. An unrecognised token is reported as unrecognised, never quoted. |
| `mechanism` | Matched against a closed list of SASL mechanism names. |
| `tag` | IMAP tag shape only: 32 characters from a restricted alphabet. |
| `capabilities` | Shape-filtered, and only ever taken from a line a parser already identified as a capability advertisement in a *server* reply. |
| `reply_code` | Three digits, or `+OK` / `-ERR` / `OK` / `NO` / `BAD`. |
| `detail` | Written by the engine. Never contains capture content. |

Shape alone is not sufficient for verbs: a base64 SASL payload such as
`dXNlcgBteXBhc3N3b3Jk` is alphanumeric and short, so a naive "looks like a
verb" filter would pass a credential straight into a report. This was caught
while building the filter, and is why verbs are allowlisted.

Greeting banners, command arguments, mailbox names, addresses, message bodies,
IMAP literals and SASL payloads are never recorded at all -- not as text, not
as hex, not as a digest.

### Authentication observations

`AuthenticationObservation` records that an attempt happened and nothing about
what was sent: protocol, verb, mechanism (when it is a recognised name),
direction, offset, packet references, whether an accepted TLS upgrade was in
effect, and a *count* of continuation rounds. `credentials_recorded` is a
constant `False`, present so a reader does not have to take the guarantee on
trust, and asserted by the test suite.

`occurred_before_tls_upgrade` is an observation, not a verdict. Whether
plaintext authentication constitutes a finding is an M4 question.

### An upgrade is not encryption

`UpgradeState` distinguishes six outcomes precisely because "STARTTLS
happened" is ambiguous. Even `TLS_BYTES_OBSERVED` means only that bytes with
valid TLS record framing followed the acceptance. Three fields on
`TLSUpgradeAttempt` exist to make the boundary of our knowledge explicit, and
all three are constants in M2:

- `handshake_analyzed: False`
- `handshake_analysis_status: "NOT_IMPLEMENTED"`
- `negotiated_parameters_available: False`

`TLSFramingEvidence` grades the framing itself. A single well-formed record
header is `SINGLE_RECORD_HEADER` and carries `INFERRED` status, because
arbitrary binary can match it by chance. An identifiable ClientHello or
ServerHello whose inner length agrees with the record length, or a chain of
records whose lengths line up end to end, is `OBSERVED`.

### Boundaries carry their basis

`TLSBoundary.basis` is one of `SERVER_SUCCESS_REPLY_END` (the end of the
server's success reply), `FIRST_TLS_RECORD` (where framing actually validated)
or `NOT_OBSERVED`. A client boundary is never inferred from the end of the
upgrade command: if no framing validates, the boundary says `NOT_OBSERVED`
with `UNKNOWN` status rather than guessing.

## The TLS and certificate layer (M3)

### Offered is not selected

`TLSVersionAnalysis` and `CipherSuiteAnalysis` keep the two apart in separate
fields. A ClientHello populates `offered_versions` and `offered`; only a
ServerHello populates `selected_version` and `selected`. With no ServerHello,
`negotiation_status` is `UNKNOWN` and the selected fields stay empty. The
highest offered version is never promoted into a negotiated one.

`selected_source` records *how* the version was determined —
`SUPPORTED_VERSIONS_EXTENSION` or `LEGACY_VERSION` — because for TLS 1.3 only
the first is correct (RFC 8446 §4.2.1).

### Unknown code points keep their numbers

`CodePointRef` carries the numeric value, its hex form, the registered name
when the registry has one, and `known`. An unrecognised cipher suite is
reported as `0x1337` with `known: false`, never approximated from a
neighbouring entry. RFC 8701 GREASE values are marked `grease: true` so they
are not counted as unknown algorithms. `CipherSuiteAnalysis` names the
registry and its revision so a reader can tell which table produced a name.

### Negotiation is not completion

Passive analysis cannot verify a Finished message without the handshake
traffic keys. Three fields exist to make that boundary explicit, and all three
are constants in M3:

- `TLSUpgradeAttempt.handshake_analyzed` / `handshake_analysis_status`
- `ForwardSecrecyAssessment.handshake_completion_observable` — `false`, with
  `handshake_completion_explanation` carrying the reason
- `TLSInventory.handshakes_cryptographically_verified` — `0`
- `TLSInventory.revocation_checks_performed` — `0`

### Forward secrecy states its criteria

`ForwardSecrecyAssessment.criteria` is a sentence naming the RFC clause and
the evidence that produced the status. The statuses separate *capability* from
*observation*:

| Status | Meaning |
|---|---|
| `EPHEMERAL_OBSERVED` | An ephemeral exchange was negotiated **and** its key material was seen (a TLS 1.2 ServerKeyExchange or a TLS 1.3 server `key_share`) |
| `CAPABLE_NEGOTIATED` | An ephemeral suite was negotiated but the key material was not captured |
| `STATIC_RSA_KEY_EXCHANGE` | RFC 5246 §7.4.7.1: the premaster secret is encrypted to the server's long-term key |
| `PSK_ONLY` | A pre-shared key with no ephemeral contribution |
| `NOT_FORWARD_SECRET` | A known method that provides none |
| `UNKNOWN_INCOMPLETE_EVIDENCE` | Not enough was observed to classify |
| `NOT_OBSERVABLE` | The property cannot be determined passively for this session |

TLS 1.3 is **not** assumed forward secret merely because it is TLS 1.3: a
PSK-only resumption without a `key_share` is `PSK_ONLY`.

### Certificate absence has causes

`CertificateVisibility` distinguishes why no certificate is available, so
"none present" is never reported as a certificate failure:

| Value | Meaning |
|---|---|
| `OBSERVED` | A plaintext Certificate message was decoded |
| `ENCRYPTED_TLS13` | It exists but is encrypted under handshake traffic keys. Permanent. |
| `ENCRYPTED_AFTER_CCS` | TLS 1.2 went encrypted before any certificate was seen |
| `NOT_PRESENT_RESUMED` | A resumed session legitimately carries none |
| `NOT_OBSERVED` | The handshake never reached that point in this capture |
| `PARSE_FAILED` / `PARSER_UNAVAILABLE` | Present but undecodable, or no X.509 library |
| `NOT_APPLICABLE_ANONYMOUS` | An anonymous suite sends no certificate |

### Observation and validation are separate models

`CertificateObservation` records what a certificate *claims*.
`CertificateValidation` records five independent answers, each with its own
status and explanation:

| Check | Answers |
|---|---|
| `certificate_observed` | Was one visible at all? |
| `validity_dates_checked` | Was it inside its window **at capture time**? |
| `chain_verified` | Does it chain to an explicitly configured anchor? |
| `hostname_verified` | Does it name the identity the analyst expected? |
| `revocation_checked` | Always `NOT_AVAILABLE` — see below |

None implies another. A verified chain says nothing about the name, and
neither says anything about revocation.

`assessment_mode` is always `CAPTURE_TIME` for the primary answer; a
current-time assessment, when requested, is additive and labelled as a
separate statement. `PublicKeyInfo.size_bits` is `None` for Ed25519 and Ed448,
because a variable key length is not a meaningful description of them.

`TrustStoreInfo` identifies the anchor set by a digest of its members'
fingerprints rather than by a filesystem path, so two reports can be compared
without disclosing where anyone keeps their files.

### Revocation is never performed

`REVOCATION_EXPLANATION` is attached wherever it matters: the engine makes no
network requests, so OCSP and CRL retrieval are out of scope by design, and a
successful chain verification is **not** evidence of non-revocation.

## The assessment layer (M4)

M4 introduces a second kind of statement. The forensic layers say *this was
observed*; the assessment layer says *this is a problem under this policy*.
Those are different claims with different warrants, and the model keeps them
apart.

### Rule outcomes are not evidence statuses

| Evidence status | Grades | Produced by |
| --- | --- | --- |
| `OBSERVED` / `INFERRED` / `UNKNOWN` / `NOT_AVAILABLE` | an observation | M1–M3 |
| `FAIL` / `PASS` / `UNKNOWN` / `NOT_APPLICABLE` | a judgement about observations | M4 |

They are deliberately separate enumerations. An `OBSERVED` cipher suite can
`FAIL` a rule; an `INFERRED` one produces a finding at reduced *confidence*,
not at reduced severity.

### Confidence is derived from evidence status

`Confidence` is the bridge between the two vocabularies:

| Confidence | When |
| --- | --- |
| `CONFIRMED` | Every supporting observation was `OBSERVED`, from a complete record. |
| `PROBABLE` | At least one supporting observation was `INFERRED`. |
| `LOW` | The session was partial, indeterminate, or identified only by port. |

A finding never inherits a *severity* from evidence quality, and never has its
severity reduced because the evidence was thin. Thin evidence lowers
confidence, which lowers priority through the matrix — and the report shows
both numbers, so the reason is visible.

### Every finding carries its evidence forward

A `SecurityFinding` carries `evidence_refs` (packet references), `stream_offsets`
and `observed_values` (the concrete values the rule read, each naming the
observation field it came from). A `FAIL` with no evidence references is a
contract violation and is asserted against.

Packet references are checked to be in range for the capture and to carry the
timestamp the capture actually recorded for that frame, against the committed
fixture manifest rather than against anything the pipeline produced.

### Rules for the assessment layer

These extend the rules above, and apply to M5 onward as well:

10. **A judgement is never presented as an observation.** Rule outcomes,
    findings, scores and remediations live in the `assessment` block; the
    forensic blocks are unchanged by their presence.
11. **`UNKNOWN` is never promoted to `PASS`.** A rule that could not be
    evaluated says so, and contributes to neither side of the score.
12. **A finding is never generated because an observation is unavailable.**
    Only `FAIL` becomes a finding. The absence of a trust store is an evidence
    gap, not a chain failure.
13. **Severity, confidence and priority are never multiplied together.** They
    are three axes, reported separately, combined only by a published lookup
    table.
14. **Attack intent is never inferred from a configuration.** Where a weak
    observation has an innocent explanation, the finding states it.
15. **One underlying weakness is counted once and reported once.** Rules
    sharing a de-duplication group charge the most severe member; the rest are
    reported with `counts_toward_score: false`.
16. **Criticality is supplied, never inferred.** No port number, hostname or
    address makes a host important.
17. **A finding identifier binds to the criteria that produced it.** The policy
    fingerprint — version plus every applied override — is part of the
    identifier, so reports produced under different thresholds cannot appear to
    describe the same finding.

## The forensic intelligence layer (M5)

M5 introduces statements about *relationships between* observations. They are
weaker than the observations themselves, and the model keeps that visible.

### Three vocabularies, kept apart

| Vocabulary | Grades | Layer |
| --- | --- | --- |
| `OBSERVED` / `INFERRED` / `UNKNOWN` / `NOT_AVAILABLE` | an observation | M1-M3 |
| `FAIL` / `PASS` / `UNKNOWN` / `NOT_APPLICABLE` | a judgement about observations | M4 |
| `OBSERVED_CHANGE` / `UNCHANGED_WITH_EVIDENCE` / `INCONCLUSIVE` / `NOT_COMPARABLE` | a comparison of observations | M5 |

`NOT_COMPARABLE` is M5's `UNKNOWN`: the honest answer when one side was not
observed, and never promoted to either "changed" or "unchanged".

### Fingerprint component sources

`CLIENT_OFFERED`, `SERVER_SELECTED`, `CERTIFICATE_OBSERVED`, `INFERRED`,
`UNKNOWN`. A fingerprint contains only server-attributable components; a test
asserts no component is ever `CLIENT_OFFERED`.

### Relationships are typed by what was matched

`EXACT_ENDPOINT`, `SHARED_CERTIFICATE`, `SHARED_PUBLIC_KEY`, `OBSERVED_SNI`,
`CONFIGURATION_MATCH`, `POSSIBLE_RELATION`, `INSUFFICIENT_EVIDENCE`. Each names
exactly the property that matched. None of them means "the same machine", and
each carries the limitation that says so.

### Rules for the intelligence layer

These extend the earlier rules and apply to M6 onward:

18. **Entities are merged only on exact endpoint equality.** Every weaker
    signal is a typed relationship between entities that stay separate.
19. **A comparison against an unobserved value is `NOT_COMPARABLE`.** Absence
    is never reported as change, in either direction.
20. **A negotiated value is a function of two inputs.** A difference is
    attributed to the server only when the client's offer was the same.
21. **A fingerprint records its own incompleteness.** Missing components are
    listed, written explicitly into the canonical form, and reflected in the
    completeness status.
22. **A correlation groups observations, never actors.** No attack, campaign,
    intent, ownership or topology is inferred anywhere.
23. **Counts name their counting method and their scope.** Every aggregate says
    how it counted and that it covers the analysed captures only.
24. **Derived events name what they were derived from.** A timeline event that
    was computed rather than observed carries `derived_from` and is marked
    `INFERRED`.
25. **No timestamp is invented.** An event whose timing the capture does not
    establish has no timestamp, and file modification times are never
    substituted.

## The machine-learning layer (M6)

ML adds a fourth kind of statement, and it is the weakest of the four.

| Vocabulary | Grades | Layer |
|---|---|---|
| `OBSERVED` / `INFERRED` / `UNKNOWN` / `NOT_AVAILABLE` | an observation | M1-M3 |
| `FAIL` / `PASS` / `UNKNOWN` / `NOT_APPLICABLE` | a judgement about observations | M4 |
| `OBSERVED_CHANGE` / `UNCHANGED_WITH_EVIDENCE` / `INCONCLUSIVE` / `NOT_COMPARABLE` | a comparison of observations | M5 |
| `ANOMALOUS` / `NOT_ANOMALOUS` / `NOT_EVALUABLE` / `MODEL_UNAVAILABLE` | a model's opinion about observations | M6 |

Every ML result carries a disclosure that a model produced it, and every ML
result is `INFERRED` by construction. Rule 3 of this document -- no stage may
upgrade another stage's status -- applies with full force here.

### Absence has reasons, and the model is told which

`AbsenceReason` distinguishes `OBSERVED`, `UNKNOWN`, `NOT_AVAILABLE` and
`NOT_APPLICABLE` as an explicit feature. A certificate absent from a TLS 1.3
session is `NOT_AVAILABLE` -- the protocol encrypts it; a certificate absent
from a truncated session is `UNKNOWN`. Collapsing both to a zero would teach a
model that TLS 1.3 servers have no certificate.

### Rules for the ML layer

These extend the earlier rules:

26. **A model's output is never an observation.** It lives in the `ml` block,
    is labelled as ML on its face, and modifies nothing above it.
27. **Insufficient evidence produces abstention, never a fallback.** A session
    without an observed negotiation is `ML_NOT_EVALUABLE`; scoring it anyway
    would report the capture's limits as the subject's.
28. **A model is never trained on another layer's conclusions.** No M4 score,
    severity or rule outcome is a feature or a target, or the model would be an
    opaque reimplementation of a deterministic engine that already exists.
29. **An identity is never a feature.** No address, host name, SNI or
    certificate subject, so a model cannot memorise entities and present it as
    generalisation.
30. **A score is not a probability unless calibration was fitted and
    validated.** It has not been, so model outputs are reported as relative
    scores.
31. **An anomaly is relative to a stated population.** The reference population
    is recorded with the model, because "unusual" has no meaning without it.
32. **Rarity is not risk.** A rare configuration may be the strongest one
    present, and the negative-control family exists to keep that testable.

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
6. No capture byte becomes report text without passing a redaction filter. New
   fields carrying capture-derived strings must be allowlisted or
   shape-constrained, and covered by a test that a dummy credential cannot
   reach them.
7. An upgrade, a record header and a handshake are three different facts. No
   stage may collapse them.
8. Offered is never selected; negotiated is never completed; parsed is never
   validated. Each pair has separate fields and neither may be derived from
   the other.
9. A code point with no registry entry keeps its number. Nothing is
   approximated from a name's shape.
