# M2 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M2 — Email protocol intelligence and STARTTLS/STLS state reconstruction
- **Baseline (M1):** `fe3e0d1ef4aff90f31eb0316e8de1c9fe34bc351`
- **Result:** **COMPLETE** — every acceptance gate in the directive passes. Two
  gates are qualified below (§10.1 and §10.2) and neither is a failure.

---

## 1. Pre-implementation audit

The supplied baseline was verified before any change:

| Claim | Verified | Actual |
|---|---|---|
| HEAD at `fe3e0d1ef4aff90f31eb0…` | yes | `fe3e0d1ef4aff90f31eb0316e8de1c9fe34bc351` |
| Local HEAD == remote HEAD | yes | identical |
| Branch | yes | `main` |
| Working tree | yes | clean, zero untracked files |
| 168 passing tests | yes | `168 passed in 7.79s` |
| 17 deterministic fixtures | yes | 17 manifests |
| Lint / type checks | yes | ruff clean, mypy clean over 41 files |
| Private GitHub repository | yes | `sgtsujith141-wq/securemailscope`, `PRIVATE` |

**No discrepancies against the supplied baseline.** No unrelated local changes
existed to preserve, and no destructive git operation was performed.

One environment finding: **TShark is not installed on this machine**
(`which tshark` → not found). Its consequences are in §10.2.

The implementation was adapted to the code that exists rather than to the
directive's suggested shapes. In particular `AnalysisArtifacts.payload_runs`
already existed from M1 as the intended hand-off point, so M2 consumes it
rather than introducing a parallel path.

---

## 2. Files changed

71 files, +8,793 / −112.

### New engine modules

| Module | Lines | Purpose |
|---|---|---|
| `models/protocol.py` | 430 | `ProtocolEvent`, `ProtocolDetection`, `TLSUpgradeAttempt`, `TLSBoundary`, `TLSRecordObservation`, `AuthenticationObservation`, `ProtocolSessionAnalysis`, `ProtocolInventory` and their enums |
| `protocols/reader.py` | 460 | Gap-safe bounded line reader, `DirectionalBuffer`, `PacketIndex`, `DialogueDriver`, `merge_span` |
| `protocols/redaction.py` | 160 | Allowlists and shape filters that gate every capture-derived string |
| `protocols/framing.py` | 200 | TLS record framing validation and evidence grading |
| `protocols/base.py` | 480 | Outstanding-command queue, upgrade bookkeeping, boundary probing, detection scoring |
| `protocols/smtp.py` | 480 | SMTP state machine |
| `protocols/imap.py` | 460 | IMAP state machine with tag matching and literals |
| `protocols/pop3.py` | 400 | POP3 state machine with dot-terminated bodies |
| `protocols/analyzer.py` | 330 | Speculative parsing, evidence-based winner selection, implicit TLS |

### New test-support modules

`testing/dialogue.py` (sequence/offset-tracking conversation builder),
`testing/tls_blobs.py` (synthetic structurally-valid TLS records),
`testing/protocol_fixtures.py` (the 20 M2 fixtures with hand-derived
expectations).

### New tests

`tests/test_protocols.py` (manifest-driven, 140 cases),
`tests/test_protocol_reader.py` (37),
`tests/test_protocol_behaviour.py` (16),
`tests/test_tshark_crosscheck.py` (5, opt-in).

### Modified

`models/analysis.py` (schema 1.1.0, new stages, two new result fields),
`models/evidence.py` (+16 warning codes), `config.py` (+5 limits),
`diagnostics.py` (`WarningSink.extend`), `pipeline.py` (protocol stage),
`cli.py` (flags + protocol summary), `reporting/json_report.py`
(`include_protocol_events`), `protocols/hints.py` (`protocol_for_port`),
`testing/fixtures.py`, `testing/manifest.py`, `tests/test_cli.py`,
`tests/test_report.py`, all 17 M1 manifests (two new fields only), and the
five documentation files.

No file outside this project directory was created or modified.

---

## 3. Implemented functionality

### Protocol detection

Three real state machines — not regexes, not port lookups. All three run
speculatively over the same reconstructed streams; each reports how much
application evidence it found (conforming greeting, commands matching its
grammar, commands matched to responses in capture order) and the highest score
wins. Losing parsers write to a throwaway sink so only the winner's
diagnostics survive.

| Status | Requires |
|---|---|
| `CONFIRMED` | Greeting + ≥1 matched exchange, or ≥2 matched exchanges without a greeting |
| `PROBABLE` | Real but incomplete application evidence |
| `PORT_HINT` | Only the TCP port |
| `UNKNOWN` | Neither |

**A port number can never reach `CONFIRMED`.** SMTP on port 8025 is confirmed
from payload (fixture P_H); a POP3 dialogue on port 143 is reported POP3 with
`port_hint_agrees: false` (P_I); binary traffic on port 25/143/110 is never
confirmed.

### Gap-safe stream reading

Lines are assembled only from bytes inside a single contiguous run. A run
boundary ends the line `complete=False`; the next line carries
`preceded_by_gap` and the hole's size. `skip_bytes` (IMAP literals) stops at a
run boundary and says which way it stopped. Bytes overlapping an unresolved
TCP overlap conflict are flagged `ambiguous` and are never usable as evidence.
Lines over `max_line_bytes` are truncated, reported, and the reader
resynchronises at the next terminator rather than buffering.

A hole while an upgrade command is outstanding clears the pending queue, emits
`PROTOCOL_DESYNCHRONISED`, and forces the upgrade state to `INCOMPLETE`.

### SMTP

Greeting, `EHLO`/`HELO`, multiline replies (complete only at the final line),
`STARTTLS` advertisement and command, `AUTH` with `334` continuations, `QUIT`.
Replies match a FIFO of outstanding commands, so a `220` answering `EHLO`
cannot accept a pipelined `STARTTLS`. `354` and `334` are intermediate and do
not complete their command. DATA bodies are skipped by terminator with
dot-stuffing handled — only a line that is exactly `.` ends one.

Outcomes: `220` accepts; `454` and other `4xx` are temporary failures; `5xx`
is permanent rejection; anything else leaves the outcome undetermined and
marks the negotiation unsafe.

### IMAP

Greeting (including `[CAPABILITY …]` in the greeting), tagged commands,
`* CAPABILITY`, `STARTTLS`, `LOGIN`/`AUTHENTICATE`, `LOGOUT`. Completions match
on the client's tag — a tagged `OK` with a different tag never accepts
`STARTTLS` (P_E) and untagged `* OK` never completes a command. Literals
(`{n}` and `{n+}`) are skipped by declared length in both directions, so a
literal containing a full fake STARTTLS exchange produces no upgrade (P_Q). A
literal that runs past a gap or the size cap stops parsing.

### POP3

Greeting, `CAPA` with its dot-terminated body, `STLS`, `USER`/`PASS`/`APOP`/
`AUTH`, `QUIT`. Multiline responses for `CAPA`/`LIST`/`UIDL`/`RETR`/`TOP` are
skipped to their dot terminator with dot-stuffing handled, so a retrieved
message containing `STLS` and a fake `+OK` produces no upgrade (P_R). `STLS`
issued after authentication is recorded with a note that RFC 2595 does not
allow it.

### TLS transition model

Eight states: `PLAINTEXT`, `UPGRADE_ADVERTISED`, `UPGRADE_REQUESTED`,
`UPGRADE_ACCEPTED`, `UPGRADE_REJECTED`, `TLS_BYTES_OBSERVED`, `INCOMPLETE`,
`UNKNOWN`.

Client and server boundaries are independent and carry their basis:

- **Server:** `SERVER_SUCCESS_REPLY_END` — the end of the success reply,
  which for a multiline `220` is the end of its *final* line (P_C).
- **Client:** `FIRST_TLS_RECORD` — where record framing actually validated.
  The end of the upgrade command is where it is *expected*, not assumed: when
  nothing validates there the boundary is `NOT_OBSERVED` with `UNKNOWN` status.

TLS bytes arriving in the same TCP payload as the acceptance are preserved and
forwarded with their offsets and packet references (P_L). After acceptance,
plaintext parsing stops unconditionally — a failure to decode the following
bytes never causes a fall back (P_N).

`handshake_analyzed` is `False`, `handshake_analysis_status` is
`"NOT_IMPLEMENTED"` and `negotiated_parameters_available` is `False` in every
report M2 produces.

### Implicit TLS

Record framing probed from the first byte of the session. When strong, the
session is reported as TLS-framed from the start — and the email protocol
inside it stays a **port hint**, never confirmed. Truncated records are
reported incomplete with an explicit limitation.

Framing evidence is graded: a lone well-formed record header is
`SINGLE_RECORD_HEADER` with `INFERRED` status, because arbitrary binary can
match it by chance. An identifiable ClientHello/ServerHello whose inner length
agrees with the record length, or a chain of length-consistent records, is
`OBSERVED`.

### Authentication privacy

`AuthenticationObservation` records protocol, verb, mechanism (when it is a
recognised SASL name), direction, offset, packet references, whether an
accepted upgrade was in effect, and a **count** of continuation rounds.
`credentials_recorded` is a constant `False`.

Nothing else is kept. Usernames, passwords, base64 tokens, SASL payloads,
email addresses, mailbox names, greeting banners and message bodies never
reach a model, a report, a warning, a log line or a test snapshot.

**A hole found in my own first implementation:** the initial `safe_verb`
filter accepted "letters and digits, ≤20 characters", which a base64 SASL blob
such as `dXNlcgBteXBhc3N3b3Jk` passes. Verbs and mechanisms are now matched
against closed allowlists, and
`test_safe_verb_only_accepts_known_protocol_keywords` pins that behaviour.

---

## 4. Test results

Every command below was executed; output is verbatim.

```
$ .venv/bin/python -m pytest -q
351 passed, 20 skipped in 26.84s

$ .venv/bin/python -m pytest -q -m "not integration"
338 passed, 20 skipped, 13 deselected in 4.19s

$ .venv/bin/python -m pytest -q -m integration
13 passed, 358 deselected in 18.67s

$ .venv/bin/ruff check src tests scripts
All checks passed!

$ .venv/bin/mypy
Success: no issues found in 53 source files

$ .venv/bin/python scripts/generate_fixtures.py
37 fixtures -> tests/fixtures/generated
37 manifests -> tests/fixtures/manifests
```

**351 passed, 0 failed.** The 20 skips are all intentional:

| Skips | Reason |
|---|---|
| 15 | `test_no_credential_material_reaches_the_report` on fixtures that carry no credentials — nothing to assert |
| 5 | `test_tshark_crosscheck.py` — opt-in, and TShark is not installed here |

### Coverage by file

| File | Tests | Scope |
|---|---|---|
| `test_ingestion.py` | 66 | M1: numbering, timestamps, rejections, all limits |
| `test_reassembly.py` | 47 | M1: reconstruction, byte equality, provenance |
| `test_protocols.py` | 140 | M2: manifest-driven detection, upgrade, events, auth, warnings, credential absence |
| `test_protocol_reader.py` | 37 | Reader bounds and gap safety, redaction, TLS framing |
| `test_protocol_behaviour.py` | 16 | Command matching, malformed input, limits, boundary |
| `test_formats.py` | 13 | Magic-number detection |
| `test_cli.py` | 13 | End-to-end subprocess, including 5 new M2 cases |
| `test_sessions.py` | 10 | M1: flows, tuple reuse, roles |
| `test_seqspace.py` | 10 | M1: wraparound |
| `test_report.py` | 8 | JSON contract, payload absence, stage status |
| `test_passive.py` | 6 | No socket, no subprocess, ARP/NDP blocked |
| `test_tshark_crosscheck.py` | 5 | Opt-in cross-validation (skipped) |

### Directive §14 coverage

| Required test area | Where |
|---|---|
| Protocol detection precision | `test_protocols.py::test_detection_matches_manifest`, `test_a_conventional_port_alone_never_confirms` |
| State transitions | `test_upgrade_state_and_boundaries_match_manifest` (all 20 fixtures) |
| Tag and response matching | P_E, `test_a_220_answering_an_earlier_command_does_not_accept_starttls`, `test_imap_untagged_ok_does_not_complete_a_command` |
| Gap behavior | P_K, `test_line_is_never_assembled_across_a_gap`, `test_skip_bytes_stops_at_a_gap_and_says_so` |
| Correct stream offsets | `test_key_events_present_with_exact_offsets_and_provenance`, `test_offsets_are_absolute_not_run_relative` |
| Exact packet provenance | same, asserting `packet_refs` and aware timestamps |
| Implicit TLS uncertainty | P_O, `test_implicit_tls_on_993_is_a_port_hint_not_confirmed_imap` |
| Authentication redaction | `test_no_credential_material_reaches_the_report`, `test_analyze_never_emits_credentials`, `test_unrecognised_command_token_is_not_echoed` |
| Malformed responses | `test_malformed_server_reply_is_reported_not_crashed`, `test_reply_code_followed_by_neither_space_nor_hyphen_is_rejected` |
| Oversized lines and literals | `test_oversized_line_is_truncated_and_resynchronises`, `test_oversized_imap_literal_stops_parsing`, `test_oversized_data_body_stops_parsing` |
| No plaintext after acceptance | P_N, `test_no_plaintext_parsing_resumes_after_acceptance` |
| End-to-end CLI | 5 new cases in `test_cli.py` |

---

## 5. Fixture inventory

37 total: the 17 M1 fixtures (unchanged) plus 20 new protocol fixtures.
Captures remain gitignored; the generator and hand-derived manifests are
committed.

| Fixture | Bytes | SHA-256 (prefix) | Scenario |
|---|---|---|---|
| P_A | 1172 | `51bd469b14` | SMTP STARTTLS accepted, command segment retransmitted |
| P_B | 1245 | `1b126dad1d` | SMTP STARTTLS refused with 454 |
| P_C | 1083 | `be58e4689b` | Multiline 220 acceptance |
| P_D | 1093 | `b4d293b86f` | IMAP STARTTLS accepted, CAPABILITY out of order |
| P_E | 1096 | `069f6499bc` | IMAP tagged OK with the wrong tag |
| P_F | 936 | `40d831f075` | POP3 STLS accepted after multiline CAPA |
| P_G | 1139 | `dd076b5e73` | POP3 STLS refused with -ERR |
| P_H | 903 | `cda89fe107` | SMTP on port 8025 |
| P_I | 817 | `369b80b1fc` | POP3 dialogue on port 143 |
| P_J | 751 | `cd35959940` | STARTTLS with no server response |
| P_K | 922 | `7b16ac76c0` | Server response missing (gap), then TLS bytes |
| P_L | 952 | `23bd81ba41` | 220 acceptance and ServerHello in one payload |
| P_M | 1604 | `4917793e6d` | AUTH LOGIN, two-round base64, no TLS |
| P_N | 1136 | `d0137d7710` | Fake plaintext AUTH after the boundary |
| P_O | 414 | `7caa198c31` | Port 993, truncated ClientHello |
| P_P | 1873 | `0319732812` | DATA body containing "STARTTLS" and a fake 220 |
| P_Q | 1279 | `44efedf2d0` | IMAP literal containing a fake STARTTLS exchange |
| P_R | 1570 | `08321ff8be` | POP3 RETR body containing "STLS" and a fake +OK |
| P_S | 1113 | `dfc4ebe01d` | Commands split across segments, CRLF split |
| P_T | 494 | `aead51c2c4` | Capture starting midstream |

Retransmission is exercised in P_A; out-of-order delivery in P_D; segmentation
including a split CRLF in P_S.

All addresses are RFC 5737 documentation ranges, hostnames use
`.example`/`.invalid`, and TLS records are synthetic byte structures. **No
fixture contains a real TLS handshake, a real certificate, or traffic from any
real system.** No Scapy operation that could trigger live ARP, NDP or DNS is
used: the passive guard from M1 is intact and still asserted by
`test_passive.py`.

---

## 6. A real CLI analysis

```
$ securemailscope analyze tests/fixtures/generated/p_a_smtp_starttls_accepted.pcap \
    --output out/m2-starttls.json

report       : /Volumes/Volume/Projects/securemailscope/out/m2-starttls.json
capture      : p_a_smtp_starttls_accepted.pcap
capture id   : sha256:51bd469b14ebf05448ce78d2d7c4726d56c85f4fd28df9d42e741a5c26a33512
format       : PCAP (little-endian)
packets      : 12 (12 TCP, 0 non-IP, 0 non-TCP, 0 malformed)
time range   : 2024-01-01T00:00:00+00:00 .. 2024-01-01T00:00:00.011000+00:00
sessions     : 1 (complete 0, partial 1, midstream 0, truncated 0)
reconstructed: 298 bytes, 0 gap(s), 0 overlap conflict(s)
protocols    : SMTP 1 confirmed, IMAP 0 confirmed, POP3 0 confirmed, 0 probable, 0 port-hint only, 0 unknown
tls upgrades : 1 advertised, 1 requested, 1 accepted, 0 rejected, 0 inconclusive; 1 with TLS bytes observed
tls handshake: NOT ANALYSED - handshake reconstruction, cipher suites and certificates are not implemented (M3)
  sess-16e403a0c629803a  192.0.2.10:49152 -> 198.51.100.25:25  PARTIAL *  c2s=83B s2c=215B  [SMTP/CONFIRMED]
      STARTTLS: TLS_BYTES_OBSERVED  boundaries client@31(FIRST_TLS_RECORD), server@166(SERVER_SUCCESS_REPLY_END)
warnings     : 1 (see the JSON report)
```

And the inconclusive case, reported honestly rather than optimistically:

```
$ securemailscope analyze tests/fixtures/generated/p_k_gap_during_upgrade.pcap -o out/m2-gap.json
reconstructed: 268 bytes, 1 gap(s), 0 overlap conflict(s)
tls upgrades : 1 advertised, 1 requested, 0 accepted, 0 rejected, 1 inconclusive; 0 with TLS bytes observed
  sess-54864ed7b19a6bb6  192.0.2.10:49152 -> 198.51.100.25:25  PARTIAL *  c2s=83B s2c=185B  [SMTP/CONFIRMED]
      STARTTLS: INCOMPLETE
```

TLS-framed bytes *are* present in that capture. The engine still refuses to
call the upgrade successful, because the response that would have accepted it
was never captured.

---

## 7. Sample JSON output (redacted by construction)

From `p_m_auth_before_tls.pcap`, a capture containing
`dummy-user@example.invalid`, `NotARealPassword123` and their base64 forms.
None of them appear anywhere below, or anywhere in the full report.

```json
{
  "protocol_inventory": {
    "analysed_session_count": 1,
    "confirmed_smtp_count": 1,
    "authentication_observation_count": 1,
    "authentication_before_upgrade_count": 1,
    "tls_handshakes_analysed": 0
  },
  "protocols": [{
    "session_id": "sess-aa1e7f8eb6cd4b6f",
    "detection": {
      "protocol": "SMTP",
      "status": "CONFIRMED",
      "evidence_status": "OBSERVED",
      "confidence_basis": "GREETING_AND_MATCHED_EXCHANGE",
      "explanation": "SMTP was identified from application payload: A conforming SMTP server greeting was parsed. 3 client command(s) matched the SMTP command grammar. 3 command(s) were matched to their server response in capture order.",
      "port_hint": "SMTP",
      "port_hint_agrees": true,
      "limitations": [
        "Only plaintext application traffic is parsed. Encrypted payload is never decoded.",
        "TLS handshake reconstruction, cipher suite and certificate analysis are not implemented (planned for M3)."
      ]
    },
    "parse_state": "COMPLETE",
    "authentication": [{
      "protocol": "SMTP",
      "command_verb": "AUTH",
      "mechanism": "LOGIN",
      "direction": "CLIENT_TO_SERVER",
      "stream_offset": 21,
      "packet_refs": [{"packet_number": 7,
                       "timestamp": "2024-01-01T00:00:00.006000Z",
                       "timestamp_ns": 1704067200006000000}],
      "occurred_before_tls_upgrade": true,
      "upgrade_state_at_attempt": "PLAINTEXT",
      "continuation_exchanges": 2,
      "credentials_recorded": false,
      "status": "OBSERVED",
      "limitations": [
        "No credential material is recorded: usernames, passwords, base64 tokens and SASL payloads are discarded during parsing.",
        "The attempt was observed in plaintext. Whether that is a finding is an M4 assessment question; this is an observation only."
      ]
    }],
    "events": [
      {"event_type": "AUTHENTICATION_CONTINUATION",
       "direction": "CLIENT_TO_SERVER",
       "stream_offset": 33, "end_offset": 71, "byte_count": 38,
       "detail": "A client SASL continuation response was observed and discarded. Its contents are credential material and are not recorded.",
       "limitations": ["Only the presence and size of the exchange are recorded; the payload is never decoded, stored or reported."]}
    ],
    "warnings": [{
      "code": "PLAINTEXT_AUTHENTICATION_OBSERVED",
      "message": "Observed a plaintext SMTP authentication command (AUTH) at CLIENT_TO_SERVER stream offset 21 with no accepted TLS upgrade in effect. No credential material was recorded.",
      "details": {"stream_offset": 21, "command_verb": "AUTH"}
    }]
  }]
}
```

The two continuation rounds are recorded as offsets and byte counts. The 38
bytes at offset 33 are the base64 username; the report says they existed and
how big they were, and nothing else.

---

## 8. M1 regression status

**No regression. No M1 behaviour changed.**

| Check | Result |
|---|---|
| All 168 M1 tests | pass, unmodified except one deliberate update (below) |
| M1 fixture capture hashes | **0 of 17 changed** — every M1 capture is byte-identical |
| M1 manifest diffs | +3/−1 lines per file: only the two new optional fields |
| `models/tcp.py` | unchanged |
| M1 reassembly, ingestion, sessions, seqspace modules | unchanged |
| `TCPSession.protocol_hint` | retained unchanged for backward compatibility |

### The one deliberate test change

`test_report.py::test_report_declares_stage_status_honestly` asserted
`EMAIL_PROTOCOL_PARSING == "NOT_IMPLEMENTED"`. That is now false, so the
assertion was updated to the new honest reality and extended to pin
`STARTTLS_DETECTION == IMPLEMENTED`, `TLS_RECORD_FRAMING == PARTIAL`,
`TLS_ANALYSIS == NOT_IMPLEMENTED` and schema `1.1.0`.

Its "no fabricated cryptography" check also changed, from a substring scan to
a **structural** one. The old check forbade the word `certificate` anywhere in
the document; M2's limitation prose legitimately contains it in order to say
certificate analysis is *not* implemented. The new check walks the JSON and
asserts no *key* named `cipher_suite`, `certificate`, `tls_version`,
`negotiated_cipher`, `subject`, `issuer` or `not_after` exists, and that every
upgrade reports `handshake_analyzed: false`. That is a stronger guarantee than
the substring scan it replaced.

### Schema evolution

`REPORT_SCHEMA_VERSION` 1.0.0 → **1.1.0**, backward compatible:

- Added: top-level `protocols` array and `protocol_inventory` object.
- Added: `STARTTLS_DETECTION` and `TLS_RECORD_FRAMING` to `stage_status`.
- Changed: `EMAIL_PROTOCOL_PARSING` and `PROTOCOL_HINTS` status values.
- **Unchanged:** every 1.0.0 field keeps its name, type and meaning. A 1.0.0
  consumer can ignore the new keys.

---

## 9. Security and privacy checks

| Check | Result |
|---|---|
| Staged-file audit | `check_staged.sh` → "no capture data, key material or environment files staged" |
| Captures / keys / `.env` / `out/` staged | none |
| Generated fixtures staged | none (still gitignored) |
| Dummy credentials in report output | absent — asserted per fixture |
| Dummy credentials in warnings and event details | absent — asserted field by field |
| Dummy credentials in CLI stdout/stderr | absent — asserted in `test_cli.py` |
| Unrecognised command tokens echoed | never — allowlist, asserted |
| Message bodies, literals, SASL payloads recorded | never — only byte counts |
| Email addresses recorded | never (P_P and P_R assert this) |
| Scapy passive guard | intact; `test_passive.py` still passes |
| Network access during analysis or tests | none; TShark test is opt-in and offline |
| New runtime dependencies | none — still `scapy` + `pydantic` |
| Repository author identity | unchanged, not modified |

---

## 10. Known limitations

### 10.1 A midstream capture loses capability context

If the `EHLO` was not captured, the `250` multiline reply answering it is
**not** treated as a capability advertisement, because there is no way to know
which command it answers. In fixture P_T the bytes `250-STARTTLS` are plainly
present, yet `UPGRADE_ADVERTISED` is absent and detection falls to `PROBABLE`.

This is deliberate conservatism, and it is the qualification on the "capability
advertisement" acceptance gate: advertisement is detected whenever the
command it answers was observed, and reported as absent when it was not.

### 10.2 The TShark cross-check has not been executed

The directive asks for comparison against an independent offline reference
"where available". TShark is **not installed** on this machine, so
`tests/test_tshark_crosscheck.py` is written, wired and skips cleanly — but it
has never been observed passing. No claim is made about agreement with TShark.

To run it: install TShark and `SECUREMAILSCOPE_TSHARK=1 make test`. Any
deviation found must be recorded here.

### 10.3 Other limitations

- **Three parsers run per session**, so parsing is O(3n) in dialogue length.
  No performance measurement has been taken and none is claimed.
- **No fixture combines a protocol dialogue with an overlap conflict.** The
  reader's ambiguity handling is unit-tested directly but not end to end.
- **SMTP `BDAT`/CHUNKING bodies are not skipped** — only dot-terminated `DATA`.
- **IMAP `COMPRESS=DEFLATE` is not handled**; a compressed stream would not
  parse.
- **SASL semantics are not interpreted.** Mechanism names are recorded when
  recognised; the exchange itself is counted, never decoded.
- **Duplicate vs retransmission** remains an M1 inference (see M0-M1 report).
- **An accepted upgrade is not encryption.** `TLS_BYTES_OBSERVED` means only
  that TLS-framed bytes followed. No handshake, version, cipher suite or
  certificate is analysed, and `handshake_analyzed` is always `false`.

---

## 11. Git and remote status

| Item | Value |
|---|---|
| Files changed | 71 (36 added, 35 modified) |
| Lines | +8,793 / −112 |
| Branch | `main` |
| Remote | `https://github.com/sgtsujith141-wq/securemailscope` (**PRIVATE**) |
| Commit SHA | `49bdb12b764e2a1d3f0aef8faf4fe407b0105c30` |

Push verified: `fe3e0d1..49bdb12  main -> main`, exit 0.
Local HEAD and remote HEAD both `49bdb12b764e2a1d3f0aef8faf4fe407b0105c30`.
The published tree was audited afterwards: 126 files, zero matches for capture,
key, environment, venv or analysis-output patterns.

---

## 12. M3 readiness

M2 was built so that M3 receives a well-defined hand-off rather than having to
re-derive it:

1. **Exact starting offsets.** `TLSBoundary` gives each direction's transition
   point and the basis for it. M3 begins record parsing there.
2. **Bytes already located.** `TLSUpgradeAttempt.tls_records` carries the
   offsets, lengths, content types and packet references of the records M2
   validated — including records that shared a TCP payload with the acceptance
   reply, which are preserved rather than discarded.
3. **Implicit TLS sessions identified.** `ImplicitTLSObservation` marks
   sessions that are TLS from byte zero, with no plaintext phase to skip.
4. **Uncertainty already propagated.** `INCOMPLETE` upgrades, truncated
   records and gap-interrupted negotiations are flagged, so M3 knows which
   streams it must not attempt to parse continuously.
5. **The contract is reserved.** `handshake_analyzed`,
   `handshake_analysis_status` and `negotiated_parameters_available` exist and
   are constants now; M3 fills them in without a schema break.

Recommended M3 scope, in order:

1. TLS record layer over `payload_runs()`, stopping at gaps rather than
   guessing across them.
2. Handshake message reassembly across records.
3. `ClientHello` / `ServerHello` parsing: offered and selected versions,
   cipher suites, supported groups, signature algorithms, ALPN, SNI.
4. Certificate extraction for **TLS 1.2 and earlier only**, with TLS 1.3
   certificate fields reported `NOT_AVAILABLE` — never `UNKNOWN`, never
   omitted.
5. Correlation with the M2 boundaries so a finding can say "this connection
   advertised STARTTLS, upgraded at client offset 31, and negotiated X".
6. Fixtures with real-shaped handshakes, including a TLS 1.3 session that
   proves the certificate is correctly reported as unavailable.

**M3 was not started.** No TLS parsing, handshake reconstruction or
certificate handling exists in this milestone.
