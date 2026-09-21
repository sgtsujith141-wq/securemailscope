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

### M3 TLS and certificate fixtures

Two generation methods, kept clearly distinct because they buy different
things and have different reproducibility.

**Locally negotiated (A-F)** -- real OpenSSL handshakes produced through
`ssl.MemoryBIO` pairs. No socket is created and no capture privilege is
needed: the client and server exchange bytes in memory. These test the parser
against what a real implementation actually emits. TLS randoms and ephemeral
key shares make them non-reproducible, so their manifests record **no capture
hash** and assert negotiated parameters instead.

**Synthetically constructed (G-Z)** -- messages assembled byte by byte from
the RFC structures. This is the only way to produce a record split at a chosen
boundary, a truncated record, a hole mid-handshake, or bytes two segments
disagree about. Fixtures whose certificates come from the synthetic CA inherit
ECDSA's randomised signatures and are also non-reproducible; the purely
structural ones assert a capture hash.

| Fixture | Method | Principally verifies |
|---|---|---|
| T_A | live | Complete TLS 1.2 flight; certificate extracted |
| T_B | live | TLS 1.2 ECDHE; group from ServerKeyExchange, not from client offers |
| T_C | live | Static RSA key exchange ⇒ `STATIC_RSA_KEY_EXCHANGE`, no ServerKeyExchange |
| T_D | live | TLS 1.3 version from `supported_versions`, not `legacy_version` |
| T_E | live | TLS 1.3 certificate is `ENCRYPTED_TLS13`, not a failure |
| T_F | live | TLS 1.3 PSK resumption; no new certificate is not an error |
| T_G | synthetic | ClientHello only ⇒ selected version and suite stay UNKNOWN |
| T_H | synthetic | ServerHello without ClientHello (midstream) |
| T_I | synthetic | One record across three TCP segments |
| T_J | synthetic | One handshake message across several records |
| T_K | synthetic | Four messages in one record |
| T_L | synthetic | Truncated record reported, framing stops |
| T_M | synthetic | Missing segment ⇒ `ALIGNMENT_LOST_AT_GAP` |
| T_N | synthetic | Conflicting overlapping bytes ⇒ not interpreted |
| T_O | synthetic | Expired at capture time |
| T_P | synthetic | Not yet valid at capture time |
| T_Q | synthetic | Self-signed: a fact, not a verdict |
| T_R | synthetic | Valid chain; verifies only with a configured anchor |
| T_S | synthetic | Incomplete chain distinguished from invalid |
| T_T | synthetic | Hostname match, wildcard match and mismatch |
| T_U | synthetic | SNI present but not an authorised expectation |
| T_V | synthetic | Implicit TLS on an email port |
| T_W | synthetic | STARTTLS then an observable handshake |
| T_X | synthetic | Upgrade accepted, ClientHello never captured |
| T_Y | synthetic | Malformed certificate lengths ⇒ safe failure |
| T_Z | synthetic | Fatal alert ⇒ aborted, not negotiated |
| T_HRR | synthetic | HelloRetryRequest is not a ServerHello; TLS 1.3 compat CCS is not TLS 1.2 |

### Assessment fixtures (M4)

Three configurations the local OpenSSL will not negotiate at any security
level, so all three are assembled byte by byte from the RFC structures. Each
carries a manifest with hand-computed expected outcomes, findings, score
arithmetic, coverage and remediations.

| Fixture | Negotiated | Principally verifies |
|---|---|---|
| AA | TLS 1.0, `TLS_RSA_WITH_AES_128_CBC_SHA` | An obsolete *negotiated* version; several independent findings in one session; score 59 / `WEAK` at 0.7551 coverage |
| AB | TLS 1.2, `TLS_RSA_WITH_NULL_SHA256` | Duplicate evidence for one weakness: two cipher rules, one de-duplication group, one finding, one deduction; score 64 |
| AC | TLS 1.2, `TLS_RSA_WITH_RC4_128_SHA` | A prohibited stream cipher; score 70 / `ADEQUATE`, kept deliberately to show what the score is and is not |

The remaining cases in the M4 fixture matrix reuse M1–M3 fixtures rather than
duplicating them: secure TLS 1.2 (`T_A`), TLS 1.3 with an encrypted certificate
(`T_D`, `T_E`), static RSA (`T_C`), ephemeral key exchange (`T_A`, `T_B`),
expired and not-yet-valid certificates (`T_O`, `T_P`), chain and hostname
failures (`T_S`, `T_T`), missing validation evidence (`T_R`), insufficient
evidence for scoring (`T_G`), plaintext authentication (`P_M`), a rejected
`STARTTLS` (`P_B`, `P_G`) and an incomplete upgrade (`P_J`, `P_K`).

### Certificates and keys are never committed

The synthetic CA creates a fresh key pair in-process at fixture-build time.
Certificates and keys are written only into temporary directories, and the
public root is emitted next to the generated captures (also gitignored) so
chain verification can be demonstrated. **No private key material exists
anywhere in the repository** -- only the code that generates it.

No fixture contains a real TLS handshake against a real server, a real
certificate, or traffic from any real system. The TLS records in
P_A, P_C, P_D, P_F, P_L, P_N, P_O, P_S and P_T are synthetic, structurally
valid record/handshake headers built byte by byte
(`securemailscope.testing.tls_blobs`) so the framing detector has something
genuine to validate. They carry no cryptographic meaning, and nothing in the
suite claims a handshake was analysed.

## The assessment layer (M4)

The assessment tests divide into two halves, and the second is the one that
matters most.

**Findings that must exist.** Three new fixtures (`AA`, `AB`, `AC`) carry
manifests specifying the exact outcome of every rule, every finding with its
severity, confidence, priority band and rank, the full score arithmetic and the
remediation list. Every number in them was **computed by hand** from the policy
weights before the engine was run against the fixture; the working is written
out in each fixture's docstring in
`src/securemailscope/testing/assessment_fixtures.py` so a reviewer can check it
without executing anything. Nothing recomputes an expectation using the code
under test, so a change in the scoring implementation fails a test rather than
redefining the answer.

**Findings that must NOT exist.** Thirteen explicit false-positive tests, one
per case in the M4 directive: TLS 1.3 encrypted certificates, missing
ClientHello, missing ServerHello, truncated captures, unknown cipher suites,
unknown key-exchange groups, incomplete chains, missing trust stores, missing
reference hostnames, PSK-versus-ephemeral negotiation, STARTTLS rejection,
authentication detected without credential disclosure, and port hints without a
confirmed protocol. Each asserts that unsupported findings are **absent**.

The asymmetry is deliberate. Asserting an expected finding exists proves a rule
fires. Only asserting that an unsupported finding does not exist proves it does
not fire on evidence that never established the weakness — and inventing a
weakness is the failure mode that costs an operator real time.

Three defects in the M4 fixture expectations were found this way, before the
fixtures were committed: `TLS-CIPHER-003` correctly passes on a NULL cipher
because `TLS-CIPHER-001` owns that algorithm; an unrecognised cipher suite is
`UNKNOWN` rather than a finding; and per-session tallies were under-reporting
suppressed duplicates. The first two were wrong predictions and the manifests
were corrected; the third was a real bug in `engine.py` and was fixed.

### Generated documents are tested

`docs/security-policy.md` and `docs/remediation-catalog.md` are generated from
the policy and catalogue by `scripts/generate_policy_docs.py`, and
`test_the_generated_policy_documents_are_current` asserts the committed files
match what the generator produces. A policy document that disagrees with the
engine is worse than no document, because a reader would check the wrong
thresholds. `test_the_requirements_matrix_summary_is_arithmetically_correct`
likewise re-counts the requirements matrix against its own summary table.

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
| `test_tls.py` | Manifest-driven M3: records, messages, version, cipher, key exchange, forward secrecy, certificates, validation |
| `test_tls_validation.py` | Chain and hostname verification under different configurations, capture-time dates, TLS 1.3 limits, bounds, no-socket guarantee |
| `test_assessment.py` | M4: manifest-driven rule outcomes, findings and scores; evidence linkage; finding identifiers; scoring and coverage arithmetic; prioritisation; remediation mapping; duplicate suppression; thirteen false-positive cases; schema compatibility; redaction; CLI; determinism; generated-document freshness |
| `test_tshark_crosscheck.py` | Cross-validation against an independent dissector (optional; executed and passing against TShark 4.6.8) |

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

## Cross-validation against TShark

`test_tshark_crosscheck.py` compares packet counts, TCP stream counts,
SMTP/IMAP/POP3 dissection, TLS version, cipher suite and certificate
dissection against TShark. It is **skipped unless** `tshark` is on `PATH`
*and* `SECUREMAILSCOPE_TSHARK=1` is set, so an ordinary test run has no
external dependency. TShark is invoked strictly offline (`-r` on a local file,
`-n` to disable name resolution).

```bash
SECUREMAILSCOPE_TSHARK=1 make test   # with tshark installed
```

**Executed in M4 against TShark (Wireshark) 4.6.8: all 10 checks pass.** They
had been written but never run through M2 and M3, and were reported as
`NOT_VERIFIED` in both milestone reports. Running them found three defects —
all three in the *checks*, none in the engine:

| Check | What was wrong | Resolution |
| --- | --- | --- |
| SMTP `STARTTLS` | The filter looked for `smtp.req.command == "STARTTLS"`. Wireshark tokenises SMTP commands as a four-character verb plus a parameter, so it dissects command `STAR`, parameter `TLS`. | Filter corrected; the tokenisation difference is documented in the test. Both tools agree on which frame carried the request, which is the fact under comparison. |
| Cipher suite | The check parsed TShark's output as decimal; TShark prints `0xc02b`. | Parsed as hex. |
| Certificate | The check read `x509sat.printableString`; the synthetic CA encodes the common name as a UTF-8 string. | Switched to `x509af.version`, which does not depend on the ASN.1 string encoding the issuer chose. |

No disagreement about a protocol fact was found. An eleventh check was added in
M4 comparing the negotiated version and cipher suite of the three assessment
fixtures, since every finding they produce rests on those two values.

Any deviation found in future must be recorded in the milestone report rather
than worked around.

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
- ~~The TShark cross-check has not been executed~~ — **closed in M4.** TShark
  4.6.8 was installed and all 10 checks were executed and observed passing.
  See *Cross-validation against TShark* above. The checks remain optional, so
  a machine without TShark still skips them cleanly.
- The cross-check compares a sample of facts, not the whole report. Agreement
  on packet counts, stream counts, protocol identification, TLS version,
  cipher suite and certificate dissection is not agreement on everything, and
  no such claim is made.
- TLS fixtures built from live OpenSSL depend on the local library's
  defaults. The TLS 1.3 fixtures assert the suite OpenSSL itself reports
  negotiating, which is an independent cross-check on our parse of the
  ServerHello rather than a copy of our own output, but a different OpenSSL
  build may negotiate a different suite or group.
- Static RSA key exchange is only exercised while the local OpenSSL still
  offers `kRSA` at `@SECLEVEL=0`. The generator detects that and falls back to
  a constructed handshake, which is recorded in the fixture's `generation`
  field.
- No fixture yet combines a protocol dialogue with an overlapping-segment
  conflict. The reader's ambiguity handling is unit-tested directly
  (`test_bytes_from_an_overlap_conflict_are_flagged_ambiguous`) but not end to
  end from a capture.
- Running three parsers per session is O(3n) in dialogue length. No
  performance measurement has been taken, and none is claimed.
