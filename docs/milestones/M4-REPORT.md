# M4 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M4 — Evidence-based security rules, explainable scoring, threat prioritisation and remediation
- **Baseline (M3):** `765203e29d3aac5e1bd2cb57b92f103c72466e03`
- **Commit:** `5518ccbeb2b41cc75942d71be85372b63882d0b3`
- **Result:** **COMPLETE** — all 12 acceptance gates pass.

The TShark cross-check, reported `NOT_VERIFIED` in both M2 and M3, was
**executed in this milestone and passes**. See §7.

---

## 1. Pre-implementation verification

| Claim | Actual |
|---|---|
| Branch | `main` |
| Local HEAD == remote HEAD | both `765203e29d3aac5e1bd2cb57b92f103c72466e03` |
| Working tree | clean |
| Test suite at baseline | `677 passed, 24 skipped` |
| Lint / types | ruff clean; mypy clean over 82 files |

No history was rewritten and no force-push was performed. The remote is the
existing private repository; no repository was created, renamed or deleted.

---

## 2. What was built

Four **independent** analytical layers on top of the unchanged M1–M3 forensic
output:

```
          forensic observations (M1-M3, byte-identical with or without M4)
                                 |
        +------------------ rule evaluation ------------------+
        |  25 rules x each session -> FAIL/PASS/UNKNOWN/N.A.  |
        |  de-duplication: one weakness -> one charged unit   |
        +-----------------------------------------------------+
             |                   |                   |
             v                   v                   v
        posture scoring    prioritisation      remediation
```

Scoring never reads the priority order; prioritisation never reads the score;
remediation walks the findings that were **raised**, never the rules that might
have fired. Each is testable in isolation, and a defect in one cannot silently
corrupt another.

### Files created

| File | Lines | Purpose |
|---|---|---|
| `src/securemailscope/models/assessment.py` | 387 | 21 data contracts: outcomes, severity, confidence, findings, scores, coverage |
| `src/securemailscope/assessment/policy.py` | 478 | The versioned policy: thresholds, weights, approved/prohibited algorithms, rationale, fingerprint |
| `src/securemailscope/assessment/catalog.py` | 868 | 25 `RuleDefinition` and 12 `Remediation` entries with typed citations |
| `src/securemailscope/assessment/rules.py` | 1,207 | The 25 evaluators |
| `src/securemailscope/assessment/evaluator.py` | 185 | Rule execution, de-duplication, finding identifiers |
| `src/securemailscope/assessment/scoring.py` | 303 | Scoring units, the formula, coverage |
| `src/securemailscope/assessment/prioritization.py` | 159 | The severity × confidence matrix and the deterministic sort |
| `src/securemailscope/assessment/remediation.py` | 43 | Catalogue selection from raised findings |
| `src/securemailscope/assessment/engine.py` | 155 | Per-session and per-capture orchestration |
| `src/securemailscope/testing/assessment_fixtures.py` | 528 | Fixtures AA–AC with hand-computed expectations |
| `scripts/generate_policy_docs.py` | 301 | Generates the policy and remediation documents from the code |
| `tests/test_assessment.py` | 1,036 | 225 tests |
| `docs/security-policy.md` | 417 | Generated |
| `docs/scoring-methodology.md` | 251 | The formula, its properties, and what the score is not |
| `docs/remediation-catalog.md` | 399 | Generated |

### Files modified

`models/analysis.py` (schema 1.2.0 → **1.3.0**, additive; five new stages),
`config.py`, `pipeline.py`, `cli.py`, `reporting/json_report.py`,
`testing/manifest.py`, `testing/fixtures.py`, `tests/conftest.py`, and the
five existing documents.

---

## 3. The rules

25 rules across the five required categories. The full table, with every
weight, threshold, de-duplication group and typed standards citation, is in
[security-policy.md](../security-policy.md).

| Category | Rules | Range |
|---|---|---|
| A — TLS protocol version | 3 | `TLS-PROTO-001..003` |
| B — Cipher suite | 6 | `TLS-CIPHER-001..006` |
| C — Key exchange and forward secrecy | 2 | `TLS-KEX-001..002` |
| D — Certificate | 7 | `CERT-001..007` |
| E — Email transport | 7 | `MAIL-001..007` |

Every rule distinguishes all four outcomes, cites at least one standard typed
as `PROTOCOL_REQUIREMENT`, `STANDARDS_RECOMMENDATION`, `PROJECT_POLICY` or
`ENVIRONMENT_CHOICE`, and produces a finding only on `FAIL`.

### One weakness, one finding

Rules sharing a de-duplication group describe one underlying weakness. The most
severe failing member carries the unit; the rest are reported with
`counts_toward_score: false` and never become findings. Fixture `AB` exists to
demonstrate this: a NULL cipher fails both `TLS-CIPHER-001` (CRITICAL) and
`TLS-CIPHER-005` (MEDIUM), and produces exactly one finding and one deduction
of 10.

### Algorithm ownership

A defect found during fixture verification: `PROHIBITED_ENCRYPTION` in the
policy and a private `_BROKEN_ENCRYPTION` set in `rules.py` had drifted apart,
and only the private one was consulted. The policy is now the single source:
each prohibited algorithm names the one rule that owns it, and `rules.py`
derives its sets from that table. A published policy that disagrees with the
engine would have sent a reader to check the wrong thresholds.

---

## 4. Scoring

```
coverage = W(evaluated) / W(applicable)
score    = 100 * (W(evaluated) - W(failed)) / W(evaluated)
```

`UNKNOWN` units appear in the coverage fraction and **nowhere in the score**.
If they scored as passes, a capture showing nothing would score 100; if they
scored as failures, a truncated capture would look like a misconfigured server.
Excluding them from both sides makes the score a statement about what was
actually checked, and makes coverage the separate statement about how much that
was.

Below the coverage floor (default 0.50) the status is `SCORE_UNAVAILABLE` and
the score is `null`. Refusing to produce a number is a feature: a capture with
only a ClientHello reaches 4.3% coverage, and printing "100" beside it would be
actively misleading.

All ten properties — range, monotonicity, no double counting, determinism,
auditability — are stated with their proofs in
[scoring-methodology.md](../scoring-methodology.md) and each is asserted by a
named test.

### The score is a project-defined metric

Stated in the report itself, in the policy block's `limitations`, not only in
prose: **the posture score is a transparent, project-defined analytical metric,
not an independently validated measure of enterprise-wide security.** The
weights and band boundaries are ordering judgements chosen by this project,
documented with their rationale, and fully configurable.

Fixture `AC_rc4_weak_cipher` is kept deliberately: it scores 70 (`ADEQUATE`)
while negotiating RC4, because its certificate handling is sound and the score
averages across the session rather than reporting its worst moment. The RC4
finding sits at P1 in the same report. **The findings are the substance; the
score is a reading aid.**

---

## 5. Prioritisation and remediation

Priority comes from a **matrix**, never a product:

| Severity \ Confidence | CONFIRMED | PROBABLE | LOW |
|---|---|---|---|
| **CRITICAL** | P1 | P1 | P2 |
| **HIGH** | P1 | P2 | P3 |
| **MEDIUM** | P2 | P3 | P3 |
| **LOW** | P3 | P4 | P4 |
| **INFO** | P4 | P4 | P4 |

Multiplying severity by a confidence percentage would invent precision a packet
capture does not measure, and would collapse two different questions — "how bad
is it" and "how sure are we" — into one number, after which a reader could no
longer tell which had driven the ranking.

Ordering within a band uses a published sort key:
`(severity, confidence, asset criticality, -sessions observed, rule id, finding id)`.
Asset criticality is **operator-supplied and never inferred**; unlabelled assets
sort last within their band.

Remediation walks the raised findings, so advice is never produced for a rule
that merely might have failed or that returned `UNKNOWN`. All 12 entries are
vendor-neutral and carry validation steps. No remediation is applied, no
connection is made, and no projected post-fix score exists in any model.

---

## 6. Fixtures

Three new fixtures, each with a manifest specifying exact rule outcomes,
findings with severity/confidence/priority/rank, full score arithmetic,
coverage and remediations. **Every number was computed by hand from the policy
weights before the engine was run against the fixture**, and the working is
written out in each fixture's docstring.

| Fixture | Negotiated | Score | Coverage | Findings |
|---|---|---|---|---|
| `AA_tls10_static_rsa_multiple_findings` | TLS 1.0, `TLS_RSA_WITH_AES_128_CBC_SHA` | 59 `WEAK` | 0.7551 | 4 |
| `AB_null_cipher_duplicate_evidence` | TLS 1.2, `TLS_RSA_WITH_NULL_SHA256` | 64 `WEAK` | 0.7857 | 2 |
| `AC_rc4_weak_cipher` | TLS 1.2, `TLS_RSA_WITH_RC4_128_SHA` | 70 `ADEQUATE` | 0.7692 | 2 |

The remaining cases in the M4 fixture matrix reuse M1–M3 fixtures rather than
duplicating them; the mapping is in
[test-strategy.md](../test-strategy.md#assessment-fixtures-m4).

### What hand-derivation caught

Three predictions disagreed with the engine. Investigating each was the point
of deriving them independently:

1. **`TLS-CIPHER-003` passes on a NULL cipher.** Predicted `FAIL`. The engine
   is right: `TLS-CIPHER-001` owns NULL, and reporting it twice would charge
   one setting under two headings. The manifest was corrected — and this is
   what surfaced the policy/rules drift described in §3.
2. **An unrecognised cipher suite is `UNKNOWN`, not a finding.** Predicted a
   `FAIL` at INFO. The engine is right: absence from *our* registry is a gap in
   this build, not a property of the transport, and the directive forbids
   generating a finding solely because an observation is unavailable.
3. **Per-session tallies under-reported suppressed duplicates.** A real bug:
   `suppressed_duplicates` was set on the capture-wide tally but left at 0 on
   each session's own score, which is read on its own. Fixed in `engine.py`.

---

## 7. Test results

All commands were executed; the output below is what they produced.

```
$ pytest -q
902 passed, 25 skipped in 25.37s

$ SECUREMAILSCOPE_TSHARK=1 pytest -q
910 passed, 15 skipped in 35.72s

$ ruff check src tests scripts
All checks passed!

$ mypy src/securemailscope/
Success: no issues found in 83 source files
```

The 15 remaining skips are fixtures that carry no credential material, which
the credential-absence test correctly skips.

### TShark cross-check — executed, and now passing

TShark was written into the suite in M2 and reported **NOT_VERIFIED** in both
M2 and M3 because it was not installed. It was installed in this milestone
(`brew install wireshark`, TShark 4.6.8) with the user's authorisation, and all
checks were executed.

**Result: 10 of 10 pass.** Running them found three defects — **all three in
the checks, none in the engine**:

| Check | Defect | Resolution |
|---|---|---|
| SMTP `STARTTLS` | Filtered on `smtp.req.command == "STARTTLS"`; Wireshark tokenises SMTP commands as a four-character verb plus a parameter, dissecting command `STAR`, parameter `TLS` | Filter corrected; the tokenisation difference is documented. Both tools agree the request was in frame 7, which is the fact under comparison |
| Cipher suite | Parsed TShark's output as decimal; TShark prints `0xc02b` | Parsed as hex |
| Certificate | Read `x509sat.printableString`; the synthetic CA encodes the common name as UTF-8 | Switched to `x509af.version`, independent of ASN.1 string encoding |

No disagreement about a protocol fact was found. An extra check was added
comparing the negotiated version and cipher suite of all three assessment
fixtures against TShark, since every finding they produce rests on those two
values.

This is genuine independent agreement on the facts compared. It is agreement on
a **sample** — packet counts, stream counts, protocol identification, TLS
version, cipher suite, certificate dissection — not on the whole report, and no
wider claim is made.

### False-positive prevention

Thirteen explicit tests, one per case in the directive, each asserting that
unsupported findings are **absent**:

| Case | Asserted |
|---|---|
| TLS 1.3 encrypted certificate | No `CERT-00x` finding; all seven `UNKNOWN`/`NOT_APPLICABLE` |
| Missing ClientHello | `TLS-PROTO-002` `UNKNOWN`, no finding |
| Missing ServerHello | Five negotiation rules `UNKNOWN`; offered suites never judged as negotiated |
| Truncated captures | Three fixtures; no cipher verdict reached from truncated bytes |
| Unknown cipher suite | Five cipher rules `UNKNOWN`; no cipher finding at all |
| Unknown key-exchange group | No forward-secrecy finding |
| Incomplete chain | `CERT-005` `UNKNOWN` without a trust store |
| Missing trust store | `CERT-005` `UNKNOWN` across three fixtures |
| Missing reference hostname | `CERT-006` `UNKNOWN` across three fixtures, every session |
| TLS 1.3 PSK vs ephemeral | No forward-secrecy finding on a resumed session |
| Rejected STARTTLS | No attack language; the innocent explanation is stated |
| Authentication without disclosure | `MAIL-001` fires; no credential string reaches the output |
| Port hints | All six `MAIL-00x` rules `NOT_APPLICABLE` on implicit TLS |

---

## 8. Evidence sample

Policy block:

```json
{
  "policy_id": "securemailscope-default",
  "policy_version": "1.0.0",
  "policy_fingerprint": "a9f912f235f1",
  "minimum_tls_version": "0x0303",
  "minimum_coverage_for_score": 0.5,
  "assessment_mode": "HISTORICAL"
}
```

Highest-priority finding from fixture `AA`:

```json
{
  "finding_id": "find-36217459a78b25e5",
  "rule_id": "TLS-KEX-001",
  "rank": 1,
  "priority": "P1",
  "severity": "HIGH",
  "confidence": "CONFIRMED",
  "observed_session_count": 1,
  "asset_criticality": null,
  "explanation": "P1 from severity HIGH, confidence CONFIRMED, no asset criticality was supplied, observed in 1 session(s) in this capture. Severity, confidence and priority are reported separately and are never combined into a risk probability.",
  "sort_key": [1, 0, 4, -1, "TLS-KEX-001", "find-36217459a78b25e5"]
}
```

The deduction detail for the same capture, which sums to `weighted_deductions`:

```
FORWARD_SECRECY: -6 (TLS-KEX-001, HIGH)
NEGOTIATED_PROTOCOL_VERSION: -6 (TLS-PROTO-001, HIGH)
NEGOTIATED_CIPHER_SUITE: -3 (TLS-CIPHER-005, MEDIUM)
```

### Policy fingerprint

Finding identifiers incorporate a digest of the policy id, version and **every
applied override**. A policy version alone does not identify the criteria a
finding was reached under: an operator who raises `minimum_rsa_bits` on the
command line is evaluating a different standard while still running policy
`1.0.0`. Without the fingerprint, two reports produced under different criteria
would share identifiers and a diff between them would silently compare unlike
things. This was found by a test whose premise was initially wrong, and fixing
it properly was the right resolution.

---

## 9. CLI

The `analyze` command gained five flags, all additive:

```
--no-rule-results                     omit passing/unknown results, keep findings
--no-assessment                       forensic output only
--policy-reference-time {capture,current}
--disable-rules IDS
--minimum-score-coverage PERCENT
```

`--policy-reference-time` replaced an earlier `--assess-at-current-time`, which
was near-identical to M3's existing `--assess-current-time` while doing
something different. Two flags a letter apart with different meanings is a
defect; the M3 flag is published, so the new one was renamed.

The JSON report adds `assessment` containing `policy`, `sessions` (with
`rule_results`), `findings`, `prioritised_findings`, `remediations`,
`posture_score`, `coverage` and `tally`. Every M1–M3 block is present and
unchanged, which `--no-assessment` demonstrates directly. No PDF or HTML report
was built; those belong to M7.

---

## 10. Known limitations

Beyond the permanent limits in [limitations.md](../limitations.md):

- **The score summarises; it does not rank by worst finding.** `AC` scores
  `ADEQUATE` while negotiating RC4. This is documented, fixtured and
  deliberate, but a reader who looks only at the band will be misled. The
  findings list is the substance.
- **Nothing is concluded about configurations that were not exercised.** A
  server that negotiated TLS 1.2 here may also accept TLS 1.0. Passive capture
  shows what was *chosen*, never what was *available*.
- **`observed_session_count` counts within one capture.** There is no
  cross-session or cross-capture correlation; that is M5.
- **Chain and identity are `UNKNOWN` by default.** They become real checks only
  when `--trust-store` and `--expected-server-identity` are supplied.
- **The weights have not been validated against anything.** They are ordering
  judgements with documented rationale, and they are configurable.
- **No performance measurement.** 25 rules × each session adds work that has
  not been benchmarked, and no throughput figure is claimed.

---

## 11. Acceptance gates

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Deterministic security rules work | **PASS** | 225 tests in `test_assessment.py`; repeated runs byte-identical |
| 2 | Rules distinguish FAIL, PASS, UNKNOWN, NOT_APPLICABLE | **PASS** | All four reachable and asserted per fixture manifest |
| 3 | Every finding has valid evidence | **PASS** | `test_every_finding_cites_a_real_packet` — in range and matching the manifest's recorded timestamps |
| 4 | TLS 1.2 and TLS 1.3 differences respected | **PASS** | `test_tls13_encrypted_certificate_is_not_a_certificate_failure`; TLS 1.3 version read from `supported_versions` only |
| 5 | Certificate validation statuses handled correctly | **PASS** | Five independent fields; missing trust store and missing identity both `UNKNOWN` |
| 6 | Email transport findings reflect actual observations | **PASS** | `MAIL-00x` `NOT_APPLICABLE` on port hints; `MAIL-001` fires only on observed plaintext AUTH |
| 7 | Scoring methodology documented and tested | **PASS** | [scoring-methodology.md](../scoring-methodology.md); ten properties, each with a named test |
| 8 | Unknown evidence cannot improve a score | **PASS** | `test_unknown_evidence_cannot_improve_the_score` |
| 9 | Insufficient evidence produces `SCORE_UNAVAILABLE` | **PASS** | `test_insufficient_evidence_produces_no_score` |
| 10 | Prioritisation is deterministic | **PASS** | `test_prioritisation_is_a_total_order`, `test_prioritisation_is_stable_across_runs` |
| 11 | Remediation maps only to raised findings | **PASS** | `test_remediations_answer_findings_that_exist` |
| 12 | Schema additive; credentials redacted | **PASS** | `test_schema_is_additive_over_m1_to_m3`; `test_no_credential_material_reaches_the_assessment` over five fixtures |

---

## 12. Regression status

| Milestone | Status |
|---|---|
| M1 — ingestion and TCP reconstruction | All tests pass unchanged |
| M2 — email protocol and STARTTLS | All tests pass unchanged |
| M3 — TLS and certificates | All tests pass unchanged |

Five M1–M3 test assertions were updated for the schema bump (1.2.0 → 1.3.0) and
the new stage statuses. No forensic behaviour changed. Three engine changes were
made in M4 beyond the new package: the policy/rules algorithm-ownership fix, the
per-session suppressed-duplicate tally, and the policy fingerprint in finding
identifiers — all described above.

---

## 13. Readiness for M5

M5 is cross-session evidence correlation. The assessment layer leaves it a
clean seam:

- `AnalysisStage.EVIDENCE_CORRELATION` exists and is `NOT_IMPLEMENTED`, so
  reports already say "not looked for" rather than "not found".
- `PrioritisedFinding.observed_session_count` is populated and documented as
  within-capture only; correlation widens it without changing its meaning.
- Findings carry stable identifiers bound to their policy criteria, which is
  what makes correlating them across captures meaningful.

No M5, M6 or M7 work was started.
