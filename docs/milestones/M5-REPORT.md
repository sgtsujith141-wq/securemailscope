# M5 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M5 — Cryptographic DNA, drift, cross-session correlation, evidence timeline and blast radius
- **Baseline (M4):** `5cde1fd618bc84f09d5622dbbb37eece7d41f939`
- **Commit:** `aa6efeb0da78abaf019640486af8d1ae6281f2f1`
- **Result:** **COMPLETE** — all 16 acceptance gates pass.

---

## 1. Baseline audit

| Claim | Actual |
|---|---|
| Branch | `main` |
| Local HEAD == remote HEAD | both `5cde1fd618bc84f09d5622dbbb37eece7d41f939` |
| Working tree | clean |
| Test suite at baseline | `902 passed, 25 skipped` (`912 passed` with TShark) |
| Lint / types | ruff clean; mypy clean over 83 files |
| `intelligence/` | a docstring only, marked NOT IMPLEMENTED |

The directive's reported baseline — implementation `5518ccb`, report HEAD
`5cde1fd` — is confirmed correct. No history was rewritten, no force-push was
performed, and no repository other than this one was touched.

---

## 2. Files changed

**27 files changed, +6,368/−32** (15 new).

### Created

| File | Lines | Purpose |
|---|---|---|
| `src/securemailscope/models/intelligence.py` | 491 | 23 contracts: fingerprints, entities, drift, correlation, timeline, blast radius |
| `src/securemailscope/intelligence/fingerprints.py` | 368 | Versioned canonical digests with explicit completeness |
| `src/securemailscope/intelligence/identity.py` | 280 | Endpoint entities and typed relationships; merges nothing |
| `src/securemailscope/intelligence/drift.py` | 385 | Cross-capture comparison with client-offer context |
| `src/securemailscope/intelligence/correlation.py` | 263 | Indexed grouping by shared observation |
| `src/securemailscope/intelligence/timeline.py` | 132 | Deterministic ordering anchored to packets |
| `src/securemailscope/intelligence/blast_radius.py` | 101 | Observed-scope counting with stated method |
| `src/securemailscope/intelligence/engine.py` | 700 | Batch orchestration, de-duplication, assembly |
| `src/securemailscope/testing/investigation_fixtures.py` | 869 | 15 fixture groups with hand-derived expectations |
| `tests/test_intelligence.py` | 1,225 | 210 tests |
| `docs/cryptographic-fingerprinting.md` | 151 | Schema, algorithm version, completeness rules |
| `docs/drift-methodology.md` | 120 | Comparison rules and why each refusal exists |
| `docs/correlation-methodology.md` | 98 | Assumptions and false-positive prevention |
| `docs/blast-radius-methodology.md` | 91 | Counting methodology |

### Modified

`models/certificates.py` and `certificates/parse.py` (the SPKI fingerprint),
`testing/certs.py` (`reissue`), `config.py` (five batch limits),
`cli.py` (`analyze-batch`), `reporting/json_report.py`
(`investigation_to_dict`), and the five existing documents.

---

## 3. Features implemented

### Multi-capture analysis

`securemailscope analyze-batch a.pcap b.pcap -o investigation.json` runs the
**existing** single-capture pipeline over each file, then correlates the
results. No competing analysis engine was created, and the intelligence layer
never reparses a packet.

A capture is identified by its **content hash**, so the same file supplied
twice, or under two names, is analysed once and recorded as a `DUPLICATE`. A
capture that fails stays in the inventory with its reason and raises a warning.
Output does not depend on argument order.

Five configurable limits (`max_batch_captures`, `max_batch_sessions`,
`max_batch_fingerprints`, `max_batch_correlations`, `max_timeline_events`), and
every one of them **warns explicitly** rather than truncating silently.

### Cryptographic DNA

Versioned (`smsfp/1`), canonicalised, with the exact hashed string published in
the report so any digest can be recomputed by hand. Components carry a source
(`CLIENT_OFFERED` / `SERVER_SELECTED` / `CERTIFICATE_OBSERVED` / `INFERRED` /
`UNKNOWN`); a test asserts no component is ever `CLIENT_OFFERED`. Source ports,
timestamps and session ids are excluded.

Completeness is explicit: `COMPLETE`, `PARTIAL` or `INSUFFICIENT`, with missing
components listed and written into the canonical form as `<ABSENT>` so an
incomplete fingerprint cannot collide with a complete one.

A separate **configuration fingerprint** over the negotiated settings alone
(certificate excluded) backs `CONFIGURATION_MATCH` — see §7.

### Server identity resolution

Entities are one observed `(ip, port)`, and **that is the only equality
performed**. Seven typed relations carry everything weaker. Nothing is merged.

### Cryptographic drift, correlation, timeline, blast radius

Covered in §6–§10 below and in the four methodology documents.

---

## 4. Test results

Every command was executed; this is its output.

```
$ pytest -q
1111 passed, 25 skipped in 30.61s

$ SECUREMAILSCOPE_TSHARK=1 pytest -q
1121 passed, 15 skipped in 34.08s

$ ruff check src tests scripts
All checks passed!

$ mypy src/securemailscope/
Success: no issues found in 92 source files
```

209 of those tests are new in `test_intelligence.py`. The 15 skips are fixtures
carrying no credential material, which the credential-absence test correctly
skips.

---

## 5. Fixture inventory

**15 capture-based groups.** Their letters are taken from the directive's
scenario list and are therefore *not contiguous*: the inventory is A, B, C, D,
E, F, G, H, I, K, L, M, N, Q, T. Writing "15 groups (A-T)" in an earlier draft
of this report implied a contiguous range of twenty and was corrected during
the M6 baseline audit.

Five directive scenarios are covered by tests over existing groups rather than
by dedicated capture sets, which is why their letters are absent:

| Scenario | Covered by |
|---|---|
| J — two sessions with the same finding | group Q, which does exactly this across two endpoints |
| O — assessment policy changed between captures | re-analysing a group's captures under a different policy (`test_score_drift_across_different_policies_is_not_comparable`) |
| P — different assessment coverage | re-analysing under a different coverage floor (`test_a_withheld_score_is_reported_as_incomparable`) |
| R — incomplete evidence preventing correlation | group I, whose second capture holds only a ClientHello |
| S — same-timestamp timeline events | group A, where the whole server flight shares one packet (`test_timeline_ordering_is_stable_for_equal_timestamps`) |

No fixtures were manufactured to make the count reach twenty.

Each group is a small set of captures isolating one behaviour, with
hand-derived expectations including the **negative** half.

| Group | Scenario | Verifies |
|---|---|---|
| A | Same config, two captures | `UNCHANGED_WITH_EVIDENCE` throughout |
| B | Same offer, TLS 1.2 then 1.0 | Attribution when the offer is constant |
| C | Same offer, different suite | Cipher drift attributable |
| D | Different offers, different selections | `INCONCLUSIVE` |
| E | Renewed certificate, same key | Renewal ≠ rekey |
| F | Two IPs, one certificate | Two entities stay two |
| G | One IP, ports 993 and 465 | Two services, two entities |
| H | TLS 1.3 both sides | `PARTIAL` fingerprints, `NOT_COMPARABLE` certificate drift |
| I | Complete, then ClientHello only | Missing evidence is never drift |
| K | Same bytes twice | `DUPLICATE`; counts not inflated |
| L | Unrelated servers, identical settings | The primary false-correlation test |
| M | Later capture supplied first | Chronology from the capture |
| N | Overlapping ranges, two source ports | One endpoint |
| Q | Same finding, two endpoints | Blast radius 2 / 2 / 2 |
| T | A file that is not a capture | `FAILED` with a warning |

Policy-change and coverage-change scenarios are exercised by re-analysing a
group's captures under different configurations rather than duplicating bytes.

### What hand-derivation caught

Three defects, all fixed in the implementation rather than in the expectation:

1. **Group B originally varied the client's advertised version too**, so the
   engine correctly answered `INCONCLUSIVE`. The fixture builder gained a
   separate `client_version`: a genuine server-side change can only be
   demonstrated with the offer held constant. My expectation was wrong; the
   engine was right.
2. **`CONFIGURATION_MATCH` could never fire**, because the certificate was part
   of the fingerprint and two hosts almost always present different
   certificates. That produced the separate configuration fingerprint — which
   also stopped a routine certificate renewal being reported as a
   configuration divergence.
3. **Drift-derived timeline events carried a timestamp with no nanosecond value**,
   and `CRYPTO_PARAMETERS_SELECTED` was dated at the ClientHello rather than
   the ServerHello that made the selection. Both fixed; a test now asserts a
   selection is never dated before the message that made it.

---

## 6. Genuine fingerprint example

From fixture `E_certificate_rotation_same_key`:

```
fingerprint_id: smsfp/1:74180c45b9481f91
completeness:   PARTIAL
missing:        key_exchange_group, alpn_selected

version=smsfp/1
tls_version=TLS 1.2
cipher_suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
key_exchange_group=<ABSENT>
alpn_selected=<ABSENT>
certificate_sha256=9e77b09d04d4f912e3297f60e6e6db5996636aae7d91e70c9bc10d073c439755
certificate_spki_sha256=97be88ee943f815b67d75c2a30d7ce4f0db6cb5cf1611c829f1d734060444b26
certificate_issuer=CN=SecureMailScope Synthetic Test Root
```

`sha256` of that string, truncated to 16 hex characters, is the id. Note the
two explicit `<ABSENT>` lines and the `PARTIAL` status: this is not presented
as a complete fingerprint, and it cannot collide with one.

---

## 7. Genuine drift example

Same fixture — a certificate renewal that kept its key:

```json
{"kind": "CERTIFICATE_FINGERPRINT", "status": "OBSERVED_CHANGE",
 "before": "9e77b09d...", "after": "d80b80d7...",
 "client_offers_comparable": null}

{"kind": "CERTIFICATE_PUBLIC_KEY", "status": "UNCHANGED_WITH_EVIDENCE",
 "before": "97be88ee...", "after": "97be88ee...",
 "client_offers_comparable": null}
```

The certificate changed and the key did not: a renewal, not a rekey. That
distinction is why `spki_sha256` was added to the certificate model.

`client_offers_comparable` is `null` because a server presents its certificate
regardless of what the client offered, so the offer was never consulted.
Reporting `true` would suggest a check that was never relevant.

---

## 8. False-correlation prevention example

Fixture `L_unrelated_same_configuration`: two unrelated servers with identical
TLS settings, different certificates, different keys, different names.

```
entities: 2
  entity-a70f88fdfee5  198.51.100.40:993
      CONFIGURATION_MATCH  configuration_fingerprint=smsfp/1/cfg:86...
  entity-c1e61a65eacb  198.51.100.25:993
      CONFIGURATION_MATCH  configuration_fingerprint=smsfp/1/cfg:86...
correlations: []
```

Two entities, not one. One weak relation, correctly typed and carrying its
limitation. **No** `SHARED_CERTIFICATE`, **no** `SHARED_PUBLIC_KEY`, **no**
`OBSERVED_SNI` and **no** `POSSIBLE_RELATION` — the last because
`POSSIBLE_RELATION` needs two corroborating weak signals and the names differ.
No correlations at all.

This is the case a careless correlation engine gets wrong, and it is what
"two hosts installed from the same distribution package" looks like.

---

## 9. Cross-session correlation example

Fixture `Q_same_finding_across_endpoints`:

```json
{
  "correlation_id": "corr-ac564a9e2a7f",
  "correlation_type": "REPEATED_OBSOLETE_TLS",
  "relationship_basis": "rule_id=TLS-PROTO-001",
  "related_session_ids": 2, "related_capture_ids": 2,
  "related_finding_ids": 2, "supporting_evidence": 4,
  "policy_versions": ["1.0.0"]
}
```

The id covers the type, the basis **and the member identities**, so it is
stable across runs and independent of argument order while still being
different for a different grouping. (An earlier version derived it from type
and basis alone; see the correction note below.) `policy_versions` is listed
because findings
correlated across captures may have been judged by different criteria; where
they are, an extra limitation says so.

---

## 10. Timeline example with packet provenance

From fixture `A_same_configuration`, two captures an hour apart:

```
#0  2026-06-01T12:00:00Z          SESSION_FIRST_PACKET        packets=[1]     OBSERVED
#1  2026-06-01T12:00:00Z          PROTOCOL_IDENTIFIED         packets=[1]     INFERRED
#2  2026-06-01T12:00:00.003000Z   CLIENT_HELLO                packets=[4]     OBSERVED
#3  2026-06-01T12:00:00.004000Z   SERVER_HELLO                packets=[5]     OBSERVED
#4  2026-06-01T12:00:00.004000Z   CRYPTO_PARAMETERS_SELECTED  packets=[4,5]   INFERRED
#5  2026-06-01T12:00:00.004000Z   CERTIFICATE_OBSERVED        packets=[5]     OBSERVED
#6  2026-06-01T13:00:00Z          SESSION_FIRST_PACKET        packets=[1]     OBSERVED
```

Every event names its packets. Derived events (`INFERRED`) carry `derived_from`
listing the observations behind them — event #4 above carries
`("tls.version.selected_version", "tls.cipher_suite.selected")`.

Events #3, #4 and #5 share a timestamp exactly, since the whole server flight
arrived in one packet. Their order comes from the documented tie-break, not
from luck: equal timestamps are broken by
`(capture, session, event rank, packet number)`.

No timestamp is invented: an event whose timing the capture does not establish
has none and sorts last. File modification times are never substituted. The
report carries the clock limitations, including that clocks across captures
taken on different hosts are independent and uncorrected.

---

## 11. Blast radius with exact arithmetic

Fixture `Q`:

```json
{
  "subject": "TLS-PROTO-001", "subject_kind": "RULE",
  "session_count": 2, "entity_count": 2,
  "capture_count": 2, "finding_count": 2,
  "protocol_distribution": {"IMAP": 2},
  "scope_statement": "Observed within analyzed captures only."
}
```

**TLS-PROTO-001 observed in 2 sessions across 2 observed server endpoints, in
2 captures.** Each number is derived: two `session_id` values, two distinct
`(ip, port)` pairs, two distinct capture hashes. A test asserts each count
equals the length of the identifier list it summarises, so the two can never
disagree.

Contrast fixture `K_duplicate_capture`, where the same bytes arrive twice under
two names: every count is 1.

---

## 12. Output contract

`investigation_to_dict` emits `investigation` with all nine required blocks —
`investigation_id`, `capture_inventory`, `server_entities`,
`cryptographic_fingerprints`, `drift_events`, `session_correlations`,
`evidence_timeline`, `blast_radius`, `intelligence_warnings` — alongside
`captures`, which carries **every individual capture report unchanged** at
schema 1.3.0. A test asserts the M1–M4 blocks survive. No existing field
changed meaning. No PDF, HTML or frontend work was done.

---

## 12a. Correction issued during the M6 baseline audit

This report originally stated that correlation identifiers are "derived from
the type and basis only, so the same grouping in two investigations carries the
same identifier". The first half was accurate and the conclusion was not.

Type and basis alone do not identify a grouping. Two investigations that each
contain sessions failing `TLS-PROTO-001` both produced
`corr-5272c9972ccf` for `SHARED_RULE_FAILURE` / `rule_id=TLS-KEX-001`, with
**entirely disjoint member sets**. Anyone diffing the two reports would have
read them as one correlation that had grown.

The identifier now covers the type, the basis and the sorted member session and
capture identities. The property the original design was reaching for — the
same grouping analysed twice diffs cleanly — is preserved, and a different
grouping is now a different correlation. Three regression tests were added:
`test_disjoint_groups_of_the_same_type_do_not_share_an_id`,
`test_the_same_grouping_keeps_its_id_across_runs` and
`test_a_correlation_id_changes_when_its_membership_changes`.

---

## 13. Known limitations

- **A fingerprint is not an identity.** Two servers from the same distribution
  package match on day one.
- **An entity is an endpoint, not a machine.** Whether it is one host, a pool
  or a virtual host is not observable.
- **Drift sees only what was captured.** A server may have changed and changed
  back between captures.
- **Clocks are not synchronised across captures.** No skew is measured or
  corrected.
- **Counts cover the analysed captures only.** Absence from a count is absence
  of observation, not evidence of safety.
- **No intent, ownership or topology is ever inferred.**
- **No performance measurement.** No throughput figure is claimed.

---

## 14. M1–M4 regression status

| Milestone | Status |
|---|---|
| M1 — ingestion and TCP reconstruction | All tests pass unchanged |
| M2 — email protocol and STARTTLS | All tests pass unchanged |
| M3 — TLS and certificates | All tests pass; `PublicKeyInfo` gained `spki_sha256` (additive) |
| M4 — assessment | All tests pass unchanged |

No forensic behaviour changed. The one model addition is additive and its value
is computed from the certificate bytes already being parsed.

---

## 15. Acceptance gates

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Multiple captures analysed together | **PASS** | `test_cli_batch_analysis_end_to_end` |
| 2 | Capture identities and evidence intact | **PASS** | `test_capture_evidence_survives_the_batch` |
| 3 | Cryptographic DNA deterministic and explainable | **PASS** | `test_fingerprints_are_deterministic`, `test_canonical_form_is_recomputable_from_the_report` |
| 4 | Missing information does not fabricate fingerprints | **PASS** | `test_a_missing_server_hello_cannot_produce_a_usable_fingerprint` |
| 5 | Identity resolution distinguishes weak from strong | **PASS** | `test_identical_configuration_alone_is_not_a_relation_claim` |
| 6 | Drift detects genuine differences | **PASS** | `test_an_identical_client_offer_permits_attribution` |
| 7 | Missing evidence is not reported as drift | **PASS** | `test_changes_the_evidence_does_not_support_are_absent` |
| 8 | Different client offers handled conservatively | **PASS** | `test_a_different_client_offer_blocks_attribution` |
| 9 | Correlations link actual evidence | **PASS** | `test_every_correlation_names_its_basis_and_its_limits` |
| 10 | False correlations covered by negative tests | **PASS** | `test_false_correlations_are_absent`, group L |
| 11 | Timelines have valid timestamps and packet references | **PASS** | `test_timeline_events_carry_real_packet_provenance` |
| 12 | Blast-radius counts match observations | **PASS** | `test_blast_radius_arithmetic_matches_expectation` |
| 13 | Duplicate captures do not inflate counts | **PASS** | `test_blast_radius_never_double_counts_a_duplicate_capture` |
| 14 | Existing M1–M4 tests pass | **PASS** | 1,111 passed |
| 15 | No sensitive information in output | **PASS** | `test_no_credential_material_reaches_an_investigation` |
| 16 | Batch CLI produces real forensic intelligence | **PASS** | §6–§11, all from executed runs |

---

## 16. Readiness for M6

M6 is ML-assisted analysis. The seam is clean:

- `AnalysisStage.ML_ANALYSIS` exists and is `NOT_IMPLEMENTED`, so reports
  already say "not looked for" rather than "not found".
- Fingerprints are a natural feature vector, already canonicalised, versioned
  and carrying explicit completeness — so a model can be told what was missing
  rather than being fed a silent zero.
- Evidence-model rule 3 stands: ML output is always `INFERRED` and may never
  promote another stage's observation.

No M6 or M7 work was started.
