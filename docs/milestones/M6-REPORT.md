# M6 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M6 — Machine learning, anomaly detection, risk classification and scientific validation
- **Baseline (M5):** `3ee7c891efc63d5fff6edb8c48e766798837e976`
- **Commit:** `0df1b2060c31ae8799175992fb0359af7f628e76`
- **Result:** **COMPLETE, with supervised classification reported PARTIAL** — 17 of 18 acceptance gates pass outright; gate 9 is met in its second form ("or its limitations are explicitly recorded").

---

## 1. Baseline audit

| Claim | Actual |
|---|---|
| Local HEAD == remote HEAD | both `3ee7c891efc63d5fff6edb8c48e766798837e976` |
| Working tree | clean |
| `pytest -q` | `1111 passed, 25 skipped` — **matches the directive exactly** |
| `SECUREMAILSCOPE_TSHARK=1 pytest -q` | `1121 passed, 15 skipped` — **matches** |
| Implementation commit `aa6efeb` | confirmed |
| `ml/` package | a docstring only, marked NOT IMPLEMENTED |

### Corrective audit 1 — correlation identifiers collided

**The directive was right, and the M5 report was wrong.**

M5 stated that correlation identifiers "derive from correlation type and basis
only, so the same grouping in two investigations carries the same identifier".
The first clause was accurate; the conclusion did not follow.

Reproduced directly: fixture groups `Q_same_finding_across_endpoints` and
`B_version_downgrade`, analysed as separate investigations, both produced
`corr-5272c9972ccf` for `SHARED_RULE_FAILURE` / `rule_id=TLS-KEX-001` with
**entirely disjoint member sets**. Anyone diffing the two reports would have
read them as one correlation that had grown.

Fixed by scoping the identifier to the canonical relationship **and its member
identities** — type, basis, and the sorted session and capture ids. The
property the original design wanted is preserved: the same grouping analysed
twice still diffs cleanly. Three regression tests were added
(`test_disjoint_groups_of_the_same_type_do_not_share_an_id`,
`test_the_same_grouping_keeps_its_id_across_runs`,
`test_a_correlation_id_changes_when_its_membership_changes`), and the M5 report
and `docs/correlation-methodology.md` now carry the correction.

### Corrective audit 2 — the fixture count was misleading

The M5 report said "15 fixture groups (A–T)". There are **15 groups**, and the
letters are **not contiguous**: A, B, C, D, E, F, G, H, I, K, L, M, N, Q, T.
Writing "A–T" implied a range of twenty.

The five absent letters correspond to directive scenarios covered by tests over
existing groups rather than by dedicated capture sets: J by group Q, O and P by
re-analysis under a different policy and coverage floor, R by group I, S by
group A. The M5 report now states the true number and the mapping.

**No fixtures were manufactured to make the count reach twenty.**

---

## 2. Dataset composition and provenance

| | |
|---|---|
| dataset_id | `securemailscope-synthetic-tls` |
| dataset_version | `1.0.0` |
| content digest | `60f1f270a9ce1c79` |
| licensing | none required — generated locally from fixed seeds |

Every sample is a **real capture analysed by the real M1–M5 pipeline**. The
generator writes pcap bytes, the engine reconstructs the session, the extractor
reads the observations. No shortcut path fabricates features.

Not used: downloaded captures, enterprise traffic, private email, third-party
datasets, real servers. No network access in generation, training or inference.

**152 servers → 608 sessions**, four per server, across seven configuration
families. Several families span more than one posture class, so the family name
is not a proxy for the label — asserted by a test.

Full composition: [ml-dataset.md](../ml-dataset.md).

---

## 3. Sample counts

| | |
|---|---|
| Generated sessions | 608 |
| **Excluded below the evidence floor** | **96** |
| Eligible for modelling | 512 |
| Independent groups (servers) | 152 |
| Sessions with an observable certificate | 320 |
| Sessions that never negotiated | 96 |

Class distribution over eligible samples: LOW 175, MODERATE 131, HIGH 150,
CRITICAL 56. Imbalanced deliberately — careless servers are a minority — which
is why every classification metric is macro-averaged.

---

## 4. Split

Grouped by **server instance**, so no server appears in two partitions.

| Partition | Samples | Groups | LOW | MODERATE | HIGH | CRITICAL |
|---|---|---|---|---|---|---|
| Train | 313 | 91 | 122 | 62 | 94 | 35 |
| Validation | 98 | 30 | 20 | 46 | 21 | 11 |
| Test | 101 | 31 | 33 | 23 | 35 | 10 |

Anomaly reference population: 246 training-split sessions from the five
reference families.

A second evaluation withholds whole families (`legacy_compatible`,
`hardened_uncommon`).

---

## 5. Leakage-prevention evidence

| Control | Evidence |
|---|---|
| Group overlap between partitions | **none** — recorded in `evaluation.json`, asserted by `test_splitting_is_group_aware` |
| A certificate never spans partitions | `test_no_certificate_spans_two_partitions` |
| A server's four sessions stay together | `test_duplicate_sessions_of_one_server_stay_together` |
| Whole families withheld | `test_family_holdout_withholds_whole_families` |
| Split happens before any fitting | Feature scales are hand-set constants, not fitted |
| No M4 output in features | `test_the_dataset_is_built_with_the_assessment_layer_off` |
| No identity in features | `test_prohibited_identifiers_are_absent_from_features` |
| Label not recoverable from family | `test_no_family_is_a_proxy_for_the_label` |
| Label genuinely differs from the session | `test_labels_are_not_derived_from_the_assessment_engine` |

---

## 6. Feature inventory

**`smsfeat/1`, 93 columns**, all derived from M1–M5 observations, each carrying
a provenance string. 13 categorical features one-hot encoded against frozen
vocabularies, 5 boolean, 5 numeric each paired with an explicit `*_missing`
indicator.

Excluded deliberately: ids, hashes, M4 scores and severities, split
assignments, family names, IP addresses, host names, SNI values, certificate
subjects, and fingerprint digests as numbers. Full schema:
[ml-features.md](../ml-features.md).

---

## 7. Model architecture and hyperparameters

**Anomaly — `tls-anomaly` 1.0.0.** Rarity table over
`(version, encryption, key exchange)`; decision threshold 0.000, frozen on
validation. The Isolation Forest candidate (200 estimators, max_samples 246,
contamination 0.05, seed 20260921) is stored in the same artifact so the
comparison can be re-run.

**Classifier — `tls-posture` 1.0.0.** Logistic regression, `max_iter=2000`,
`class_weight="balanced"`, seed 20260921.

Seeds: population 20260921, sessions 815, split 4242, models 20260921.

---

## 8. Baseline comparison

**The a priori ML candidate lost, and the simpler method ships.**

Both anomaly candidates were tuned under one rule on validation: highest
validation F1 among cuts with FPR ≤ 20%.

| Candidate | Validation F1 | Test P | Test R | Test F1 | Test FPR |
|---|---|---|---|---|---|
| **Rarity baseline** (selected) | **0.750** | **1.000** | **1.000** | **1.000** | **0.000** |
| Isolation Forest | 0.667 | 0.471 | 1.000 | 0.640 | 0.097 |

Classification, validation macro-F1: logistic regression 0.619, random forest
0.594, `DummyClassifier(most_frequent)` 0.085.

### A threshold rule that failed

The first threshold rule produced **recall 0.0** from a model whose separation
AUC is ≈ 0.97. It took "the lowest cut meeting a 5% false-positive target",
which placed the threshold below almost every normal score and therefore below
the anomalies too. The failure was in the rule, not the model. It is recorded
in `anomaly.py` and [ml-methodology.md](../ml-methodology.md) because the
instinct in that moment is to blame the model.

---

## 9. Held-out metrics

> Controlled-environment measurements over synthetic captures. Not real-world
> detection performance.

### Anomaly — 101 test sessions, 8 injected anomalies, 93 normal

| Candidate | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| Rarity baseline | 8 | 0 | 93 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
| Isolation Forest | 8 | 9 | 84 | 0 | 0.471 | 1.000 | 0.640 | 0.097 |

**Held-out families** (123 samples, 0 injected anomalies): false-positive rate
**0.000**; recall **undefined**, reported as undefined because there are no
positives — not converted to zero.

### Classification — 101 test samples

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| LOW | 0.667 | 0.485 | 0.561 | 33 |
| MODERATE | 0.320 | 0.696 | 0.438 | 23 |
| HIGH | 0.923 | 0.343 | 0.500 | 35 |
| CRITICAL | 0.643 | 0.900 | 0.750 | 10 |

**Macro-F1 0.562, accuracy 0.525** against a baseline of 0.123 / 0.327.

---

## 10. Confusion matrix

Rows true, columns predicted:

| | CRITICAL | HIGH | LOW | MODERATE |
|---|---|---|---|---|
| **CRITICAL** | 9 | 1 | 0 | 0 |
| **HIGH** | 3 | 12 | 3 | 17 |
| **LOW** | 0 | 0 | 16 | 17 |
| **MODERATE** | 2 | 0 | 5 | 16 |

---

## 11. False positives and false negatives

**Isolation Forest's nine false positives** were all ordinary configurations:
three TLS 1.2 AES-128-CBC, two TLS 1.2 AES-256-GCM, two TLS 1.2 AES-128-GCM,
one TLS 1.0 AES-256-CBC, one TLS 1.2 3DES. Flagging a TLS 1.2 AES-GCM session
as unusual is plainly wrong, and it is why the simpler model ships.

**The classifier's dominant failure is HIGH recall 0.343** — 17 of 35 HIGH
servers called MODERATE. These are `mixed_migration` servers: they still permit
static RSA, but a modern client offering only AEAD suites gets one, and the
session looks like an ordinary intermediate configuration. **The evidence to
tell them apart is not in the capture.**

That is the latent-label design working, not a defect to tune away. A model
scoring 0.95 here would mean the label had leaked.

**CRITICAL recall 0.900 over 10 samples**: one misclassification moves it by
0.1. Read as "high, over very few samples".

---

## 12. Anomaly example

Real output, from a generated capture:

```json
{
  "status": "ANOMALOUS",
  "raw_score": 0.0,
  "decision_threshold": 0.0,
  "evidence_refs": [
    {"packet_number": 4, "timestamp": "2026-06-01T12:01:00.003000+00:00"},
    {"packet_number": 5, "timestamp": "2026-06-01T12:01:00.004000+00:00"}
  ],
  "explanation": "Machine-learning observation: this combination of negotiated version, encryption and key exchange occurred in 0.0% of the 246-session training reference population, at or below the frozen decision threshold of 0.0%. Unusual is not the same as unsafe."
}
```

---

## 13. Classification example

Real output for `aa_tls10_static_rsa.pcap` (TLS 1.0, static RSA):

```json
{
  "status": "NOT_VALIDATED",
  "predicted_class": "HIGH",
  "class_scores": {"CRITICAL": 0.454, "HIGH": 0.542, "LOW": 0.003, "MODERATE": 0.001}
}
```

`NOT_VALIDATED` appears on **every** prediction. Scores are relative model
outputs, not calibrated probabilities — no calibration was fitted or validated.

---

## 14. Evidence-linked explanation

From the same anomaly:

```json
[
  {"feature": "cipher_encryption", "observed_value": "RC4_128",
   "provenance": "tls.cipher_suite (registry decomposition)",
   "reference_frequency": 0.0,
   "note": "RC4_128 did not occur at all in the 246-session training reference population."},
  {"feature": "tls_version", "observed_value": "TLS 1.0",
   "provenance": "tls.version.selected_version",
   "reference_frequency": 0.0569,
   "note": "TLS 1.0 occurred in 5.7% of the 246-session training reference population."}
]
```

Every feature names the M1–M5 field it came from. Frequencies are statements
about the training population, checkable against it. No feature is claimed to
*cause* the verdict: neither a contingency table nor a tree's feature
importance establishes causation.

---

## 15. Missing-evidence example

`t_g_client_hello_only.pcap` — a ClientHello and nothing else:

```json
{
  "status": "NOT_EVALUABLE",
  "raw_score": null,
  "explanation": "No negotiated version and cipher suite were observed. A session with too little evidence is not evaluated, rather than being reported as unusual for having little to show."
}
```

No fallback prediction. 96 of 608 dataset sessions fall below this floor.

---

## 16. Benchmarks

macOS 26.6.2 (x86-64, 16 cores), Python 3.12.14, scikit-learn 1.5.2, numpy
2.1.3, scipy 1.18.1, joblib 1.6.0.

| | |
|---|---|
| Dataset build (608 captures generated + analysed) | 12.8 s |
| Anomaly fit | 0.8 s |
| Classifier fit | 0.5 s |
| **Full training run** | **~14 s** |
| Model load, once per process | 129.5 ms |
| **Inference** | **0.43 ms / session** |
| Analysis with ML | 6.71 ms / capture |
| Analysis without ML | 6.29 ms / capture |
| Anomaly artifact | 370,074 bytes |
| Classifier artifact | 3,093 bytes |
| Peak RSS | 169 MB |

No GPU, `n_jobs=1`. The model is cached per process; reloading per capture made
analysis **seventeen times slower** (80.2 ms against 4.9 ms) and was caught by
benchmarking rather than by a test.

**Deployment limits:** a small model trained on 246 reference sessions, fit for
local analysis of individual captures. Not a production detector, and nothing
here supports deploying it as a monitoring control.

---

## 17. Test results

```
$ pytest -q
1163 passed, 25 skipped in 78.68s

$ SECUREMAILSCOPE_TSHARK=1 pytest -q
1173 passed, 15 skipped in 82.16s

$ ruff check src tests scripts
All checks passed!

$ mypy src/securemailscope/
Success: no issues found in 103 source files
```

49 new tests in `test_ml.py` covering the full §15 matrix (A–Z), plus 3
correlation-ID regression tests in `test_intelligence.py`.

Expected metrics are computed **independently**: the metric functions are
checked against confusion matrices worked out by hand in the test docstrings,
never against numbers read back from the model's own evaluation record.

---

## 18. M1–M5 regression status

| Milestone | Status |
|---|---|
| M1 — ingestion and TCP reconstruction | All tests pass unchanged |
| M2 — email protocol and STARTTLS | All tests pass unchanged |
| M3 — TLS and certificates | All tests pass; `rsa1024` added to the synthetic CA's key kinds (additive) |
| M4 — assessment | All tests pass; schema 1.3.0 → 1.4.0 (additive) |
| M5 — forensic intelligence | All tests pass; correlation identifiers corrected (see §1) |

A test asserts the deterministic analysis is **identical** with and without the
ML layer.

---

## 19. Known limitations

- **Everything is synthetic.** No evaluation on representative real traffic has
  been performed, and no metric here describes real-world performance.
- **Supervised classification is NOT_VALIDATED**, on every prediction. Its
  label is a rubric this project wrote.
- **Scores are not probabilities.** No calibration was fitted or validated.
- **The sample is small**: 31 independent test groups, 10 CRITICAL samples, 8
  injected anomalies. No confidence intervals are quoted, because an interval
  over 10 samples would mislead more than its absence.
- **An anomaly is relative** to the recorded reference population, and rarity
  is not risk.
- **The dataset is generator-shaped.** A configuration pattern we did not think
  of is not represented in any measurement.
- **The anomaly artifact is a joblib pickle.** It is committed, and the loader
  verifies its SHA-256 before deserialising, refuses paths outside the packaged
  directory, and refuses version or schema mismatches. Arbitrary artifacts are
  never loaded.

---

## 20. Acceptance gates

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | A genuine model is trained | **PASS** | Two models; `scripts/train_ml.py` reproduces the run |
| 2 | Training dataset documented | **PASS** | [ml-dataset.md](../ml-dataset.md), real counts |
| 3 | Labels and ground truth defensible | **PASS** | Three truths separated; latent target; rubric documented |
| 4 | Dataset leakage prevented | **PASS** | §5; nine controls, each with a test |
| 5 | Features are evidence-derived | **PASS** | 93 columns, each with provenance |
| 6 | Missing evidence handled explicitly | **PASS** | `AbsenceReason`; 96 sessions abstained |
| 7 | Model selection documented | **PASS** | §8; the baseline won and ships |
| 8 | Anomaly detection works | **PASS** | P 1.000 / R 1.000 held out; 0 FP on negative controls |
| 9 | Risk classification validated **or its limitations recorded** | **PARTIAL** | Implemented and measured; reported `NOT_VALIDATED` with four stated reasons |
| 10 | Real held-out evaluation executed | **PASS** | §9, plus a family holdout |
| 11 | Real metrics and failure cases reported | **PASS** | §10, §11 |
| 12 | Baselines included | **PASS** | Both tasks |
| 13 | Inference deterministic and local | **PASS** | `test_repeated_inference_is_identical`, `test_inference_opens_no_socket` |
| 14 | Outputs explainable and evidence-linked | **PASS** | §14 |
| 15 | M1–M5 analysis unchanged | **PASS** | `test_ml_never_modifies_a_deterministic_result` |
| 16 | The analyzer works without a model | **PASS** | `test_a_missing_model_is_reported_not_raised_into_the_analysis` |
| 17 | Privacy and resource limits enforced | **PASS** | Redaction and identity tests; 0.43 ms/session |
| 18 | End-to-end CLI inference | **PASS** | `test_cli_reports_ml_end_to_end` |

**Gate 9 is the honest one.** A working anomaly detector does not make the
mandatory AI/ML scope complete, and this report does not claim it does.
Supervised classification is implemented, trained, measured and clearly better
than its baseline — and reported as PARTIAL because nothing establishes that
what it predicts means anything operationally.

---

## 21. Readiness for M7

M7 is the dashboard and reporting layer. The seam is clean:

- The `ml` block is structured, machine-readable and self-describing, with
  model metadata, thresholds, per-feature explanations and packet references.
- Every ML result carries a disclosure that a model produced it, so a renderer
  cannot accidentally present an inference as an observation.
- `ml_status` distinguishes COMPLETED, DISABLED, MODEL_UNAVAILABLE and
  MODEL_REJECTED, so a dashboard can show why something is missing rather than
  showing nothing.

No M7 work was started.
