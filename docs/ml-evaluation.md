# ML evaluation

> **Every number on this page is a controlled-environment measurement over
> locally generated synthetic captures.** None of it is evidence of real-world
> detection performance, attack prevalence, breach likelihood or operational
> risk. No evaluation on representative real traffic has been performed.

Reproduce with `python scripts/train_ml.py`. The machine-readable record is
`src/securemailscope/ml/artifacts/evaluation.json`.

## Split composition

| Partition | Samples | Independent groups | LOW | MODERATE | HIGH | CRITICAL |
|---|---|---|---|---|---|---|
| Train | 313 | 91 | 122 | 62 | 94 | 35 |
| Validation | 98 | 30 | 20 | 46 | 21 | 11 |
| Test | 101 | 31 | 33 | 23 | 35 | 10 |

608 sessions generated; **96 excluded** below the evidence floor; 512 eligible.
Group overlap between partitions: **none**.

Anomaly reference population: **246** eligible training-split sessions from the
five reference families.

## Task A — anomaly detection

Both candidates were tuned under one rule, on validation only: highest
validation F1 among cuts with a validation false-positive rate at or below 20%.

### Validation (selection)

| Candidate | Threshold | FPR | Recall | F1 |
|---|---|---|---|---|
| Rarity baseline | 0.000 | 0.000 | 0.600 | **0.750** |
| Isolation Forest | 0.0125 | 0.054 | 1.000 | 0.667 |

Selected: **rarity baseline**.

### Held-out test

Denominators: 101 sessions, **8 injected anomalies**, 93 normal.

| Candidate | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| **Rarity baseline** | 8 | 0 | 93 | 0 | **1.000** | **1.000** | **1.000** | **0.000** |
| Isolation Forest | 8 | 9 | 84 | 0 | 0.471 | 1.000 | 0.640 | 0.097 |

### Isolation Forest's failure cases

All nine false positives were ordinary configurations — three TLS 1.2
AES-128-CBC, two TLS 1.2 AES-256-GCM, two TLS 1.2 AES-128-GCM, one TLS 1.0
AES-256-CBC, one TLS 1.2 3DES. Flagging a TLS 1.2 AES-GCM session as unusual is
a clear error, and it is why the simpler model ships.

Isolation Forest **ranks** correctly: measured over validation and test
together, the separation AUC is ≈ 0.97 (13 anomalies, 186 normal). Its weakness
is the operating point, not the ordering. With continuous features, or
anomalies unusual *within* seen combinations rather than absent from them, the
ranking model would likely be the better choice.

### Held-out configuration families

`legacy_compatible` and `hardened_uncommon` withheld entirely from fitting.

| | |
|---|---|
| Samples | 123 |
| Injected anomalies present | 0 |
| False positives | **0** |
| False-positive rate | **0.000** |
| Recall | **undefined** — no positives in this split |

Recall is reported as undefined rather than as zero. The meaningful number here
is the false-positive rate on kinds of server the detector has never seen, and
it includes every `hardened_uncommon` negative control: **not one rare-but-
legitimate configuration was flagged.**

## Task B — posture classification

**Status: NOT_VALIDATED.** Implemented, measured, and not fit to act on. See
[ml-model-card.md](ml-model-card.md).

### Validation macro-F1 (selection)

| Model | Macro-F1 |
|---|---|
| Logistic regression | **0.619** |
| Random forest | 0.594 |
| `DummyClassifier(most_frequent)` | 0.085 |

Selected: **logistic regression**.

### Held-out test — 101 samples

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| LOW | 0.667 | 0.485 | 0.561 | 33 |
| MODERATE | 0.320 | 0.696 | 0.438 | 23 |
| HIGH | 0.923 | 0.343 | 0.500 | 35 |
| CRITICAL | 0.643 | 0.900 | 0.750 | 10 |

**Macro-F1 0.562, accuracy 0.525.** Baseline: macro-F1 0.123, accuracy 0.327.

### Confusion matrix (rows: true, columns: predicted)

| | CRITICAL | HIGH | LOW | MODERATE |
|---|---|---|---|---|
| **CRITICAL** | 9 | 1 | 0 | 0 |
| **HIGH** | 3 | 12 | 3 | 17 |
| **LOW** | 0 | 0 | 16 | 17 |
| **MODERATE** | 2 | 0 | 5 | 16 |

### What the errors show

**HIGH recall is 0.343** — the dominant failure, and the informative one. 17 of
35 HIGH servers were called MODERATE. These are `mixed_migration` servers:
they still permit static RSA, but when a modern client offers only AEAD suites
they negotiate one, and the session looks like an ordinary intermediate
configuration. **The evidence to distinguish them is not in the capture.**

That is the latent-label design working as intended rather than a defect to
tune away. A model reaching 0.95 here would mean the label had leaked.

**MODERATE precision is 0.320** — the same effect from the other side: MODERATE
is where the model puts sessions it cannot separate.

**CRITICAL recall is 0.900** with 10 samples. A single misclassification moves
it by 0.1, so it should be read as "high, measured over very few samples".

## Statistical limitations

- **31 independent groups in the test split.** Confidence intervals on
  per-class metrics would be wide; none is quoted as if narrow, and none is
  computed, because a normal-approximation interval over 10 samples would be
  more misleading than no interval.
- **CRITICAL has 10 test samples.** Treat its metrics as indicative.
- **8 injected anomalies in the test split.** Perfect precision and recall over
  8 positives is a much weaker claim than the same numbers over 800, and the
  denominators are stated everywhere for that reason.
- **This is not a generalisation study.** It is a controlled experiment on a
  dataset we designed. A configuration pattern we did not think of is not
  represented in any of these numbers.

## Performance

Measured on macOS 26.6.2 (x86-64, 16 cores), Python 3.12.14, scikit-learn
1.5.2, numpy 2.1.3.

| | |
|---|---|
| Dataset build (608 captures, generated + analysed) | 12.8 s |
| Anomaly fit | 0.8 s |
| Classifier fit | 0.5 s |
| **Full training run** | **~14 s** |
| Model load, once per process | 129.5 ms |
| **Inference** | **0.43 ms per session** |
| Analysis with ML | 6.71 ms per capture |
| Analysis without ML | 6.29 ms per capture |
| Anomaly artifact | 370,074 bytes |
| Classifier artifact | 3,093 bytes |
| Peak RSS | 169 MB |

No GPU. Single-threaded (`n_jobs=1`). The model is loaded once per process and
cached; reloading per capture made analysis seventeen times slower for no
benefit.

The anomaly artifact is large relative to the model that ships because it
stores **both** candidates — the selected rarity table and the Isolation Forest
— so the comparison can be re-run from the artifact.

### Deployment limits

This is a small model trained on 246 reference sessions. It is suitable for
local analysis of individual captures, which is what this tool does. It is not
a production detector, it has no throughput characterisation beyond the figure
above, and nothing here supports deploying it as a monitoring control.
