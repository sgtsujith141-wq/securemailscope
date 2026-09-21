# Model card

Two models ship with SecureMailScope. Both run locally, need no network, and
can be deleted without affecting any other part of the analysis.

---

## `tls-anomaly` 1.0.0

| | |
|---|---|
| **Task** | Flag TLS sessions whose observable configuration is unusual against a stated reference population |
| **Algorithm** | Rarity table over `(version, encryption, key exchange)`, selected on validation over Isolation Forest |
| **Feature schema** | `smsfeat/1` |
| **Dataset** | `securemailscope-synthetic-tls` 1.0.0 |
| **Training population** | 246 eligible sessions, five reference families, training split only |
| **Decision threshold** | 0.000, frozen on validation before the test split was touched |
| **Held-out result** | Precision 1.000, recall 1.000, FPR 0.000 over 101 sessions with 8 anomalies |
| **Status** | Implemented and evaluated |

### Intended use

Drawing an analyst's attention to a session configured unlike the reference
population, as one input among several, alongside the deterministic M4
findings that are backed by observed evidence.

### What an anomaly is not

* **Not a vulnerability.** The rarest configuration on a network is often the
  strongest. The `hardened_uncommon` family exists to keep that in view, and
  none of its 123 held-out sessions was flagged.
* **Not an attack, and not intent.** This tool observes configuration. It does
  not detect adversaries and makes no claim about any.
* **Not absolute.** "Unusual" is relative to the recorded reference population,
  which is synthetic. Change the population and the answer changes. That is a
  property of the question, not a defect.

### Out of scope

Real-world traffic without independent evaluation; any use as a monitoring or
blocking control; any claim about prevalence.

---

## `tls-posture` 1.0.0

| | |
|---|---|
| **Task** | Predict a server's latent posture class from one observed session |
| **Algorithm** | Logistic regression (balanced class weights), selected on validation over random forest and a majority-class baseline |
| **Feature schema** | `smsfeat/1` |
| **Training population** | 313 eligible sessions, 91 server groups, training split |
| **Held-out result** | Macro-F1 0.562, accuracy 0.525 over 101 samples (baseline macro-F1 0.123) |
| **Status** | **NOT_VALIDATED** |

### Why NOT_VALIDATED

The model is real, trained properly, and beats its baseline by a wide margin.
It is still reported as `NOT_VALIDATED` on **every** prediction, for four
reasons that no amount of further tuning would remove:

1. **The label is ours.** The posture rubric is authored by this project. It is
   informed by RFC 9325 and the Mozilla TLS tiers, but it is not an externally
   validated risk measure. Predicting it well demonstrates that the *rubric's*
   verdict can be recovered from partial observations — not that compromise can
   be predicted.
2. **The data is synthetic.** Trained and evaluated entirely on captures this
   repository generates. Nothing establishes that real servers are distributed
   like these.
3. **The sample is small.** 31 independent groups in the test split; CRITICAL
   has 10 samples. Confidence intervals would be wide.
4. **Performance is moderate and unevenly distributed.** HIGH recall is 0.343.
   The model systematically cannot separate a careless server that negotiated
   well from a careful one — because that evidence is not in a single capture.

### What the status means in practice

* Predictions appear in the report with `status: NOT_VALIDATED`.
* They never enter a `SecurityFinding`, never change a posture score, and never
  modify an observation. A test asserts no ML output reaches the assessment
  block.
* **Where the ML prediction and the deterministic assessment disagree, the
  deterministic assessment is the one backed by observed evidence.**

### Calibration

**None was fitted or validated.** `class_scores` are relative model outputs,
not probabilities. A score of 0.54 does not mean a 54% chance of anything, and
nothing in the codebase converts one into a probability.

---

## Shared properties

### Abstention

| Condition | Result |
|---|---|
| No negotiated version and suite observed | `NOT_EVALUABLE` |
| No model installed | `MODEL_UNAVAILABLE` |
| Unsupported model version, schema mismatch, or failed integrity check | `MODEL_REJECTED`, with the reason |
| ML switched off | `DISABLED` |

There is no fallback prediction. 96 of the 608 dataset sessions fall below the
evidence floor, and a detector that scored them anyway would be reporting the
capture's limits as the server's.

### Security

Artifacts load **only** from the packaged directory, with the path resolved and
confined so a manifest cannot redirect the loader. The SHA-256 is verified
**before** joblib opens the file. Model version and feature schema must match
this build. Nothing is ever downloaded; there is no registry service and no URL.

### Privacy

No IP address, host name, SNI value, certificate subject or issuer, credential
or payload byte reaches a feature, a model or an ML output. Asserted by tests.

### Reproducibility

Fixed seeds (population 20260921, sessions 815, split 4242, model 20260921).
Every manifest records the dataset version, training sample count, hyper-
parameters, artifact digest and library versions. `python scripts/train_ml.py`
reproduces the run.

### Environmental cost

A full training run is ~14 seconds on one CPU core. Inference is 0.43 ms per
session. No GPU is used or required.
