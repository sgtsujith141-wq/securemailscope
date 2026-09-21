# ML methodology

## Two tasks, deliberately separate

**Task A — anomaly detection.** Learn what configurations look like in a stated
reference population, and flag sessions whose observable combination is unusual
against it. Unsupervised; no labelled attacks are needed or claimed.

**Task B — posture classification.** Predict a server's **latent posture
class** from a single observed session. Supervised, and reported as
**NOT_VALIDATED** — see [ml-model-card.md](ml-model-card.md) for why.

## What the ML layer is not allowed to be

The obvious failure mode for an ML layer bolted onto a deterministic engine is
that it learns to imitate the engine. A model trained on M4's scores would be a
slow, opaque, less accurate reimplementation of code that already exists and is
already right.

So:

* the dataset is built with **the assessment layer switched off**;
* no M4 score, severity, rule outcome or policy label is a feature or a target;
* a test asserts none of those strings reaches the feature block.

## Why the classification target is latent

A server has a complete configuration: a minimum version, a full list of suites
it will negotiate, a certificate practice, other listeners. A capture shows
**one negotiation with one client**. A server that still permits RC4 will not
reveal it to a modern client that never offers it — the session looks perfect,
and the server is not.

The target is therefore the server's posture class, assigned by a documented
rubric over its *whole* configuration, while the features come only from what
the capture observed. The model infers a latent property from partial evidence.

That has two consequences worth stating plainly:

1. It is a **genuine inference problem** with irreducible error. Perfect
   accuracy is impossible and would indicate a leak.
2. It is a **different problem from M4's**. M4 judges the session in front of
   it, correctly, and claims nothing about what else the server would accept.

## Algorithm selection

Selection was made on the **validation** split, by measurement.

### Anomaly detection: Isolation Forest against a rarity baseline

Isolation Forest was the a priori candidate, and the reasons are about the data
rather than the algorithm's reputation: the feature space is mostly one-hot
categorical and high-dimensional relative to the sample count, so distance
metrics are close to meaningless; it needs no labelled anomalies; and it is
cheap and deterministic under a fixed seed.

The comparator is a **rarity baseline** with no learning at all: count how often
each `(version, encryption, key exchange)` combination occurred in the reference
population, and flag the rare ones.

**The baseline won, decisively.** On the held-out test split the baseline
reached precision 1.00 and recall 1.00; Isolation Forest reached precision 0.47
and recall 1.00, with nine false positives on ordinary TLS 1.2 AES-GCM sessions.
The baseline is what ships.

Why: the injected anomalies here are *combinations that do not occur in the
reference population at all*. A contingency table detects exactly that, exactly.
Isolation Forest's axis-parallel splits over sparse one-hot columns produce a
softer score — it **ranks** the anomalies correctly (AUC ≈ 0.97) but its
operating point costs precision.

This conclusion is dataset-specific and is not a general claim about Isolation
Forest. With continuous features, or with anomalies that are unusual *within*
seen combinations rather than absent from them, the ranking model would very
likely be the better choice. Both are kept in the artifact so the comparison can
be re-run.

### A threshold rule that failed, and what it taught

The first threshold rule was "the lowest cut meeting a 5% false-positive
target". It produced a detector with **recall 0.0** — while the underlying model
separated the classes at AUC 0.97.

The rule placed the threshold below almost every normal score, and therefore
below the anomalies too. The failure was entirely in the selection rule, and it
is recorded here because a badly chosen threshold can make a working model look
worthless, and the instinct in that moment is to blame the model.

The rule now in use, applied identically to every candidate: among cuts whose
validation false-positive rate is at or below 20%, take the highest validation
F1; break ties towards the lower false-positive rate.

### Classification: logistic regression, random forest, and a floor

`DummyClassifier(most_frequent)` is the floor. On validation macro-F1:
logistic regression 0.619, random forest 0.594, baseline 0.085. Logistic
regression was selected.

## Leakage controls

| Control | What it prevents |
|---|---|
| Split **before** any fitting | Preprocessing statistics leaking across the boundary |
| Group by **server instance** | A model recognising a certificate it trained on |
| Held-out **configuration families** | Overstating generalisation to unfamiliar kinds of server |
| Hand-set feature scales | Scaling constants fitted on data that includes the test split |
| Identity fields excluded | Memorising IPs, hostnames, SNI or subjects |
| Fingerprint digests excluded as numbers | Numerology on a hash |

Every one is asserted by a test in `tests/test_ml.py`.

## The protocol, in order

1. Generate the dataset from fixed seeds.
2. Drop samples below the evidence floor — not scored as normal, not scored as
   anomalous, not counted in any metric.
3. Split by server group.
4. Fit every candidate on **training** only.
5. Select models and thresholds on **validation** only.
6. Touch **test** exactly once.

## Related documents

- [ml-dataset.md](ml-dataset.md) — provenance, composition, labels
- [ml-features.md](ml-features.md) — the feature schema
- [ml-evaluation.md](ml-evaluation.md) — measured results
- [ml-model-card.md](ml-model-card.md) — what the models may and may not be used for
