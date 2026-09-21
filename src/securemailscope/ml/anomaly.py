"""Anomaly detection over observed TLS configurations (M6).

## What "anomalous" means here, and what it does not

An anomaly is a configuration that is **unusual relative to a stated reference
population**. It is not a vulnerability, it is not an attack, and it is not
evidence of intent. A rare configuration may be the strongest one on the
network; the `hardened_uncommon` family in the dataset exists precisely to keep
that possibility in front of us.

The reference population is recorded in the model metadata, because "unusual"
is meaningless without it. Change the population and the same session may stop
being unusual, which is a property of the question rather than a defect.

## Why Isolation Forest

The choice is justified by the shape of the problem, not by novelty:

* The feature space is mostly **one-hot categorical** and high-dimensional
  relative to the sample count. Isolation Forest partitions on single features
  and needs no distance metric, which matters because Euclidean distance over
  one-hot columns is close to meaningless.
* It needs **no labelled anomalies** to fit, which is the honest situation: we
  have a reference population of normal configurations and no real corpus of
  attacks.
* It is **cheap and deterministic** under a fixed seed, so inference stays
  local, bounded and reproducible.
* Its output is an ordering, not a probability -- and this module never treats
  it as one.

The alternative considered and implemented as a comparator is a **rarity
baseline** with no learning at all: score each session by how often its
(version, encryption, key-exchange) combination occurred in the reference
population. If that does as well, the forest earns nothing, and the evaluation
says so rather than defending the more complicated choice.

## Thresholds

The decision threshold is selected on the **validation** split and frozen
before the test split is touched. ``decision_function`` is an isolation score,
not a calibrated probability of anything, and is never presented as one.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "ANOMALY_ALGORITHM",
    "threshold_from_scores",
    "AnomalyStatus",
    "RarityBaseline",
    "AnomalyModel",
    "fit_isolation_forest",
    "select_threshold",
]

ANOMALY_ALGORITHM: Final = "IsolationForest"

#: Fixed so a training run reproduces exactly.
ANOMALY_SEED: Final = 20260921

#: Chosen a priori from the generator's design -- the injected-anomaly family
#: is a small minority of the population -- and not tuned on the test split.
ANOMALY_CONTAMINATION: Final = 0.05
ANOMALY_ESTIMATORS: Final = 200
ANOMALY_MAX_SAMPLES: Final = 256


class AnomalyStatus(StrEnum):
    ANOMALOUS = "ANOMALOUS"
    NOT_ANOMALOUS = "NOT_ANOMALOUS"
    #: Too little evidence for the question to be meaningful.
    NOT_EVALUABLE = "NOT_EVALUABLE"
    #: No model is installed, or it could not be loaded.
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"


@dataclass
class RarityBaseline:
    """A non-ML comparator: how often was this combination seen before?

    Deliberately simple. Its job is to make the forest justify itself: a
    complicated model that cannot beat counting has not earned its place.
    """

    counts: Counter[tuple[str, str, str]]
    total: int

    @classmethod
    def fit(cls, categorical_rows: list[dict[str, str]]) -> RarityBaseline:
        counts: Counter[tuple[str, str, str]] = Counter()
        for row in categorical_rows:
            counts[cls._key(row)] += 1
        return cls(counts=counts, total=len(categorical_rows))

    @staticmethod
    def _key(row: dict[str, str]) -> tuple[str, str, str]:
        return (
            row.get("tls_version", "MISSING"),
            row.get("cipher_encryption", "MISSING"),
            row.get("cipher_key_exchange", "MISSING"),
        )

    def score(self, row: dict[str, str]) -> float:
        """Frequency of this combination. Lower means rarer."""
        if self.total == 0:
            return 0.0
        return self.counts.get(self._key(row), 0) / self.total

    def predict(self, row: dict[str, str], threshold: float) -> bool:
        """True when the combination is rarer than the threshold."""
        return self.score(row) <= threshold


@dataclass
class AnomalyModel:
    """A fitted Isolation Forest and everything needed to reproduce it."""

    estimator: Any
    threshold: float
    feature_names: tuple[str, ...]
    reference_population: str
    training_sample_count: int
    hyperparameters: dict[str, Any]

    def raw_score(self, vector: list[float]) -> float:
        """The isolation score. Higher is more normal.

        This is an ordering statistic. It is not a probability, and nothing in
        this codebase converts it into one.
        """
        return float(self.estimator.decision_function([vector])[0])

    def predict(self, vector: list[float]) -> tuple[AnomalyStatus, float]:
        score = self.raw_score(vector)
        status = (
            AnomalyStatus.ANOMALOUS
            if score <= self.threshold
            else AnomalyStatus.NOT_ANOMALOUS
        )
        return status, score


def fit_isolation_forest(
    vectors: list[list[float]],
    feature_names: tuple[str, ...],
    *,
    reference_population: str,
    seed: int = ANOMALY_SEED,
) -> AnomalyModel:
    """Fit on the reference population only."""
    from sklearn.ensemble import IsolationForest

    estimator = IsolationForest(
        n_estimators=ANOMALY_ESTIMATORS,
        max_samples=min(ANOMALY_MAX_SAMPLES, len(vectors)),
        contamination=ANOMALY_CONTAMINATION,
        random_state=seed,
        n_jobs=1,
    )
    estimator.fit(vectors)
    return AnomalyModel(
        estimator=estimator,
        # Replaced by select_threshold on the validation split. Starting from
        # the estimator's own offset makes the unset state harmless rather
        # than arbitrary.
        threshold=float(estimator.offset_),
        feature_names=feature_names,
        reference_population=reference_population,
        training_sample_count=len(vectors),
        hyperparameters={
            "n_estimators": ANOMALY_ESTIMATORS,
            "max_samples": min(ANOMALY_MAX_SAMPLES, len(vectors)),
            "contamination": ANOMALY_CONTAMINATION,
            "random_state": seed,
        },
    )


def select_threshold(
    model: AnomalyModel,
    validation_vectors: list[list[float]],
    validation_labels: list[bool],
    *,
    max_false_positive_rate: float = 0.20,
) -> tuple[float, dict[str, float]]:
    """Choose the threshold on the **validation** split, then freeze it.

    The rule, fixed in advance and applied identically to every candidate
    detector so the comparison is fair: among the candidate cuts whose
    validation false-positive rate is at or below ``max_false_positive_rate``,
    take the one with the highest validation F1; break ties towards the lower
    false-positive rate.

    An earlier rule -- "the lowest cut meeting a 5% false-positive target" --
    was discarded during development because it was not a selection rule at
    all. It placed the threshold below almost every normal score and therefore
    below the anomalies too, producing a detector that flagged nothing and a
    recall of zero, while the underlying model separated the classes with an
    AUC of 0.97. The failure was in the rule, not the model, and it is recorded
    here because a threshold chosen badly can make a working detector look
    useless.

    Returns the threshold and the validation statistics behind it, so the
    choice is auditable rather than asserted.
    """
    scores = [model.raw_score(vector) for vector in validation_vectors]
    return threshold_from_scores(
        scores, validation_labels, max_false_positive_rate=max_false_positive_rate
    )


def threshold_from_scores(
    scores: list[float],
    labels: list[bool],
    *,
    max_false_positive_rate: float = 0.20,
    lower_is_more_anomalous: bool = True,
) -> tuple[float, dict[str, float]]:
    """The shared selection rule, so every detector is tuned identically.

    Kept separate from any one model so the rarity baseline and the forest are
    held to exactly the same protocol; a comparison in which the candidates
    were tuned differently would not be a comparison.
    """
    normal = [score for score, label in zip(scores, labels, strict=True) if not label]
    anomalous = [score for score, label in zip(scores, labels, strict=True) if label]
    if not normal or not anomalous:
        return (
            (min(scores) if scores else 0.0),
            {
                "threshold": min(scores) if scores else 0.0,
                "validation_normal_count": float(len(normal)),
                "validation_anomaly_count": float(len(anomalous)),
                "undefined": 1.0,
            },
        )

    best: tuple[float, float, float, float] | None = None
    for candidate in sorted(set(scores)):
        if lower_is_more_anomalous:
            flagged_normal = sum(1 for score in normal if score <= candidate)
            caught = sum(1 for score in anomalous if score <= candidate)
        else:  # pragma: no cover - reserved for a higher-is-worse detector
            flagged_normal = sum(1 for score in normal if score >= candidate)
            caught = sum(1 for score in anomalous if score >= candidate)
        false_positive_rate = flagged_normal / len(normal)
        if false_positive_rate > max_false_positive_rate:
            continue
        precision = caught / (caught + flagged_normal) if (caught + flagged_normal) else 0.0
        recall = caught / len(anomalous)
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        key = (f1, -false_positive_rate)
        if best is None or key > (best[1], -best[2]):
            best = (candidate, f1, false_positive_rate, recall)

    if best is None:
        # No cut satisfies the cap. Refuse to flag rather than adopt a
        # threshold the operator did not accept.
        threshold = min(scores) - 1.0
        return threshold, {
            "threshold": threshold,
            "validation_normal_count": float(len(normal)),
            "validation_anomaly_count": float(len(anomalous)),
            "validation_false_positive_rate": 0.0,
            "validation_recall": 0.0,
            "validation_f1": 0.0,
            "max_false_positive_rate": max_false_positive_rate,
            "no_cut_met_the_cap": 1.0,
        }

    threshold, f1, false_positive_rate, recall = best
    return threshold, {
        "threshold": threshold,
        "validation_normal_count": float(len(normal)),
        "validation_anomaly_count": float(len(anomalous)),
        "validation_false_positive_rate": false_positive_rate,
        "validation_recall": recall,
        "validation_f1": f1,
        "max_false_positive_rate": max_false_positive_rate,
    }
