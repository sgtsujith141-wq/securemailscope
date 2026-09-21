"""Supervised posture classification (M6).

## What is being predicted, and why it is not M4 in disguise

The target is the **server's latent posture class**: a property of the server's
whole configuration, assigned by the documented rubric in
:func:`securemailscope.ml.dataset.posture_class`. A single captured session
reveals only part of that configuration -- a server that still permits RC4 does
not advertise the fact to a client that never offers it.

So the model infers a latent property from partial evidence. That is a genuine
inference problem with irreducible error, and it is a *different* problem from
the one M4 solves: M4 judges the session in front of it, correctly and
deterministically, and makes no claim about what else the server would accept.

No M4 score, severity or rule outcome is a feature or a label. The assessment
layer is switched off while the dataset is built.

## What this cannot establish

The labels are produced by a rubric this project wrote. A model that predicts
them well has learned to recover that rubric's verdict from partial
observations. It has **not** been shown to predict real-world compromise,
breach likelihood or operational risk, and no such claim is made anywhere.

The rubric is informed by RFC 9325 and the widely used Mozilla TLS
configuration tiers, so it is not arbitrary -- but it is a project-defined
ordering applied to synthetic servers, and the evaluation says so on every
metric it reports.

## Models

A ``DummyClassifier`` on the majority class is the floor: any model that cannot
beat it has learned nothing. ``LogisticRegression`` and a small
``RandomForestClassifier`` are the candidates, selected on the **validation**
split only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "CLASSIFIER_SEED",
    "ClassificationStatus",
    "ClassifierModel",
    "fit_candidates",
    "select_best",
]

CLASSIFIER_SEED: Final = 20260921


class ClassificationStatus(StrEnum):
    PREDICTED = "PREDICTED"
    #: Evidence below the eligibility floor.
    NOT_EVALUABLE = "NOT_EVALUABLE"
    #: The model declined to answer; the reason is reported with it.
    ABSTAINED = "ABSTAINED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"


@dataclass
class ClassifierModel:
    """A fitted classifier with the provenance needed to reproduce it."""

    name: str
    estimator: Any
    classes: tuple[str, ...]
    feature_names: tuple[str, ...]
    training_sample_count: int
    hyperparameters: dict[str, Any]
    #: Below this maximum class probability the model abstains rather than
    #: guessing. Selected on validation, frozen before the test split.
    abstention_floor: float = 0.0

    def predict(
        self, vector: list[float]
    ) -> tuple[ClassificationStatus, str | None, dict[str, float]]:
        """Predict, or abstain when no class is clearly preferred.

        The returned mapping is the estimator's ``predict_proba`` output. It is
        reported as a **relative score, not a calibrated probability**: no
        calibration was fitted or validated, and the model card says so.
        """
        probabilities = self.estimator.predict_proba([vector])[0]
        scores = {
            label: float(value)
            for label, value in zip(self.classes, probabilities, strict=True)
        }
        best = max(scores, key=lambda label: scores[label])
        if scores[best] < self.abstention_floor:
            return ClassificationStatus.ABSTAINED, None, scores
        return ClassificationStatus.PREDICTED, best, scores


def fit_candidates(
    vectors: list[list[float]],
    labels: list[str],
    feature_names: tuple[str, ...],
    *,
    seed: int = CLASSIFIER_SEED,
) -> list[ClassifierModel]:
    """Fit the baseline and the candidate classifiers on the training split."""
    from sklearn.dummy import DummyClassifier
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    specs: list[tuple[str, Any, dict[str, Any]]] = [
        (
            "baseline_most_frequent",
            DummyClassifier(strategy="most_frequent"),
            {"strategy": "most_frequent"},
        ),
        (
            "logistic_regression",
            LogisticRegression(
                # multi_class is not passed: scikit-learn 1.5 deprecated it and
                # already defaults to multinomial for this solver.
                max_iter=2000,
                class_weight="balanced",
                random_state=seed,
            ),
            {"max_iter": 2000, "class_weight": "balanced", "random_state": seed},
        ),
        (
            "random_forest",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=8,
                min_samples_leaf=3,
                class_weight="balanced",
                random_state=seed,
                n_jobs=1,
            ),
            {
                "n_estimators": 300,
                "max_depth": 8,
                "min_samples_leaf": 3,
                "class_weight": "balanced",
                "random_state": seed,
            },
        ),
    ]
    models: list[ClassifierModel] = []
    for name, estimator, hyperparameters in specs:
        estimator.fit(vectors, labels)
        models.append(
            ClassifierModel(
                name=name,
                estimator=estimator,
                classes=tuple(str(label) for label in estimator.classes_),
                feature_names=feature_names,
                training_sample_count=len(vectors),
                hyperparameters=hyperparameters,
            )
        )
    return models


def select_best(
    models: list[ClassifierModel],
    validation_vectors: list[list[float]],
    validation_labels: list[str],
) -> tuple[ClassifierModel, dict[str, float]]:
    """Select on **validation** macro-F1. The test split is never consulted.

    Macro-F1 rather than accuracy, because the classes are imbalanced and
    accuracy would reward ignoring the small ones.
    """
    from sklearn.metrics import f1_score

    scores: dict[str, float] = {}
    for model in models:
        predicted = model.estimator.predict(validation_vectors)
        scores[model.name] = float(
            f1_score(validation_labels, predicted, average="macro", zero_division=0)
        )
    best_name = max(scores, key=lambda name: scores[name])
    best = next(model for model in models if model.name == best_name)
    return best, scores
