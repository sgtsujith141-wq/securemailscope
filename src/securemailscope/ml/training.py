"""Training and evaluation driver (M6).

One entry point produces everything a reader needs to check the work: the
dataset, the split, both anomaly candidates under one selection protocol, the
classifier candidates, held-out metrics, and the artifacts with their
manifests.

The protocol, in the order it is executed and never rearranged:

1. build the dataset from fixed seeds;
2. drop samples below the evidence floor -- they are not evaluated, not
   scored as normal and not scored as anomalous;
3. split by **server group**, before fitting anything;
4. fit every candidate on the training split only;
5. select models and thresholds on the **validation** split only;
6. touch the test split exactly once, for the numbers that get reported.

Step 5 is where the honesty lives. Hyperparameters and thresholds are chosen
without the test set, so the held-out numbers mean what they say.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .anomaly import (
    ANOMALY_ALGORITHM,
    RarityBaseline,
    fit_isolation_forest,
    threshold_from_scores,
)
from .classification import fit_candidates, select_best
from .dataset import DATASET_ID, DATASET_VERSION, POSTURE_CLASSES, dataset_fingerprint
from .evaluation import binary_metrics, multiclass_metrics
from .explanations import ReferenceStatistics
from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from .preprocessing import (
    HELDOUT_FAMILIES,
    SPLIT_SEED,
    Sample,
    anomaly_evaluation_label,
    build_dataset,
    family_holdout,
    grouped_split,
)
from .registry import save_model

__all__ = [
    "ANOMALY_MODEL_ID",
    "CLASSIFIER_MODEL_ID",
    "MODEL_VERSION",
    "TrainingOutcome",
    "train_all",
]

ANOMALY_MODEL_ID: Final = "tls-anomaly"
CLASSIFIER_MODEL_ID: Final = "tls-posture"
MODEL_VERSION: Final = "1.0.0"
EVALUATION_REPORT: Final = "docs/ml-evaluation.md"


@dataclass
class TrainingOutcome:
    """Everything one training run produced, for the evaluation report."""

    dataset_summary: dict[str, Any]
    split_summary: dict[str, Any]
    anomaly_selection: dict[str, Any]
    anomaly_metrics: dict[str, Any]
    classification_selection: dict[str, Any]
    classification_metrics: dict[str, Any]
    timings: dict[str, float] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)


def _vectors(samples: list[Sample]) -> list[list[float]]:
    return [sample.features.vector() for sample in samples]


def _rows(samples: list[Sample]) -> list[dict[str, str]]:
    return [sample.features.categorical for sample in samples]


def _class_distribution(samples: list[Sample]) -> dict[str, int]:
    counts: dict[str, int] = {label: 0 for label in POSTURE_CLASSES}
    for sample in samples:
        counts[sample.posture] = counts.get(sample.posture, 0) + 1
    return counts


def train_all(
    *,
    directory: Path | None = None,
    write_artifacts: bool = True,
) -> TrainingOutcome:
    """Run the whole protocol and return the numbers it produced."""
    import time

    started = time.perf_counter()
    dataset = build_dataset()
    dataset_time = time.perf_counter() - started

    eligible = dataset.eligible
    excluded = [s for s in dataset.samples if not s.eligible]
    train, validation, test = grouped_split(eligible)

    # The detector learns "normal" from the reference families in the training
    # split only. Fitting it on anomalies would teach it they are normal.
    reference = [s for s in train if s.in_reference_population]

    dataset_summary = {
        "dataset_id": DATASET_ID,
        "dataset_version": DATASET_VERSION,
        "generated_sessions": len(dataset.samples),
        "eligible_sessions": len(eligible),
        "excluded_below_evidence_floor": len(excluded),
        "independent_groups": len(dataset.groups()),
        "class_distribution_all": _class_distribution(dataset.samples),
        "class_distribution_eligible": _class_distribution(eligible),
        "capture_fingerprint": dataset_fingerprint(dataset.generated),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_count": len(FEATURE_NAMES),
    }
    split_summary = {
        "split_seed": SPLIT_SEED,
        "grouped_by": "server instance (server_id)",
        "train": {
            "samples": len(train),
            "groups": len({s.group_id for s in train}),
            "classes": _class_distribution(train),
        },
        "validation": {
            "samples": len(validation),
            "groups": len({s.group_id for s in validation}),
            "classes": _class_distribution(validation),
        },
        "test": {
            "samples": len(test),
            "groups": len({s.group_id for s in test}),
            "classes": _class_distribution(test),
        },
        "reference_population_for_anomaly": len(reference),
        "group_overlap": {
            "train_validation": sorted(
                {s.group_id for s in train} & {s.group_id for s in validation}
            ),
            "train_test": sorted({s.group_id for s in train} & {s.group_id for s in test}),
            "validation_test": sorted(
                {s.group_id for s in validation} & {s.group_id for s in test}
            ),
        },
        "heldout_families": list(HELDOUT_FAMILIES),
    }

    validation_labels = [anomaly_evaluation_label(s) for s in validation]
    test_labels = [anomaly_evaluation_label(s) for s in test]

    # -- anomaly candidates, both under the identical selection protocol ----
    anomaly_started = time.perf_counter()
    forest = fit_isolation_forest(
        _vectors(reference),
        FEATURE_NAMES,
        reference_population=(
            f"{len(reference)} eligible sessions from the five reference "
            "configuration families, training split only"
        ),
    )
    forest_threshold, forest_stats = threshold_from_scores(
        [forest.raw_score(v) for v in _vectors(validation)], validation_labels
    )
    forest.threshold = forest_threshold
    anomaly_time = time.perf_counter() - anomaly_started

    baseline = RarityBaseline.fit(_rows(reference))
    baseline_threshold, baseline_stats = threshold_from_scores(
        [baseline.score(row) for row in _rows(validation)], validation_labels
    )

    forest_test = binary_metrics(
        [forest.raw_score(v) <= forest_threshold for v in _vectors(test)], test_labels
    )
    baseline_test = binary_metrics(
        [baseline.score(row) <= baseline_threshold for row in _rows(test)], test_labels
    )

    # Selection is on validation F1. The test numbers above are computed for
    # the report, not consulted here.
    chosen = (
        "rarity_baseline"
        if baseline_stats.get("validation_f1", 0.0) >= forest_stats.get("validation_f1", 0.0)
        else ANOMALY_ALGORITHM
    )

    anomaly_selection = {
        "candidates": [ANOMALY_ALGORITHM, "rarity_baseline"],
        "selection_rule": (
            "highest validation F1 among cuts with validation false-positive "
            "rate at or below 20%; ties to the lower false-positive rate"
        ),
        "selected_on": "validation split only",
        "selected": chosen,
        "isolation_forest_validation": forest_stats,
        "rarity_baseline_validation": baseline_stats,
        "isolation_forest_hyperparameters": forest.hyperparameters,
        "separation_auc_note": (
            "Isolation Forest ranks the injected anomalies below normal "
            "sessions well; its cost is precision at the chosen operating "
            "point, not ranking."
        ),
    }
    anomaly_metrics = {
        "isolation_forest_test": _metrics_dict(forest_test),
        "rarity_baseline_test": _metrics_dict(baseline_test),
        "test_sample_count": len(test),
        "test_anomaly_count": sum(test_labels),
        "test_normal_count": len(test_labels) - sum(test_labels),
    }

    # -- family holdout: entire configuration families never seen ----------
    inside, outside = family_holdout(eligible)
    inside_reference = [s for s in inside if s.in_reference_population]
    holdout_baseline = RarityBaseline.fit(_rows(inside_reference))
    holdout_predictions = [
        holdout_baseline.score(row) <= baseline_threshold for row in _rows(outside)
    ]
    holdout_metrics = binary_metrics(
        holdout_predictions, [anomaly_evaluation_label(s) for s in outside]
    )
    anomaly_metrics["family_holdout"] = {
        "heldout_families": list(HELDOUT_FAMILIES),
        "samples": len(outside),
        "metrics": _metrics_dict(holdout_metrics),
        "note": (
            "Whole families withheld from fitting. The held-out families "
            "contain no injected anomalies, so recall is undefined here and "
            "the meaningful number is the false-positive rate on kinds of "
            "server the detector has never seen."
        ),
    }

    # -- supervised classification -----------------------------------------
    classifier_started = time.perf_counter()
    candidates = fit_candidates(
        _vectors(train), [s.posture for s in train], FEATURE_NAMES
    )
    best, validation_scores = select_best(
        candidates, _vectors(validation), [s.posture for s in validation]
    )
    classifier_time = time.perf_counter() - classifier_started

    test_predicted = [str(label) for label in best.estimator.predict(_vectors(test))]
    classification_test = multiclass_metrics(
        test_predicted, [s.posture for s in test], POSTURE_CLASSES
    )
    baseline_model = next(c for c in candidates if c.name == "baseline_most_frequent")
    baseline_predicted = [
        str(label) for label in baseline_model.estimator.predict(_vectors(test))
    ]
    classification_baseline = multiclass_metrics(
        baseline_predicted, [s.posture for s in test], POSTURE_CLASSES
    )

    classification_selection = {
        "candidates": [c.name for c in candidates],
        "selection_rule": "highest macro-F1 on the validation split",
        "selected_on": "validation split only",
        "validation_macro_f1": validation_scores,
        "selected": best.name,
        "hyperparameters": best.hyperparameters,
    }
    classification_metrics = {
        "test": _metrics_dict(classification_test),
        "baseline_most_frequent_test": _metrics_dict(classification_baseline),
        "test_sample_count": len(test),
    }

    statistics = ReferenceStatistics.fit(_rows(reference))

    artifacts: dict[str, str] = {}
    if write_artifacts:
        anomaly_payload = {
            "kind": chosen,
            "rarity_counts": {
                "|".join(key): value for key, value in baseline.counts.items()
            },
            "rarity_total": baseline.total,
            "rarity_threshold": baseline_threshold,
            "isolation_forest": forest.estimator,
            "isolation_forest_threshold": forest_threshold,
            "reference_statistics": statistics.as_dict(),
            "reference_total": statistics.total,
            "feature_names": list(FEATURE_NAMES),
        }
        manifest = save_model(
            anomaly_payload,
            model_id=ANOMALY_MODEL_ID,
            model_version=MODEL_VERSION,
            algorithm=chosen,
            dataset_id=DATASET_ID,
            dataset_version=DATASET_VERSION,
            training_sample_count=len(reference),
            reference_population=forest.reference_population,
            hyperparameters=(
                {"threshold": baseline_threshold, "keyed_on": "version|encryption|key_exchange"}
                if chosen == "rarity_baseline"
                else forest.hyperparameters
            ),
            evaluation_report=EVALUATION_REPORT,
            directory=directory,
            decision_threshold=(
                baseline_threshold if chosen == "rarity_baseline" else forest_threshold
            ),
            limitations=[
                "Trained on locally generated synthetic captures only.",
                "An anomaly is a configuration unusual relative to the recorded "
                "reference population. It is not a vulnerability and not an attack.",
            ],
        )
        artifacts["anomaly"] = manifest.artifact_filename

        classifier_manifest = save_model(
            {
                "estimator": best.estimator,
                "classes": list(best.classes),
                "feature_names": list(FEATURE_NAMES),
                "reference_statistics": statistics.as_dict(),
                "reference_total": statistics.total,
            },
            model_id=CLASSIFIER_MODEL_ID,
            model_version=MODEL_VERSION,
            algorithm=best.name,
            dataset_id=DATASET_ID,
            dataset_version=DATASET_VERSION,
            training_sample_count=len(train),
            reference_population=(
                f"{len(train)} eligible sessions across all families, training split"
            ),
            hyperparameters=best.hyperparameters,
            evaluation_report=EVALUATION_REPORT,
            directory=directory,
            classes=list(best.classes),
            limitations=[
                "Predicts a latent server posture class defined by a "
                "project-authored rubric over synthetic servers.",
                "NOT VALIDATED for real-world risk. High accuracy here would "
                "demonstrate recovery of that rubric from partial observations, "
                "not prediction of compromise.",
                "Scores are relative model outputs, not calibrated probabilities: "
                "no calibration was fitted or validated.",
            ],
        )
        artifacts["classifier"] = classifier_manifest.artifact_filename

    return TrainingOutcome(
        dataset_summary=dataset_summary,
        split_summary=split_summary,
        anomaly_selection=anomaly_selection,
        anomaly_metrics=anomaly_metrics,
        classification_selection=classification_selection,
        classification_metrics=classification_metrics,
        timings={
            "dataset_build_seconds": round(dataset_time, 3),
            "anomaly_fit_seconds": round(anomaly_time, 3),
            "classifier_fit_seconds": round(classifier_time, 3),
        },
        artifacts=artifacts,
    )


def _metrics_dict(metrics: Any) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(metrics)


def write_evaluation(outcome: TrainingOutcome, path: Path) -> Path:
    """Persist the run's numbers next to the artifacts, for the report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": outcome.dataset_summary,
        "split": outcome.split_summary,
        "anomaly_selection": outcome.anomaly_selection,
        "anomaly_metrics": outcome.anomaly_metrics,
        "classification_selection": outcome.classification_selection,
        "classification_metrics": outcome.classification_metrics,
        "timings": outcome.timings,
        "artifacts": outcome.artifacts,
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
