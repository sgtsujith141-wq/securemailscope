#!/usr/bin/env python3
"""Reproduce the M6 training run and its evaluation.

    python scripts/train_ml.py                 # train, evaluate, write artifacts
    python scripts/train_ml.py --no-artifacts  # evaluate without writing models

Everything is local and seeded. The dataset is generated from fixed seeds, the
split is grouped by server before anything is fitted, models and thresholds are
chosen on the validation split, and the test split is touched exactly once.

Running this should reproduce the numbers in docs/ml-evaluation.md. Certificate
keys are freshly minted each run, so capture bytes vary by a byte or two inside
the certificate; the dataset's content digest, the split and the labels do not.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from securemailscope.ml.training import train_all, write_evaluation  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-artifacts",
        action="store_true",
        help="Evaluate without writing model artifacts.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / "src" / "securemailscope" / "ml" / "artifacts" / "evaluation.json",
        help="Where to write the evaluation record.",
    )
    args = parser.parse_args(argv)

    outcome = train_all(write_artifacts=not args.no_artifacts)
    path = write_evaluation(outcome, args.output)

    dataset = outcome.dataset_summary
    print(
        f"dataset      {dataset['generated_sessions']} sessions, "
        f"{dataset['eligible_sessions']} eligible, "
        f"{dataset['independent_groups']} independent groups"
    )
    print(f"             content digest {dataset['capture_fingerprint']}")
    split = outcome.split_summary
    print(
        f"split        train {split['train']['samples']}/"
        f"{split['train']['groups']}g  "
        f"val {split['validation']['samples']}/{split['validation']['groups']}g  "
        f"test {split['test']['samples']}/{split['test']['groups']}g"
    )
    overlap = split["group_overlap"]
    print(
        "             group overlap: "
        + ("none" if not any(overlap.values()) else json.dumps(overlap))
    )

    selection = outcome.anomaly_selection
    print(f"anomaly      selected {selection['selected']} on validation")
    for name, key in (
        ("isolation forest", "isolation_forest_test"),
        ("rarity baseline", "rarity_baseline_test"),
    ):
        metrics = outcome.anomaly_metrics[key]
        print(
            f"             {name:17s} P={_fmt(metrics['precision'])} "
            f"R={_fmt(metrics['recall'])} F1={_fmt(metrics['f1'])} "
            f"FPR={_fmt(metrics['false_positive_rate'])} "
            f"(TP{metrics['true_positives']} FP{metrics['false_positives']} "
            f"TN{metrics['true_negatives']} FN{metrics['false_negatives']})"
        )
    holdout = outcome.anomaly_metrics["family_holdout"]["metrics"]
    print(
        f"             family holdout    FPR={_fmt(holdout['false_positive_rate'])} "
        f"over {holdout['support_negative']} unseen-family sessions"
    )

    classification = outcome.classification_metrics["test"]
    print(
        f"classifier   {outcome.classification_selection['selected']}: "
        f"macro-F1 {_fmt(classification['macro_f1'])}, "
        f"accuracy {_fmt(classification['accuracy'])} "
        f"(baseline macro-F1 "
        f"{_fmt(outcome.classification_metrics['baseline_most_frequent_test']['macro_f1'])})"
    )
    print(f"timings      {outcome.timings}")
    if outcome.artifacts:
        print(f"artifacts    {', '.join(sorted(outcome.artifacts.values()))}")
    print(f"evaluation   {path}")
    return 0


def _fmt(value: float | None) -> str:
    return "undefined" if value is None else f"{value:.4f}"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
