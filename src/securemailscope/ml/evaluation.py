"""Evaluation harness (M6).

Metrics are computed here and nowhere else, so a number in a report can be
traced to one function.

Three principles:

**Denominators are always reported.** A precision of 1.0 over two samples is
not the same claim as a precision of 1.0 over two hundred, and a reader who is
given only the ratio cannot tell them apart.

**Undefined stays undefined.** Precision with no positive predictions is
``0/0``. It is reported as ``None`` with a stated reason, not silently
converted to zero, because zero would read as "the model got everything wrong"
when in fact it predicted nothing.

**Everything is labelled synthetic.** Every result carries the environment it
was measured in. These are controlled-environment measurements over generated
data; they are not evidence of real-world detection performance, and the
wording never implies otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

__all__ = [
    "MEASUREMENT_CONTEXT",
    "BinaryMetrics",
    "MulticlassMetrics",
    "binary_metrics",
    "multiclass_metrics",
]

MEASUREMENT_CONTEXT: Final = (
    "Controlled-environment measurement over locally generated synthetic "
    "captures. Not a measurement of real-world detection performance, and not "
    "evidence of prevalence, breach likelihood or operational risk."
)


@dataclass(frozen=True)
class BinaryMetrics:
    """Binary classification results with explicit denominators."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    false_positive_rate: float | None
    undefined_reasons: dict[str, str] = field(default_factory=dict)
    support_positive: int = 0
    support_negative: int = 0
    measurement_context: str = MEASUREMENT_CONTEXT

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )

    def confusion_matrix(self) -> dict[str, int]:
        return {
            "true_positive": self.true_positives,
            "false_positive": self.false_positives,
            "true_negative": self.true_negatives,
            "false_negative": self.false_negatives,
        }


def binary_metrics(predicted: list[bool], actual: list[bool]) -> BinaryMetrics:
    """Compute binary metrics, reporting undefined ones as undefined."""
    if len(predicted) != len(actual):
        raise ValueError("predicted and actual must be the same length")
    tp = sum(1 for p, a in zip(predicted, actual, strict=True) if p and a)
    fp = sum(1 for p, a in zip(predicted, actual, strict=True) if p and not a)
    tn = sum(1 for p, a in zip(predicted, actual, strict=True) if not p and not a)
    fn = sum(1 for p, a in zip(predicted, actual, strict=True) if not p and a)

    reasons: dict[str, str] = {}
    if tp + fp == 0:
        precision = None
        reasons["precision"] = (
            "undefined: the model made no positive predictions, so the "
            "denominator is zero. This is not the same as being wrong."
        )
    else:
        precision = tp / (tp + fp)
    if tp + fn == 0:
        recall = None
        reasons["recall"] = (
            "undefined: there are no positive samples in this split, so the "
            "denominator is zero."
        )
    else:
        recall = tp / (tp + fn)
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
        reasons.setdefault(
            "f1", "undefined: precision or recall is undefined or both are zero."
        )
    else:
        f1 = 2 * precision * recall / (precision + recall)
    if fp + tn == 0:
        false_positive_rate = None
        reasons["false_positive_rate"] = (
            "undefined: there are no negative samples in this split."
        )
    else:
        false_positive_rate = fp / (fp + tn)

    return BinaryMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=false_positive_rate,
        undefined_reasons=reasons,
        support_positive=tp + fn,
        support_negative=tn + fp,
    )


@dataclass(frozen=True)
class MulticlassMetrics:
    per_class: dict[str, dict[str, float | None]]
    support: dict[str, int]
    macro_f1: float | None
    accuracy: float | None
    confusion: dict[str, dict[str, int]]
    total: int
    undefined_reasons: dict[str, str] = field(default_factory=dict)
    measurement_context: str = MEASUREMENT_CONTEXT


def multiclass_metrics(
    predicted: list[str], actual: list[str], classes: tuple[str, ...]
) -> MulticlassMetrics:
    """Per-class precision, recall and F1, plus macro-F1 and a confusion matrix."""
    if len(predicted) != len(actual):
        raise ValueError("predicted and actual must be the same length")
    confusion = {
        true: {pred: 0 for pred in classes} for true in classes
    }
    for p, a in zip(predicted, actual, strict=True):
        if a in confusion and p in confusion[a]:
            confusion[a][p] += 1

    per_class: dict[str, dict[str, float | None]] = {}
    support: dict[str, int] = {}
    reasons: dict[str, str] = {}
    f1_values: list[float] = []
    for label in classes:
        tp = confusion[label][label]
        fn = sum(confusion[label][other] for other in classes if other != label)
        fp = sum(confusion[other][label] for other in classes if other != label)
        support[label] = tp + fn
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        if precision is None:
            reasons[f"{label}.precision"] = (
                f"undefined: nothing was predicted as {label}."
            )
        if recall is None:
            reasons[f"{label}.recall"] = (
                f"undefined: no sample of class {label} is present in this split."
            )
        if precision is None or recall is None or (precision + recall) == 0:
            f1: float | None = None
            reasons.setdefault(
                f"{label}.f1", "undefined: precision or recall is undefined or zero."
            )
        else:
            f1 = 2 * precision * recall / (precision + recall)
            f1_values.append(f1)
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1}

    total = len(actual)
    correct = sum(1 for p, a in zip(predicted, actual, strict=True) if p == a)
    # Macro-F1 over the classes that are actually present. Averaging a defined
    # value with an undefined one would silently treat "absent" as "failed".
    present = [label for label in classes if support[label] > 0]
    defined = [
        value
        for label in present
        if (value := per_class[label]["f1"]) is not None
    ]
    macro = sum(defined) / len(present) if present and defined else None
    if macro is None:
        reasons["macro_f1"] = "undefined: no class had a defined F1 in this split."

    return MulticlassMetrics(
        per_class=per_class,
        support=support,
        macro_f1=macro,
        accuracy=(correct / total) if total else None,
        confusion={true: dict(row) for true, row in confusion.items()},
        total=total,
        undefined_reasons=reasons,
    )


def as_dict(metrics: Any) -> dict[str, Any]:
    """Serialise metrics for the evaluation report."""
    from dataclasses import asdict

    return asdict(metrics)
