"""Explanations grounded in feature statistics (M6).

Every explanation here is a statement about the **training reference
population**, computed from it and checkable against it:

    "TLS 1.0 was observed in 4.1% of the reference population."

That is a frequency, not a cause. This module never says a feature *caused* a
verdict, because neither a contingency table nor a tree ensemble's feature
importance establishes causation -- importance tells you what the model leaned
on, not what makes a configuration risky.

Nothing is invented. If a feature's value never occurred in the reference
population the frequency is ``0.0`` and says so; if the statistic was not
recorded, the field is ``None`` rather than a plausible-looking number.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Final

from ..models.ml import FeatureExplanation
from .features import SessionFeatures

__all__ = ["ReferenceStatistics", "explain_session", "EXPLANATION_LIMITATIONS"]

EXPLANATION_LIMITATIONS: Final[tuple[str, ...]] = (
    "Frequencies describe the model's training reference population, which is "
    "synthetic. They are not estimates of how common a configuration is on the "
    "internet or on any real network.",
    "A rare configuration is unusual, not unsafe. The strongest configuration "
    "on a network is often the rarest one.",
    "These are correlational statistics. No feature is claimed to cause the "
    "model's verdict.",
)

#: Explained per session. More than this and the block stops being readable;
#: the full vector is reproducible from the feature schema anyway.
_MAX_EXPLANATIONS: Final = 6

#: Explained first when present, because they are what an analyst acts on.
_PRIORITY: Final = (
    "tls_version",
    "cipher_encryption",
    "cipher_key_exchange",
    "cert_key_algorithm",
    "cert_signature_hash",
    "key_exchange_group",
    "certificate_absence_reason",
)


@dataclass(frozen=True)
class ReferenceStatistics:
    """How often each categorical value occurred in the training population."""

    counts: dict[str, Counter[str]]
    total: int

    @classmethod
    def fit(cls, rows: list[dict[str, str]]) -> ReferenceStatistics:
        counts: dict[str, Counter[str]] = {}
        for row in rows:
            for feature, value in row.items():
                counts.setdefault(feature, Counter())[value] += 1
        return cls(counts=counts, total=len(rows))

    def frequency(self, feature: str, value: str) -> float | None:
        if self.total == 0 or feature not in self.counts:
            return None
        return self.counts[feature].get(value, 0) / self.total

    def as_dict(self) -> dict[str, dict[str, int]]:
        return {
            feature: dict(counter) for feature, counter in sorted(self.counts.items())
        }

    @classmethod
    def from_dict(cls, data: dict[str, dict[str, int]], total: int) -> ReferenceStatistics:
        return cls(
            counts={feature: Counter(values) for feature, values in data.items()},
            total=total,
        )


def explain_session(
    features: SessionFeatures, statistics: ReferenceStatistics
) -> tuple[FeatureExplanation, ...]:
    """Explain a session by how unusual each of its values is.

    Ordered by rarity within the reference population, since the rarest value
    is the one a reader most wants to see first.
    """
    candidates: list[tuple[float, FeatureExplanation]] = []
    for feature in _PRIORITY:
        value = features.categorical.get(feature)
        if value is None:
            continue
        frequency = statistics.frequency(feature, value)
        if frequency is None:
            note = (
                f"{feature} was not recorded in the reference population, so no "
                "frequency can be given for it."
            )
        elif frequency == 0.0:
            note = (
                f"{value} did not occur at all in the {statistics.total}-session "
                "training reference population."
            )
        else:
            note = (
                f"{value} occurred in {frequency:.1%} of the {statistics.total}-session "
                "training reference population."
            )
        candidates.append(
            (
                frequency if frequency is not None else 1.0,
                FeatureExplanation(
                    feature=feature,
                    observed_value=value,
                    provenance=features.provenance.get(feature, "derived"),
                    reference_frequency=frequency,
                    note=note,
                ),
            )
        )
    candidates.sort(key=lambda item: (item[0], item[1].feature))
    return tuple(explanation for _, explanation in candidates[:_MAX_EXPLANATIONS])
