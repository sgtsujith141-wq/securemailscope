"""Dataset assembly and group-aware splitting (M6).

The split happens **before** anything is fitted, and it is grouped by the
*server instance* rather than by the sample.

Why grouping matters here specifically: this dataset generates several sessions
per server, all sharing one certificate and one configuration. A random split
would put a server's sessions on both sides of the boundary, and a model could
score well by recognising a certificate it had already seen. That is
memorisation wearing generalisation's clothes, and it is the single easiest way
to produce an impressive and worthless number.

Two evaluations are therefore produced:

* a **grouped random split**, where no server appears in more than one
  partition; and
* a **held-out configuration family**, where entire families are withheld, so
  the test set contains kinds of server the model has never seen.

The second is the harder and more honest measurement, and both are reported.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

from ..config import AnalysisConfig
from ..pipeline import analyze_capture
from .dataset import (
    ANOMALY_FAMILY,
    NEGATIVE_CONTROL_FAMILY,
    REFERENCE_FAMILIES,
    GeneratedSession,
    generate_sessions,
    write_captures,
)
from .features import EligibilityStatus, SessionFeatures, extract_from_result

__all__ = [
    "SPLIT_SEED",
    "Sample",
    "Dataset",
    "build_dataset",
    "grouped_split",
    "family_holdout",
]

SPLIT_SEED: Final = 4242

#: Withheld entirely from training in the family-holdout evaluation. Chosen
#: before any model was fitted: one common family and one rare-but-legitimate
#: one, so the holdout tests both ordinary and unfamiliar generalisation.
HELDOUT_FAMILIES: Final[tuple[str, ...]] = ("legacy_compatible", NEGATIVE_CONTROL_FAMILY)


@dataclass(frozen=True)
class Sample:
    """One dataset row: observed features plus its independent labels."""

    sample_id: str
    #: The grouping key. Every session from one server stays together.
    group_id: str
    family: str
    features: SessionFeatures
    #: ML evaluation label: the server's latent posture class.
    posture: str
    #: True when drawn from the injected-anomaly family.
    injected_anomaly: bool
    #: True when drawn from the rare-but-legitimate negative control.
    negative_control: bool
    #: Forensic ground truth, retained to check the analyzer, never a feature.
    forensic_version: int | None = None
    forensic_suite: int | None = None

    @property
    def eligible(self) -> bool:
        return self.features.eligibility is EligibilityStatus.ELIGIBLE

    @property
    def in_reference_population(self) -> bool:
        """Whether this sample defines what 'normal' means for this dataset."""
        return self.family in REFERENCE_FAMILIES


@dataclass(frozen=True)
class Dataset:
    samples: list[Sample]
    generated: list[GeneratedSession] = field(repr=False, default_factory=list)

    @property
    def eligible(self) -> list[Sample]:
        return [sample for sample in self.samples if sample.eligible]

    def groups(self) -> set[str]:
        return {sample.group_id for sample in self.samples}


def build_dataset(
    *, sessions_per_server: int = 4, config: AnalysisConfig | None = None
) -> Dataset:
    """Generate captures, analyse them for real, and read out features.

    The assessment layer is switched off while building the dataset. The ML
    task must not see M4's conclusions even incidentally: a feature derived
    from a posture score would make the model an expensive way of reproducing
    a rule engine.
    """
    analysis_config = config or AnalysisConfig(assess_security=False)
    generated = generate_sessions(sessions_per_server=sessions_per_server)
    samples: list[Sample] = []
    with TemporaryDirectory() as directory:
        paths = write_captures(generated, Path(directory))
        for session in generated:
            result = analyze_capture(paths[session.sample_id], config=analysis_config)
            extracted = extract_from_result(result)
            if not extracted:
                continue
            samples.append(
                Sample(
                    sample_id=session.sample_id,
                    group_id=session.server.server_id,
                    family=session.family,
                    features=extracted[0],
                    posture=session.posture,
                    injected_anomaly=session.injected_anomaly,
                    negative_control=session.negative_control,
                    forensic_version=session.negotiated_version,
                    forensic_suite=session.negotiated_suite,
                )
            )
    return Dataset(samples=samples, generated=generated)


def grouped_split(
    samples: list[Sample],
    *,
    seed: int = SPLIT_SEED,
    train: float = 0.6,
    validation: float = 0.2,
) -> tuple[list[Sample], list[Sample], list[Sample]]:
    """Split by **group**, so no server spans two partitions.

    Groups are shuffled, not samples. A server contributes all of its sessions
    to exactly one side, which is what stops the model recognising a
    certificate it has already been trained on.
    """
    groups = sorted({sample.group_id for sample in samples})
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not cryptography
    rng.shuffle(groups)
    train_end = int(len(groups) * train)
    validation_end = train_end + int(len(groups) * validation)
    assignment = {}
    for index, group in enumerate(groups):
        if index < train_end:
            assignment[group] = 0
        elif index < validation_end:
            assignment[group] = 1
        else:
            assignment[group] = 2
    buckets: tuple[list[Sample], list[Sample], list[Sample]] = ([], [], [])
    for sample in samples:
        buckets[assignment[sample.group_id]].append(sample)
    return buckets


def family_holdout(
    samples: list[Sample], *, heldout: tuple[str, ...] = HELDOUT_FAMILIES
) -> tuple[list[Sample], list[Sample]]:
    """Withhold whole configuration families from training.

    The harder generalisation question: not "can it handle an unseen server of
    a familiar kind" but "can it handle a kind of server it has never seen".
    """
    inside = [sample for sample in samples if sample.family not in heldout]
    outside = [sample for sample in samples if sample.family in heldout]
    return inside, outside


def reference_population(samples: list[Sample]) -> list[Sample]:
    """Samples that define 'normal'.

    The anomaly detector is fitted on these alone. Recording which population
    unusualness is measured against is not bookkeeping: an unusual TLS
    configuration is only unusual relative to something.
    """
    return [
        sample
        for sample in samples
        if sample.eligible and sample.in_reference_population
    ]


def anomaly_evaluation_label(sample: Sample) -> bool:
    """The independent evaluation label for anomaly detection.

    ``True`` for a sample drawn from the injected-anomaly family, ``False``
    otherwise -- including the rare-but-legitimate negative control, which is
    deliberately labelled *not* anomalous. Declared here, before training, and
    never derived from a model's output or from M4.
    """
    return sample.family == ANOMALY_FAMILY
