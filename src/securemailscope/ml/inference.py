"""Local inference (M6).

Runs after the deterministic assessment and the forensic intelligence, and
changes neither. The ordering matters: ML sees the observations, never the
other way round, so nothing a model says can feed back into a finding, a score
or an observation.

    observations -> features -> eligibility -> model -> interpretation -> result

Four things this layer guarantees:

* **The analyzer works without it.** No model installed, scikit-learn not
  installed, artifact rejected -- each is reported as a status and the rest of
  the report is unaffected. A forensic tool that stops working because a model
  file is missing would be a worse tool.
* **Nothing is silently dropped.** Every outcome, including a refusal, appears
  in the report with a reason.
* **It is local and bounded.** No network access at any point, no download, no
  GPU, one model held in memory for the run.
* **It is deterministic.** The same capture, model and configuration produce
  the same output every time.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from ..models.ml import (
    AnomalyResult,
    AnomalyVerdict,
    ClassificationVerdict,
    MLAnalysis,
    MLStatus,
    MLWarning,
    ModelMetadata,
    RiskClassification,
)
from .explanations import EXPLANATION_LIMITATIONS, ReferenceStatistics, explain_session
from .features import (
    FEATURE_SCHEMA_VERSION,
    EligibilityStatus,
    SessionFeatures,
    extract_from_result,
)
from .registry import ArtifactManifest, ModelRejected, load_model

if TYPE_CHECKING:
    from ..config import AnalysisConfig
    from ..models.analysis import AnalysisResult

__all__ = ["MLEngine", "analyse_with_ml", "get_engine", "clear_engine_cache"]

ANOMALY_MODEL_ID: Final = "tls-anomaly"
CLASSIFIER_MODEL_ID: Final = "tls-posture"

#: Attached to every classification result. The classifier is implemented and
#: measured; it is not validated for anything an operator should act on.
_CLASSIFICATION_LIMITATIONS: Final[tuple[str, ...]] = (
    "NOT VALIDATED for operational use. The target is a latent posture class "
    "defined by a rubric this project wrote, over synthetic servers.",
    "Predicting it well demonstrates that the rubric's verdict can be "
    "recovered from partial observations. It does not demonstrate prediction "
    "of compromise, breach likelihood or real-world risk.",
    "Class scores are relative model outputs, not calibrated probabilities. No "
    "calibration was fitted or validated.",
    "This prediction does not modify any deterministic finding or score in "
    "this report. Where the two differ, the deterministic result is the one "
    "backed by observed evidence.",
)

_ANOMALY_LIMITATIONS: Final[tuple[str, ...]] = (
    "An anomaly is a configuration unusual relative to the recorded training "
    "reference population. It is not a vulnerability, not an attack and not "
    "evidence of intent.",
    "The reference population is synthetic. Frequencies describe it and "
    "nothing wider.",
    *EXPLANATION_LIMITATIONS,
)


@dataclass
class _LoadedModel:
    payload: dict[str, Any]
    manifest: ArtifactManifest
    statistics: ReferenceStatistics


class MLEngine:
    """Holds the loaded models for one run.

    Loading is attempted once. A failure is recorded and reported, never
    retried per session and never allowed to fail the analysis.
    """

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self.anomaly: _LoadedModel | None = None
        self.classifier: _LoadedModel | None = None
        self.status: MLStatus = MLStatus.MODEL_UNAVAILABLE
        self.warnings: list[MLWarning] = []
        self._load()

    def _load(self) -> None:
        try:
            import sklearn  # noqa: F401
        except ImportError:
            self.warnings.append(
                MLWarning(
                    code="ML_EXTRA_NOT_INSTALLED",
                    message=(
                        "scikit-learn is not installed, so no model can run. The "
                        "forensic and assessment results in this report are "
                        "complete and unaffected."
                    ),
                )
            )
            self.status = MLStatus.MODEL_UNAVAILABLE
            return

        loaded_any = False
        rejected = False
        for attribute, model_id in (
            ("anomaly", ANOMALY_MODEL_ID),
            ("classifier", CLASSIFIER_MODEL_ID),
        ):
            try:
                payload, manifest = load_model(model_id, directory=self.directory)
            except ModelRejected as exc:
                message = str(exc)
                code = (
                    "MODEL_NOT_INSTALLED"
                    if message.startswith("no manifest")
                    else "MODEL_REJECTED"
                )
                if code == "MODEL_REJECTED":
                    rejected = True
                self.warnings.append(
                    MLWarning(code=code, message=f"{model_id}: {message}")
                )
                continue
            statistics = ReferenceStatistics.from_dict(
                payload.get("reference_statistics", {}),
                int(payload.get("reference_total", 0)),
            )
            setattr(
                self,
                attribute,
                _LoadedModel(payload=payload, manifest=manifest, statistics=statistics),
            )
            loaded_any = True

        if loaded_any:
            self.status = MLStatus.COMPLETED
        elif rejected:
            self.status = MLStatus.MODEL_REJECTED
        else:
            self.status = MLStatus.MODEL_UNAVAILABLE

    # -- metadata ---------------------------------------------------------
    def _metadata(self, model: _LoadedModel) -> ModelMetadata:
        manifest = model.manifest
        return ModelMetadata(
            model_id=manifest.model_id,
            model_version=manifest.model_version,
            algorithm=manifest.algorithm,
            feature_schema_version=manifest.feature_schema_version,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            trained_at=manifest.trained_at,
            training_sample_count=manifest.training_sample_count,
            reference_population=manifest.reference_population,
            hyperparameters={
                key: str(value) for key, value in manifest.hyperparameters.items()
            },
            artifact_sha256=manifest.artifact_sha256,
            library_versions=manifest.library_versions,
            evaluation_report=manifest.evaluation_report,
            limitations=tuple(manifest.limitations or ()),
        )

    # -- anomaly ----------------------------------------------------------
    def _anomaly_for(
        self, features: SessionFeatures
    ) -> AnomalyResult:
        capture_id, session_id = features.capture_id, features.session_id
        if self.anomaly is None:
            return AnomalyResult(
                capture_id=capture_id,
                session_id=session_id,
                status=AnomalyVerdict.MODEL_UNAVAILABLE,
                explanation="No anomaly model is available in this build.",
                limitations=_ANOMALY_LIMITATIONS,
            )
        if features.eligibility is not EligibilityStatus.ELIGIBLE:
            return AnomalyResult(
                capture_id=capture_id,
                session_id=session_id,
                status=AnomalyVerdict.NOT_EVALUABLE,
                explanation=features.reason,
                limitations=(
                    "A session with too little evidence is not scored. Treating "
                    "an incomplete capture as unusual would report the "
                    "capture's limits as the server's.",
                ),
            )

        payload = self.anomaly.payload
        threshold = float(payload["rarity_threshold"])
        key = "|".join(
            (
                features.categorical.get("tls_version", "MISSING"),
                features.categorical.get("cipher_encryption", "MISSING"),
                features.categorical.get("cipher_key_exchange", "MISSING"),
            )
        )
        counts: dict[str, int] = payload["rarity_counts"]
        total = int(payload["rarity_total"]) or 1
        score = counts.get(key, 0) / total
        status = (
            AnomalyVerdict.ANOMALOUS if score <= threshold else AnomalyVerdict.NOT_ANOMALOUS
        )
        explanations = explain_session(features, self.anomaly.statistics)
        if status is AnomalyVerdict.ANOMALOUS:
            explanation = (
                f"Machine-learning observation: this combination of negotiated "
                f"version, encryption and key exchange occurred in {score:.1%} of "
                f"the {total}-session training reference population, at or below "
                f"the frozen decision threshold of {threshold:.1%}. Unusual is "
                "not the same as unsafe."
            )
        else:
            explanation = (
                f"Machine-learning observation: this combination occurred in "
                f"{score:.1%} of the {total}-session training reference "
                "population, above the decision threshold, so it is not unusual "
                "for that population."
            )
        return AnomalyResult(
            capture_id=capture_id,
            session_id=session_id,
            status=status,
            raw_score=score,
            decision_threshold=threshold,
            evidence_refs=tuple(features.evidence_refs),
            feature_explanations=explanations,
            explanation=explanation,
            limitations=_ANOMALY_LIMITATIONS,
        )

    # -- classification ---------------------------------------------------
    def _classification_for(
        self, features: SessionFeatures
    ) -> RiskClassification:
        capture_id, session_id = features.capture_id, features.session_id
        if self.classifier is None:
            return RiskClassification(
                capture_id=capture_id,
                session_id=session_id,
                status=ClassificationVerdict.MODEL_UNAVAILABLE,
                explanation="No classification model is available in this build.",
                limitations=_CLASSIFICATION_LIMITATIONS,
            )
        if features.eligibility is not EligibilityStatus.ELIGIBLE:
            return RiskClassification(
                capture_id=capture_id,
                session_id=session_id,
                status=ClassificationVerdict.NOT_EVALUABLE,
                explanation=features.reason,
                limitations=_CLASSIFICATION_LIMITATIONS,
            )

        estimator = self.classifier.payload["estimator"]
        classes = [str(label) for label in self.classifier.payload["classes"]]
        vector = features.vector()
        probabilities = estimator.predict_proba([vector])[0]
        scores = {
            label: float(value)
            for label, value in zip(classes, probabilities, strict=True)
        }
        best = max(scores, key=lambda label: scores[label])
        return RiskClassification(
            capture_id=capture_id,
            session_id=session_id,
            # Reported as NOT_VALIDATED rather than PREDICTED: the model runs
            # and produces a class, but nothing establishes that the class
            # means anything operationally. See docs/ml-model-card.md.
            status=ClassificationVerdict.NOT_VALIDATED,
            predicted_class=best,
            class_scores=scores,
            evidence_refs=tuple(features.evidence_refs),
            feature_explanations=explain_session(features, self.classifier.statistics),
            explanation=(
                f"Machine-learning observation: the model's highest-scoring "
                f"latent posture class for this session is {best} "
                f"(relative score {scores[best]:.2f}). Reported as NOT_VALIDATED: "
                "the label it predicts is a project-authored rubric over "
                "synthetic servers, so this is not a risk assessment. The "
                "deterministic assessment in this report is the evidence-backed "
                "judgement."
            ),
            limitations=_CLASSIFICATION_LIMITATIONS,
        )

    # -- driver -----------------------------------------------------------
    def analyse(self, result: AnalysisResult) -> MLAnalysis:
        features = extract_from_result(result)
        anomalies = tuple(self._anomaly_for(item) for item in features)
        classifications = tuple(self._classification_for(item) for item in features)
        not_evaluable = sum(
            1 for item in features if item.eligibility is not EligibilityStatus.ELIGIBLE
        )
        warnings = list(self.warnings)
        if not_evaluable:
            warnings.append(
                MLWarning(
                    code="SESSIONS_BELOW_EVIDENCE_FLOOR",
                    message=(
                        f"{not_evaluable} of {len(features)} session(s) had too "
                        "little evidence to evaluate and were reported as "
                        "NOT_EVALUABLE rather than scored."
                    ),
                )
            )
        return MLAnalysis(
            ml_status=self.status,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            anomaly_model=self._metadata(self.anomaly) if self.anomaly else None,
            classification_model=(
                self._metadata(self.classifier) if self.classifier else None
            ),
            anomaly_results=anomalies,
            risk_classification=classifications,
            evaluation_limitations=(
                "All models were trained and evaluated on locally generated "
                "synthetic captures. Reported metrics are controlled-environment "
                "measurements, not real-world detection performance.",
                "Supervised classification is reported as NOT_VALIDATED. See "
                "docs/ml-model-card.md for what that means and why.",
                f"{len(features)} session(s) were considered; {not_evaluable} were "
                "below the evidence floor.",
            ),
            ml_warnings=tuple(warnings),
        )


#: One engine per model directory, reused across captures in a process.
#:
#: Loading an artifact costs far more than scoring a session -- about 75ms
#: against well under a millisecond -- so reloading per capture made analysis
#: seventeen times slower for no benefit. The cache holds only artifacts that
#: already passed every integrity and version check in the registry, and is
#: keyed by the resolved directory so two directories cannot be confused.
_ENGINES: dict[str, MLEngine] = {}


def clear_engine_cache() -> None:
    """Drop cached engines. For tests that install or tamper with artifacts."""
    _ENGINES.clear()


def get_engine(directory: Path | None = None) -> MLEngine:
    key = str(Path(directory).resolve()) if directory is not None else "<default>"
    engine = _ENGINES.get(key)
    if engine is None:
        engine = _ENGINES[key] = MLEngine(directory=directory)
    return engine


def analyse_with_ml(
    result: AnalysisResult,
    *,
    config: AnalysisConfig | None = None,
    directory: Path | None = None,
) -> MLAnalysis:
    """Run ML over one analysed capture, or report why it did not run."""
    if config is not None and not config.enable_ml:
        return MLAnalysis(
            ml_status=MLStatus.DISABLED,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            evaluation_limitations=(
                "The machine-learning layer was disabled for this run. Every "
                "forensic and assessment result in this report is complete.",
            ),
        )
    return get_engine(directory).analyse(result)


def feature_value_counts(features: list[SessionFeatures]) -> Counter[str]:
    """Small helper for the CLI summary."""
    return Counter(
        item.categorical.get("tls_version", "MISSING")
        for item in features
        if item.eligibility is EligibilityStatus.ELIGIBLE
    )
