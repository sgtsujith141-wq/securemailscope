"""ML analysis contracts (M6).

ML output lives in its own block and is labelled as ML on every result. It
never enters a :class:`SecurityFinding`, never changes a posture score and
never upgrades an observation's evidence status. A reader must be able to
delete this block and still have the complete deterministic analysis.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from .evidence import PacketReference

__all__ = [
    "MLStatus",
    "AnomalyVerdict",
    "ClassificationVerdict",
    "ModelMetadata",
    "FeatureExplanation",
    "AnomalyResult",
    "RiskClassification",
    "MLWarning",
    "MLAnalysis",
]


class MLStatus(StrEnum):
    """What the ML layer did, at the capture level."""

    COMPLETED = "COMPLETED"
    #: Switched off by configuration.
    DISABLED = "DISABLED"
    #: No model artifact is installed. The rest of the analysis is unaffected.
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    #: A model exists but could not be used: version or schema mismatch, or a
    #: failed integrity check. Never silently ignored.
    MODEL_REJECTED = "MODEL_REJECTED"


class AnomalyVerdict(StrEnum):
    ANOMALOUS = "ANOMALOUS"
    NOT_ANOMALOUS = "NOT_ANOMALOUS"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"


class ClassificationVerdict(StrEnum):
    PREDICTED = "PREDICTED"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    ABSTAINED = "ABSTAINED"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    #: Implemented and measured, but not validated well enough to act on.
    NOT_VALIDATED = "NOT_VALIDATED"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ModelMetadata(_Frozen):
    """Everything needed to identify and reproduce the model that answered.

    protected_namespaces is cleared because these fields genuinely describe
    a machine-learning model; pydantic reserves the model_ prefix for its
    own API, and renaming them to avoid the clash would make the report less
    readable than the warning is worth.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", protected_namespaces=())

    model_id: str
    model_version: str
    algorithm: str
    feature_schema_version: str
    dataset_id: str
    dataset_version: str
    trained_at: str
    training_sample_count: int = Field(ge=0)
    #: The population "unusual" is measured against. Without it the word has
    #: no meaning.
    reference_population: str
    hyperparameters: dict[str, str] = Field(default_factory=dict)
    artifact_sha256: str
    library_versions: dict[str, str] = Field(default_factory=dict)
    evaluation_report: str = Field(
        description="Where the held-out evaluation for this model is recorded."
    )
    limitations: tuple[str, ...] = ()


class FeatureExplanation(_Frozen):
    """One feature's contribution, traceable to a forensic observation."""

    feature: str
    observed_value: str
    #: The M1-M5 field this was read from.
    provenance: str
    #: How often this value occurred in the training reference population.
    reference_frequency: float | None = Field(default=None, ge=0.0, le=1.0)
    note: str


class AnomalyResult(_Frozen):
    """One session's anomaly verdict.

    ``raw_score`` is the detector's ordering statistic. It is **not** a
    probability of anything, and least of all a probability of attack.
    """

    capture_id: str
    session_id: str
    status: AnomalyVerdict
    raw_score: float | None = None
    decision_threshold: float | None = None
    evidence_refs: tuple[PacketReference, ...] = ()
    feature_explanations: tuple[FeatureExplanation, ...] = ()
    explanation: str
    limitations: tuple[str, ...] = ()


class RiskClassification(_Frozen):
    """One session's predicted posture class, where the model was validated."""

    capture_id: str
    session_id: str
    status: ClassificationVerdict
    predicted_class: str | None = None
    #: Relative model scores. Not calibrated probabilities: no calibration was
    #: fitted or validated, and the model card says so.
    class_scores: dict[str, float] = Field(default_factory=dict)
    decision_threshold: float | None = None
    evidence_refs: tuple[PacketReference, ...] = ()
    feature_explanations: tuple[FeatureExplanation, ...] = ()
    explanation: str
    limitations: tuple[str, ...] = ()


class MLWarning(_Frozen):
    code: str
    message: str
    session_id: str | None = None


class MLAnalysis(_Frozen):
    """The ML block added to a report."""

    ml_status: MLStatus
    feature_schema_version: str
    anomaly_model: ModelMetadata | None = None
    classification_model: ModelMetadata | None = None
    anomaly_results: tuple[AnomalyResult, ...] = ()
    risk_classification: tuple[RiskClassification, ...] = ()
    evaluation_limitations: tuple[str, ...] = ()
    ml_warnings: tuple[MLWarning, ...] = ()
    #: Stated on every report: these are ML inferences, not observations.
    disclosure: str = (
        "Produced by a machine-learning model trained on locally generated "
        "synthetic data. These are inferences, never observations, and they do "
        "not modify any deterministic finding, score or observation in this "
        "report."
    )
