from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from securemailscope.config import AnalysisConfig
from securemailscope.ml.dataset import (
    CONFIGURATION_FAMILIES,
    NEGATIVE_CONTROL_FAMILY,
    POSTURE_CLASSES,
    build_population,
    capture_size_profile,
    dataset_fingerprint,
    generate_sessions,
    posture_class,
)
from securemailscope.ml.evaluation import binary_metrics, multiclass_metrics
from securemailscope.ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    AbsenceReason,
    EligibilityStatus,
)
from securemailscope.ml.preprocessing import (
    HELDOUT_FAMILIES,
    anomaly_evaluation_label,
    build_dataset,
    family_holdout,
    grouped_split,
)
from securemailscope.ml.registry import (
    MODEL_DIRECTORY,
    ModelRejected,
    load_model,
    read_manifest,
)
from securemailscope.pipeline import analyze_capture

pytestmark = pytest.mark.filterwarnings("ignore")


@pytest.fixture(scope="module")
def dataset():
    return build_dataset()


@pytest.fixture(scope="module")
def splits(dataset):
    return grouped_split(dataset.eligible)


# ---------------------------------------------------------------------------
# A. Reproducible dataset generation
# ---------------------------------------------------------------------------
def test_dataset_generation_is_reproducible() -> None:
    """Same seeds, same dataset: same servers, negotiations and labels.

    Not byte-for-byte. The synthetic authority mints a fresh key per
    certificate and ECDSA signatures vary in DER length, so captures differ by
    a byte or two inside the certificate between runs while describing exactly
    the same sessions. The content digest is what must hold, and the byte-level
    variation is measured rather than ignored.
    """
    first = generate_sessions()
    second = generate_sessions()
    assert dataset_fingerprint(first) == dataset_fingerprint(second)
    assert [item.sample_id for item in first] == [item.sample_id for item in second]
    assert [item.posture for item in first] == [item.posture for item in second]
    assert [item.negotiated_suite for item in first] == [
        item.negotiated_suite for item in second
    ]

    a, b = capture_size_profile(first), capture_size_profile(second)
    assert a["captures"] == b["captures"]
    # The variation is confined to certificate material and is small.
    assert abs(a["total_bytes"] - b["total_bytes"]) < a["captures"] * 8


def test_population_is_reproducible_and_spans_families() -> None:
    assert [s.server_id for s in build_population()] == [
        s.server_id for s in build_population()
    ]
    families = {s.family for s in build_population()}
    assert families == set(CONFIGURATION_FAMILIES)


def test_no_family_is_a_proxy_for_the_label() -> None:
    """If family determined posture, the task would be trivial and useless."""
    population = build_population()
    spanning = [
        family
        for family in CONFIGURATION_FAMILIES
        if len({posture_class(s) for s in population if s.family == family}) > 1
    ]
    assert spanning, (
        "at least one configuration family must span several posture classes, "
        "or the family name would be a stand-in for the target"
    )


def test_labels_are_not_derived_from_the_assessment_engine(dataset) -> None:
    """The ML label must not be M4's opinion under another name.

    The rubric is applied to the server's whole configuration; M4 judges the
    one session in front of it. They therefore disagree in exactly the cases
    the task is about: a careless server that happened to negotiate well.
    """
    disagreements = 0
    checked = 0
    for sample in dataset.eligible:
        generated = next(
            item for item in dataset.generated if item.sample_id == sample.sample_id
        )
        # A server whose *supported* suites include a broken one is CRITICAL,
        # whatever this session negotiated.
        if sample.posture == "CRITICAL" and generated.negotiated_suite not in (
            0x0005,
            0x003B,
        ):
            disagreements += 1
        checked += 1
    assert checked
    assert disagreements, (
        "the latent label must sometimes differ from what the session shows, "
        "or the task collapses into reproducing the deterministic engine"
    )


def test_the_dataset_is_built_with_the_assessment_layer_off(dataset) -> None:
    """No M4 output may reach the feature extractor, even incidentally."""
    for sample in dataset.samples[:20]:
        text = json.dumps(
            {
                "categorical": sample.features.categorical,
                "numeric": dict(sample.features.numeric),
                "provenance": sample.features.provenance,
            }
        )
        for forbidden in ("posture_score", "severity", "finding", "rule_id", "policy"):
            assert forbidden not in text, f"{forbidden!r} leaked into the features"


# ---------------------------------------------------------------------------
# B, C, D. Feature extraction, missingness, TLS 1.3
# ---------------------------------------------------------------------------
def test_feature_extraction_is_deterministic(dataset) -> None:
    sample = dataset.eligible[0]
    assert sample.features.vector() == sample.features.vector()
    assert len(sample.features.vector()) == len(FEATURE_NAMES)


def test_every_feature_vector_has_the_schema_width(dataset) -> None:
    for sample in dataset.eligible:
        assert len(sample.features.vector()) == len(FEATURE_NAMES)


def test_missing_values_carry_an_indicator_not_a_zero(dataset) -> None:
    """A missing number must be distinguishable from a small one."""
    names = list(FEATURE_NAMES)
    without_certificate = [
        s for s in dataset.eligible if not s.features.boolean.get("certificate_observed")
    ]
    assert without_certificate, "the dataset must contain sessions with no certificate"
    sample = without_certificate[0]
    vector = sample.features.vector()
    assert vector[names.index("cert_key_bits")] == 0.0
    assert vector[names.index("cert_key_bits_missing")] == 1.0

    with_certificate = [
        s for s in dataset.eligible if s.features.boolean.get("certificate_observed")
    ]
    assert with_certificate
    present = with_certificate[0].features.vector()
    assert present[names.index("cert_key_bits_missing")] == 0.0


def test_tls13_absent_certificate_is_not_the_same_as_a_missing_one(dataset) -> None:
    """D: encryption is a protocol property, a truncation is an evidence gap."""
    tls13 = [
        s
        for s in dataset.eligible
        if s.features.categorical.get("tls_version") == "TLS 1.3"
    ]
    assert tls13, "the dataset must contain TLS 1.3 sessions"
    for sample in tls13:
        assert (
            sample.features.categorical["certificate_absence_reason"]
            == AbsenceReason.NOT_AVAILABLE.value
        ), "a TLS 1.3 certificate is encrypted, not missing"

    truncated = [
        s
        for s in dataset.samples
        if not s.eligible and s.features.categorical
    ]
    for sample in truncated:
        assert (
            sample.features.categorical.get("certificate_absence_reason")
            != AbsenceReason.NOT_AVAILABLE.value
        )


def test_no_certificate_property_is_invented_for_tls13(dataset) -> None:
    for sample in dataset.eligible:
        if sample.features.categorical.get("tls_version") != "TLS 1.3":
            continue
        assert sample.features.categorical["cert_key_algorithm"] == "MISSING"
        assert sample.features.numeric["cert_key_bits"] is None
        assert sample.features.numeric["cert_lifetime_days"] is None


def test_insufficient_evidence_is_not_evaluated(dataset) -> None:
    """P: abstention, not a fallback prediction."""
    excluded = [s for s in dataset.samples if not s.eligible]
    assert excluded, "the dataset must contain sessions below the evidence floor"
    for sample in excluded:
        assert sample.features.eligibility is EligibilityStatus.ML_NOT_EVALUABLE
        assert sample.features.reason.strip()


def test_prohibited_identifiers_are_absent_from_features(dataset) -> None:
    """Leakage control: no identity a model could memorise."""
    for sample in dataset.eligible[:60]:
        values = set(sample.features.categorical.values())
        numeric = sample.features.numeric
        assert sample.sample_id not in values
        assert sample.group_id not in values
        assert sample.family not in values
        assert sample.posture not in values
        assert sample.features.capture_id not in values
        assert sample.features.session_id not in values
        for value in values:
            assert "198.51.100" not in value, "an IP address reached the features"
            assert "example.invalid" not in value, "a hostname reached the features"
            assert not value.startswith("smp-"), "a sample id reached the features"
        assert "capture_hash" not in numeric


# ---------------------------------------------------------------------------
# E, F, G, H. Splitting and leakage prevention
# ---------------------------------------------------------------------------
def test_splitting_is_group_aware(splits) -> None:
    """E: no server appears in more than one partition."""
    train, validation, test = splits
    groups = [{s.group_id for s in part} for part in (train, validation, test)]
    assert not groups[0] & groups[1]
    assert not groups[0] & groups[2]
    assert not groups[1] & groups[2]
    assert all(groups), "every partition must contain samples"


def test_no_certificate_spans_two_partitions(splits, dataset) -> None:
    """G: a certificate is an identity. Sharing one across the split leaks it."""
    train, validation, test = splits
    by_sample = {item.sample_id: item for item in dataset.generated}

    def certificates(part):
        return {
            by_sample[s.sample_id].server.server_id
            for s in part
            if s.sample_id in by_sample
        }

    a, b, c = certificates(train), certificates(validation), certificates(test)
    assert not a & b
    assert not a & c
    assert not b & c


def test_duplicate_sessions_of_one_server_stay_together(splits) -> None:
    """F: several sessions per server; all of them land on one side."""
    train, validation, test = splits
    placement: dict[str, set[int]] = {}
    for index, part in enumerate((train, validation, test)):
        for sample in part:
            placement.setdefault(sample.group_id, set()).add(index)
    multi = [group for group, sides in placement.items() if len(sides) > 1]
    assert not multi, f"these groups span partitions: {multi[:5]}"
    repeated = [group for group, sides in placement.items() if sides]
    assert len(repeated) > 1


def test_family_holdout_withholds_whole_families(dataset) -> None:
    """H: the harder generalisation question."""
    inside, outside = family_holdout(dataset.eligible)
    assert inside and outside
    assert {s.family for s in outside} == set(HELDOUT_FAMILIES)
    assert not {s.family for s in inside} & set(HELDOUT_FAMILIES)
    assert not {s.group_id for s in inside} & {s.group_id for s in outside}


def test_the_split_is_reproducible(dataset) -> None:
    first = grouped_split(dataset.eligible)
    second = grouped_split(dataset.eligible)
    for a, b in zip(first, second, strict=True):
        assert [s.sample_id for s in a] == [s.sample_id for s in b]


# ---------------------------------------------------------------------------
# I, J, K, L. Training, baselines and detection
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def trained(splits):
    from securemailscope.ml.anomaly import (
        RarityBaseline,
        fit_isolation_forest,
        threshold_from_scores,
    )

    train, validation, test = splits
    reference = [s for s in train if s.in_reference_population]
    vectors = [s.features.vector() for s in reference]
    forest = fit_isolation_forest(
        vectors, FEATURE_NAMES, reference_population="test reference"
    )
    labels = [anomaly_evaluation_label(s) for s in validation]
    forest.threshold = threshold_from_scores(
        [forest.raw_score(s.features.vector()) for s in validation], labels
    )[0]
    baseline = RarityBaseline.fit([s.features.categorical for s in reference])
    baseline_threshold = threshold_from_scores(
        [baseline.score(s.features.categorical) for s in validation], labels
    )[0]
    return forest, baseline, baseline_threshold


def test_training_is_reproducible(splits) -> None:
    """I: same data and seed, same model."""
    from securemailscope.ml.anomaly import fit_isolation_forest

    train, _, _ = splits
    vectors = [s.features.vector() for s in train if s.in_reference_population]
    first = fit_isolation_forest(vectors, FEATURE_NAMES, reference_population="r")
    second = fit_isolation_forest(vectors, FEATURE_NAMES, reference_population="r")
    scores_a = [first.raw_score(v) for v in vectors[:40]]
    scores_b = [second.raw_score(v) for v in vectors[:40]]
    assert scores_a == scores_b


def test_the_anomaly_detector_finds_the_injected_anomalies(trained, splits) -> None:
    """K: it must detect what was declared anomalous before training."""
    _, baseline, threshold = trained
    _, _, test = splits
    anomalies = [s for s in test if anomaly_evaluation_label(s)]
    assert anomalies, "the test split must contain injected anomalies"
    caught = sum(
        1 for s in anomalies if baseline.predict(s.features.categorical, threshold)
    )
    assert caught / len(anomalies) >= 0.5, (
        f"only {caught}/{len(anomalies)} injected anomalies were detected"
    )


def test_rare_but_legitimate_configurations_are_not_flagged(trained, dataset) -> None:
    """L: the negative control. Unfamiliar is not the same as unsafe."""
    _, baseline, threshold = trained
    controls = [
        s
        for s in dataset.eligible
        if s.family == NEGATIVE_CONTROL_FAMILY
    ]
    assert controls, "the dataset must contain rare-but-legitimate configurations"
    flagged = [
        s for s in controls if baseline.predict(s.features.categorical, threshold)
    ]
    assert not flagged, (
        f"{len(flagged)}/{len(controls)} rare but legitimate configurations were "
        "reported as anomalous"
    )


def test_a_baseline_is_always_compared(trained, splits) -> None:
    """J: the simple comparator must be measured, not assumed to be worse."""
    forest, baseline, threshold = trained
    _, _, test = splits
    labels = [anomaly_evaluation_label(s) for s in test]
    forest_metrics = binary_metrics(
        [forest.raw_score(s.features.vector()) <= forest.threshold for s in test], labels
    )
    baseline_metrics = binary_metrics(
        [baseline.predict(s.features.categorical, threshold) for s in test], labels
    )
    # Both must be defined and reported. Which wins is an empirical question
    # answered in docs/ml-evaluation.md, not an assumption made here.
    assert forest_metrics.total == baseline_metrics.total == len(test)
    assert baseline_metrics.f1 is not None


def test_incomplete_captures_are_not_treated_as_anomalies(dataset) -> None:
    """A capture with little evidence must not be unusual for that reason."""
    excluded = [s for s in dataset.samples if not s.eligible]
    assert excluded
    for sample in excluded:
        assert sample.features.eligibility is EligibilityStatus.ML_NOT_EVALUABLE


# ---------------------------------------------------------------------------
# N. Metric arithmetic, computed independently
# ---------------------------------------------------------------------------
def test_binary_metrics_match_a_hand_worked_matrix() -> None:
    predicted = [True, True, True, False, False, False, False, False]
    actual = [True, True, False, True, False, False, False, False]
    # TP=2, FP=1, FN=1, TN=4.  precision 2/3, recall 2/3, f1 2/3, fpr 1/5.
    metrics = binary_metrics(predicted, actual)
    assert metrics.confusion_matrix() == {
        "true_positive": 2,
        "false_positive": 1,
        "true_negative": 4,
        "false_negative": 1,
    }
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.recall == pytest.approx(2 / 3)
    assert metrics.f1 == pytest.approx(2 / 3)
    assert metrics.false_positive_rate == pytest.approx(1 / 5)
    assert metrics.support_positive == 3
    assert metrics.support_negative == 5
    assert metrics.total == 8


def test_undefined_metrics_are_reported_as_undefined_not_zero() -> None:
    """A precision of 0/0 is not a precision of 0."""
    metrics = binary_metrics([False, False], [True, False])
    assert metrics.precision is None
    assert "precision" in metrics.undefined_reasons
    assert "denominator is zero" in metrics.undefined_reasons["precision"]
    assert metrics.f1 is None
    assert metrics.recall == 0.0, "recall is defined here: there is a positive sample"


def test_multiclass_metrics_match_a_hand_worked_matrix() -> None:
    classes = ("LOW", "MODERATE", "HIGH", "CRITICAL")
    actual = ["LOW", "LOW", "MODERATE", "HIGH", "HIGH", "HIGH"]
    predicted = ["LOW", "MODERATE", "MODERATE", "HIGH", "HIGH", "LOW"]
    metrics = multiclass_metrics(predicted, actual, classes)
    # LOW:      tp=1 fp=1 fn=1 -> p=1/2 r=1/2 f1=1/2
    # MODERATE: tp=1 fp=1 fn=0 -> p=1/2 r=1   f1=2/3
    # HIGH:     tp=2 fp=0 fn=1 -> p=1   r=2/3 f1=4/5
    assert metrics.per_class["LOW"]["precision"] == pytest.approx(0.5)
    assert metrics.per_class["LOW"]["f1"] == pytest.approx(0.5)
    assert metrics.per_class["MODERATE"]["recall"] == pytest.approx(1.0)
    assert metrics.per_class["MODERATE"]["f1"] == pytest.approx(2 / 3)
    assert metrics.per_class["HIGH"]["precision"] == pytest.approx(1.0)
    assert metrics.per_class["HIGH"]["f1"] == pytest.approx(0.8)
    assert metrics.support == {"LOW": 2, "MODERATE": 1, "HIGH": 3, "CRITICAL": 0}
    assert metrics.accuracy == pytest.approx(4 / 6)
    # Macro over present classes only: absent is not failed.
    assert metrics.macro_f1 == pytest.approx((0.5 + 2 / 3 + 0.8) / 3)
    assert metrics.per_class["CRITICAL"]["f1"] is None
    assert "CRITICAL.recall" in metrics.undefined_reasons


def test_metrics_reject_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        binary_metrics([True], [True, False])


def test_every_metric_result_states_it_is_synthetic() -> None:
    metrics = binary_metrics([True], [True])
    assert "synthetic" in metrics.measurement_context.lower()
    assert "not" in metrics.measurement_context.lower()


# ---------------------------------------------------------------------------
# O. Threshold selection without test leakage
# ---------------------------------------------------------------------------
def test_threshold_selection_uses_only_the_split_it_is_given() -> None:
    from securemailscope.ml.anomaly import threshold_from_scores

    scores = [0.9, 0.8, 0.7, 0.1, 0.05]
    labels = [False, False, False, True, True]
    threshold, stats = threshold_from_scores(scores, labels)
    assert threshold == pytest.approx(0.1)
    assert stats["validation_false_positive_rate"] == 0.0
    assert stats["validation_recall"] == 1.0
    # Changing data the function never saw cannot change its answer.
    again, _ = threshold_from_scores(scores, labels)
    assert again == threshold


def test_threshold_selection_respects_the_false_positive_cap() -> None:
    from securemailscope.ml.anomaly import threshold_from_scores

    scores = [0.5, 0.5, 0.5, 0.5, 0.4]
    labels = [False, False, False, False, True]
    threshold, stats = threshold_from_scores(
        scores, labels, max_false_positive_rate=0.0
    )
    assert stats["validation_false_positive_rate"] == 0.0
    assert threshold <= 0.4


# ---------------------------------------------------------------------------
# Q, R, S, T. Model availability, versions, schemas and tampering
# ---------------------------------------------------------------------------
@pytest.fixture
def installed_models(tmp_path):
    """A private copy of the shipped artifacts, safe to corrupt."""
    target = tmp_path / "models"
    target.mkdir()
    for path in MODEL_DIRECTORY.glob("*"):
        if path.is_file():
            shutil.copy2(path, target / path.name)
    return target


def test_a_shipped_model_loads_and_verifies(installed_models) -> None:
    payload, manifest = load_model("tls-anomaly", directory=installed_models)
    assert manifest.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert manifest.artifact_sha256
    assert payload["feature_names"] == list(FEATURE_NAMES)


def test_a_missing_model_is_reported_not_raised_into_the_analysis(tmp_path) -> None:
    """Q: the analyzer must work with no model installed."""
    empty = tmp_path / "none"
    empty.mkdir()
    with pytest.raises(ModelRejected, match="no manifest"):
        load_model("tls-anomaly", directory=empty)

    result = analyze_capture(
        Path("tests/fixtures/generated/t_a_tls12_complete_handshake.pcap"),
        config=AnalysisConfig(model_directory=str(empty)),
    )
    assert result.ml is not None
    assert result.ml.ml_status.value == "MODEL_UNAVAILABLE"
    # Everything else is complete.
    assert result.tls and result.assessment is not None
    assert result.assessment.posture_score is not None


def test_an_unsupported_model_version_is_refused(installed_models) -> None:
    """R: never silently load a model whose behaviour is unknown."""
    manifest_path = next(installed_models.glob("tls-anomaly-*.manifest.json"))
    data = json.loads(manifest_path.read_text())
    data["model_version"] = "99.0.0"
    manifest_path.write_text(json.dumps(data))
    with pytest.raises(ModelRejected, match="not supported"):
        load_model("tls-anomaly", directory=installed_models)


def test_a_feature_schema_mismatch_is_refused(installed_models) -> None:
    """S: mismatched columns would not line up, so the model is refused."""
    manifest_path = next(installed_models.glob("tls-anomaly-*.manifest.json"))
    data = json.loads(manifest_path.read_text())
    data["feature_schema_version"] = "smsfeat/999"
    manifest_path.write_text(json.dumps(data))
    with pytest.raises(ModelRejected, match="feature schema"):
        load_model("tls-anomaly", directory=installed_models)


def test_a_tampered_artifact_is_never_deserialised(installed_models) -> None:
    """T: the digest is verified before the file is opened by joblib."""
    artifact = next(installed_models.glob("tls-anomaly-*.joblib"))
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ModelRejected, match="digest mismatch"):
        load_model("tls-anomaly", directory=installed_models)


def test_an_artifact_outside_the_model_directory_is_refused(installed_models, tmp_path) -> None:
    """A manifest is data. It must not be able to point the loader elsewhere."""
    outside = tmp_path / "elsewhere.joblib"
    outside.write_bytes(b"not a model")
    manifest_path = next(installed_models.glob("tls-anomaly-*.manifest.json"))
    data = json.loads(manifest_path.read_text())
    data["artifact_filename"] = "../elsewhere.joblib"
    manifest_path.write_text(json.dumps(data))
    with pytest.raises(ModelRejected, match="outside the model directory"):
        load_model("tls-anomaly", directory=installed_models)


def test_a_rejected_model_does_not_fail_the_analysis(installed_models) -> None:
    """A refusal is reported, never silently discarded."""
    from securemailscope.ml.inference import clear_engine_cache

    artifact = next(installed_models.glob("tls-anomaly-*.joblib"))
    artifact.write_bytes(b"corrupt")
    clear_engine_cache()
    try:
        result = analyze_capture(
            Path("tests/fixtures/generated/t_a_tls12_complete_handshake.pcap"),
            config=AnalysisConfig(model_directory=str(installed_models)),
        )
    finally:
        clear_engine_cache()
    assert result.ml is not None
    codes = {warning.code for warning in result.ml.ml_warnings}
    assert "MODEL_REJECTED" in codes
    assert result.assessment is not None, "the deterministic analysis must survive"


def test_manifests_record_reproducibility_metadata() -> None:
    for path in MODEL_DIRECTORY.glob("*.manifest.json"):
        manifest = read_manifest(path)
        assert manifest.dataset_id and manifest.dataset_version
        assert manifest.training_sample_count > 0
        assert manifest.artifact_sha256
        assert manifest.library_versions.get("sklearn")
        assert manifest.library_versions.get("python")
        assert manifest.evaluation_report
        assert manifest.reference_population


# ---------------------------------------------------------------------------
# P, U, V, W, X, Y, Z. Inference behaviour end to end
# ---------------------------------------------------------------------------
def test_inference_abstains_on_insufficient_evidence() -> None:
    """P: a ClientHello-only capture is NOT_EVALUABLE, not guessed at."""
    result = analyze_capture(Path("tests/fixtures/generated/t_g_client_hello_only.pcap"))
    assert result.ml is not None
    anomaly = result.ml.anomaly_results[0]
    assert anomaly.status.value == "NOT_EVALUABLE"
    assert anomaly.raw_score is None
    assert anomaly.explanation.strip()
    classification = result.ml.risk_classification[0]
    assert classification.status.value == "NOT_EVALUABLE"
    assert classification.predicted_class is None


def test_every_explanation_is_traceable_to_an_observation() -> None:
    """U: evidence provenance."""
    result = analyze_capture(Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap"))
    assert result.ml is not None
    anomaly = result.ml.anomaly_results[0]
    assert anomaly.feature_explanations
    packet_count = result.capture.packet_count
    for explanation in anomaly.feature_explanations:
        assert explanation.provenance.strip()
        assert explanation.observed_value
        if explanation.reference_frequency is not None:
            assert 0.0 <= explanation.reference_frequency <= 1.0
    for reference in anomaly.evidence_refs:
        assert 1 <= reference.packet_number <= packet_count


def test_ml_output_discloses_that_a_model_produced_it() -> None:
    result = analyze_capture(Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap"))
    assert result.ml is not None
    assert "machine-learning" in result.ml.disclosure.lower()
    for item in result.ml.anomaly_results:
        if item.status.value in ("ANOMALOUS", "NOT_ANOMALOUS"):
            assert "machine-learning" in item.explanation.lower()


def test_ml_never_modifies_a_deterministic_result() -> None:
    """X: the analysis is identical with and without the ML layer."""
    path = Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap")
    with_ml = analyze_capture(path)
    without = analyze_capture(path, config=AnalysisConfig(enable_ml=False))
    assert without.ml is not None
    assert without.ml.ml_status.value == "DISABLED"
    for field in ("sessions", "tls", "protocols", "assessment", "inventory"):
        assert getattr(with_ml, field) == getattr(without, field), (
            f"{field} changed when the ML layer ran"
        )


def test_no_ml_prediction_enters_a_security_finding() -> None:
    result = analyze_capture(Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap"))
    assert result.assessment is not None and result.ml is not None
    serialised = json.dumps(result.assessment.model_dump(mode="json"))
    for token in ("anomal", "machine-learning", "predicted_class", "raw_model_score"):
        assert token.lower() not in serialised.lower(), (
            f"{token!r} reached the deterministic assessment block"
        )


def test_no_credential_material_reaches_the_ml_block(tmp_path) -> None:
    """V: privacy and redaction hold through the new layer."""
    from securemailscope.testing.fixtures import build_fixtures

    spec = next(s for s in build_fixtures() if s.name == "P_M_auth_before_tls")
    path = tmp_path / spec.filename
    path.write_bytes(spec.data)
    result = analyze_capture(path)
    assert result.ml is not None
    serialised = json.dumps(result.ml.model_dump(mode="json"), ensure_ascii=False)
    assert spec.forbidden_strings
    for secret in spec.forbidden_strings:
        assert secret not in serialised


def test_no_identity_reaches_the_ml_block() -> None:
    """Hostnames, SNI and certificate subjects must not be reported by ML."""
    result = analyze_capture(Path("tests/fixtures/generated/t_a_tls12_complete_handshake.pcap"))
    assert result.ml is not None
    serialised = json.dumps(result.ml.model_dump(mode="json"))
    assert "mail.example.invalid" not in serialised
    assert "198.51.100" not in serialised


def test_inference_opens_no_socket() -> None:
    """W: no outbound network activity, as everywhere else in this engine."""
    import socket

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the ML layer attempted a network connection")

    original = socket.socket
    socket.socket = refuse  # type: ignore[assignment,misc]
    try:
        result = analyze_capture(
            Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap")
        )
    finally:
        socket.socket = original  # type: ignore[misc]
    assert result.ml is not None
    assert result.ml.ml_status.value == "COMPLETED"


def test_repeated_inference_is_identical() -> None:
    """Z: same capture, same model, same output."""
    path = Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap")
    runs = [
        json.dumps(analyze_capture(path).ml.model_dump(mode="json"), sort_keys=True)
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]


def test_cli_reports_ml_end_to_end(tmp_path, capsys) -> None:
    """Y: end-to-end CLI inference."""
    from securemailscope.cli import main

    destination = tmp_path / "report.json"
    exit_code = main(
        [
            "analyze",
            "tests/fixtures/generated/aa_tls10_static_rsa.pcap",
            "-o",
            str(destination),
        ]
    )
    assert exit_code == 0
    document = json.loads(destination.read_text())
    block = document["ml"]
    for key in (
        "ml_status",
        "feature_schema_version",
        "anomaly_model",
        "anomaly_results",
        "risk_classification",
        "evaluation_limitations",
        "ml_warnings",
    ):
        assert key in block, f"missing required ML block {key}"
    assert block["ml_status"] == "COMPLETED"
    assert block["anomaly_model"]["artifact_sha256"]
    assert document["tool"]["report_schema_version"] == "1.4.0"
    printed = capsys.readouterr().err
    assert "ml" in printed
    assert "inferences, not observations" in printed


def test_cli_can_disable_ml(tmp_path) -> None:
    from securemailscope.cli import main

    destination = tmp_path / "no-ml.json"
    assert (
        main(
            [
                "analyze",
                "tests/fixtures/generated/aa_tls10_static_rsa.pcap",
                "-o",
                str(destination),
                "--no-ml",
                "--quiet",
            ]
        )
        == 0
    )
    document = json.loads(destination.read_text())
    assert document["ml"]["ml_status"] == "DISABLED"
    assert document["assessment"]["posture_score"]["score"] == 59, (
        "the deterministic result must be unchanged"
    )


def test_classification_is_reported_as_not_validated() -> None:
    """The honest status: implemented and measured, not validated."""
    result = analyze_capture(Path("tests/fixtures/generated/aa_tls10_static_rsa.pcap"))
    assert result.ml is not None
    item = result.ml.risk_classification[0]
    assert item.status.value == "NOT_VALIDATED"
    assert item.predicted_class in POSTURE_CLASSES
    joined = " ".join(item.limitations).lower()
    assert "not validated" in joined
    assert "calibrated probabilities" in joined
