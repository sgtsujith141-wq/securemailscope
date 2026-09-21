"""M5: fingerprints, identity, drift, correlation, timeline and blast radius.

Expectations come from ``investigation_fixtures``, where each group's expected
result was derived by hand from how the captures were constructed -- not read
back from the engine. Half of every expectation is negative: what the evidence
does **not** support. A correlation engine that is never tested for restraint
will happily turn coincidence into a finding, and the coincidences here are the
realistic ones: two hosts behind one certificate, two hosts with the same
distribution defaults, one host on two ports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from securemailscope.config import AnalysisConfig
from securemailscope.errors import SecureMailScopeError
from securemailscope.intelligence import analyze_batch
from securemailscope.intelligence.blast_radius import SCOPE_STATEMENT
from securemailscope.intelligence.fingerprints import (
    COMPONENT_NAMES,
    FINGERPRINT_ALGORITHM_VERSION,
    canonical_form,
    compare_fingerprints,
    configuration_fingerprint,
)
from securemailscope.models.intelligence import (
    CaptureStatus,
    DriftStatus,
    FingerprintCompleteness,
    FingerprintMatch,
    Investigation,
)
from securemailscope.pipeline import analyze_capture
from securemailscope.reporting.json_report import investigation_to_dict
from securemailscope.testing.investigation_fixtures import (
    InvestigationFixture,
    build_investigation_fixtures,
)

GROUP_NAMES = [fixture.name for fixture in build_investigation_fixtures()]


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def groups() -> dict[str, InvestigationFixture]:
    return {fixture.name: fixture for fixture in build_investigation_fixtures()}


@pytest.fixture(scope="session")
def group_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Write each group's captures into its own directory.

    Regenerated per session, so the suite never depends on a file that happens
    to be lying around, and nothing is committed.
    """
    root = tmp_path_factory.mktemp("investigations")
    for fixture in build_investigation_fixtures():
        directory = root / fixture.name
        directory.mkdir()
        for name, data in fixture.captures:
            (directory / name).write_bytes(data)
    return root


def paths_for(group_dir: Path, fixture: InvestigationFixture) -> list[Path]:
    return [group_dir / fixture.name / name for name, _ in fixture.captures]


@pytest.fixture(scope="session")
def investigations(
    group_dir: Path, groups: dict[str, InvestigationFixture]
) -> dict[str, Investigation]:
    return {
        name: analyze_batch(paths_for(group_dir, fixture)).investigation
        for name, fixture in groups.items()
    }


def relations_of(investigation: Investigation) -> set[str]:
    return {
        relationship.relation.value
        for entity in investigation.server_entities
        for relationship in entity.relationships
    }


def correlation_types(investigation: Investigation) -> set[str]:
    return {item.correlation_type.value for item in investigation.session_correlations}


def observed_changes(investigation: Investigation) -> set[str]:
    return {
        event.kind.value
        for event in investigation.drift_events
        if event.status is DriftStatus.OBSERVED_CHANGE
    }


# ---------------------------------------------------------------------------
# Fixture matrix -- positive and negative expectations from the manifests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", GROUP_NAMES)
def test_capture_inventory_matches_expectation(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    expected = groups[name].expected
    investigation = investigations[name]
    statuses = sorted(record.status.value for record in investigation.capture_inventory)
    assert statuses == sorted(expected.capture_statuses)
    assert len(investigation.capture_inventory) == len(groups[name].captures), (
        "every submitted capture must appear in the inventory, whatever happened to it"
    )


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_entity_count_matches_expectation(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    assert len(investigations[name].server_entities) == groups[name].expected.entity_count


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_expected_drift_is_classified_correctly(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    actual = {
        (event.kind.value, event.status.value)
        for event in investigations[name].drift_events
    }
    for expected in groups[name].expected.drift:
        assert (expected.kind, expected.status) in actual, (
            f"{name}: expected {expected.kind} to be {expected.status}, got "
            f"{sorted(k for k in actual if k[0] == expected.kind)}"
        )


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_changes_the_evidence_does_not_support_are_absent(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    """Gate 7: missing evidence is never reported as drift."""
    changed = observed_changes(investigations[name])
    for kind in groups[name].expected.forbidden_observed_changes:
        assert kind not in changed, (
            f"{name}: {kind} was reported as an observed change without support"
        )


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_expected_correlations_are_present(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    actual = correlation_types(investigations[name])
    for kind in groups[name].expected.correlation_types:
        assert kind in actual, f"{name}: expected a {kind} correlation, got {sorted(actual)}"


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_false_correlations_are_absent(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    """Gate 10: the negative half of every fixture group."""
    actual = correlation_types(investigations[name])
    for kind in groups[name].expected.forbidden_correlation_types:
        assert kind not in actual, (
            f"{name}: a {kind} correlation was produced without supporting evidence"
        )


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_identity_relations_match_expectation(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    expected = groups[name].expected
    actual = relations_of(investigations[name])
    for relation in expected.identity_relations:
        assert relation in actual, f"{name}: expected {relation}, got {sorted(actual)}"
    for relation in expected.forbidden_identity_relations:
        assert relation not in actual, (
            f"{name}: claimed a {relation} the evidence does not support"
        )


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_blast_radius_arithmetic_matches_expectation(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    """Gate 12: counts derived from evidence, checked against hand-derived ones."""
    by_rule = {item.subject: item for item in investigations[name].blast_radius}
    for expected in groups[name].expected.blast_radius:
        assert expected.rule_id in by_rule, (
            f"{name}: no blast radius for {expected.rule_id}; have {sorted(by_rule)}"
        )
        actual = by_rule[expected.rule_id]
        assert actual.session_count == expected.session_count, expected.rule_id
        assert actual.entity_count == expected.entity_count, expected.rule_id
        assert actual.capture_count == expected.capture_count, expected.rule_id
        # The counts must equal the lengths of the lists they summarise.
        assert actual.session_count == len(set(actual.affected_session_ids))
        assert actual.entity_count == len(set(actual.affected_entity_ids))
        assert actual.capture_count == len(set(actual.affected_capture_ids))


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_expected_warnings_are_raised(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    codes = {warning.code for warning in investigations[name].intelligence_warnings}
    for code in groups[name].expected.warning_codes:
        assert code in codes, f"{name}: expected warning {code}, got {sorted(codes)}"


@pytest.mark.parametrize("name", GROUP_NAMES)
def test_fingerprint_completeness_matches_expectation(
    name: str,
    groups: dict[str, InvestigationFixture],
    investigations: dict[str, Investigation],
) -> None:
    expected = groups[name].expected.fingerprint_completeness
    if not expected:
        return
    actual = sorted(
        item.completeness.value
        for item in investigations[name].cryptographic_fingerprints
    )
    assert actual == sorted(expected)


# ---------------------------------------------------------------------------
# Fingerprints: determinism, canonicalisation, versioning, partial handling
# ---------------------------------------------------------------------------
def test_fingerprints_are_deterministic(group_dir: Path, groups: dict) -> None:
    fixture = groups["A_same_configuration"]
    paths = paths_for(group_dir, fixture)
    runs = [
        [
            item.fingerprint_id
            for item in analyze_batch(paths).investigation.cryptographic_fingerprints
        ]
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]


def test_canonical_form_is_recomputable_from_the_report(
    investigations: dict[str, Investigation],
) -> None:
    """The digest must be checkable by hand from what the report contains."""
    import hashlib

    for investigation in investigations.values():
        for item in investigation.cryptographic_fingerprints:
            rebuilt = canonical_form(list(item.components))
            assert rebuilt == item.canonical_form
            digest = hashlib.sha256(item.canonical_form.encode("utf-8")).hexdigest()[:16]
            assert item.fingerprint_id == f"{FINGERPRINT_ALGORITHM_VERSION}:{digest}"


def test_canonical_form_is_ordered_and_versioned(
    investigations: dict[str, Investigation],
) -> None:
    item = investigations["A_same_configuration"].cryptographic_fingerprints[0]
    lines = item.canonical_form.splitlines()
    assert lines[0] == f"version={FINGERPRINT_ALGORITHM_VERSION}"
    assert [line.split("=", 1)[0] for line in lines[1:]] == list(COMPONENT_NAMES)
    assert item.algorithm_version == FINGERPRINT_ALGORITHM_VERSION


def test_absent_components_are_written_explicitly(
    investigations: dict[str, Investigation],
) -> None:
    """An incomplete fingerprint must not collide with a complete one."""
    item = next(
        f
        for f in investigations["H_tls13_encrypted_certificate_both"].cryptographic_fingerprints
    )
    assert "certificate_sha256=<ABSENT>" in item.canonical_form
    assert item.completeness is FingerprintCompleteness.PARTIAL
    assert "certificate_sha256" in item.missing_components


def test_a_missing_server_hello_cannot_produce_a_usable_fingerprint(
    investigations: dict[str, Investigation],
) -> None:
    """Gate 4: missing information must not fabricate a complete fingerprint."""
    insufficient = [
        item
        for item in investigations["I_missing_server_hello"].cryptographic_fingerprints
        if item.completeness is FingerprintCompleteness.INSUFFICIENT
    ]
    assert insufficient, "a ClientHello-only session must be INSUFFICIENT"
    item = insufficient[0]
    assert "tls_version" in item.missing_components
    assert item.limitations
    for component in item.components:
        if component.present:
            continue
        assert component.value is None
        assert component.source.value == "UNKNOWN"


def test_client_offers_never_become_server_components(
    investigations: dict[str, Investigation],
) -> None:
    """Gate: a client capability must never be recorded as a server one."""
    for investigation in investigations.values():
        for item in investigation.cryptographic_fingerprints:
            for component in item.components:
                assert component.source.value != "CLIENT_OFFERED", (
                    "no fingerprint component may come from what the client offered"
                )


def test_fingerprints_exclude_incidental_session_material(
    group_dir: Path, groups: dict
) -> None:
    """Source ports, timestamps and session ids must not be fingerprint input.

    Group N is two sessions to one endpoint from different source ports at
    different times. If anything incidental leaked in, their fingerprints
    would differ.
    """
    investigation = analyze_batch(
        paths_for(group_dir, groups["N_overlapping_time_ranges"])
    ).investigation
    digests = {item.fingerprint_id for item in investigation.cryptographic_fingerprints}
    assert len(digests) == 1, (
        "two sessions with identical cryptography must fingerprint identically"
    )
    for item in investigation.cryptographic_fingerprints:
        assert item.session_id not in item.canonical_form
        # Checked per component rather than by substring: a certificate digest
        # is hex and will contain almost any short digit string by chance.
        values = {
            component.value for component in item.components if component.present
        }
        assert str(item.endpoint.port) not in values
        assert item.endpoint.ip not in values


def test_two_tls13_sessions_never_reach_an_exact_match(
    investigations: dict[str, Investigation],
) -> None:
    """Gate: partial agreement is not proof of the same server."""
    items = investigations["H_tls13_encrypted_certificate_both"].cryptographic_fingerprints
    assert len(items) >= 2
    comparison = compare_fingerprints(items[0], items[1])
    assert comparison.match is FingerprintMatch.PARTIAL_AGREEMENT
    assert comparison.missing_components
    assert comparison.limitations


def test_insufficient_fingerprints_support_no_comparison(
    investigations: dict[str, Investigation],
) -> None:
    items = investigations["I_missing_server_hello"].cryptographic_fingerprints
    comparison = compare_fingerprints(items[0], items[1])
    assert comparison.match is FingerprintMatch.INSUFFICIENT_EVIDENCE
    assert not comparison.agreeing_components
    assert not comparison.conflicting_components


def test_conflicting_components_are_named(
    group_dir: Path, groups: dict
) -> None:
    outcome = analyze_batch(paths_for(group_dir, groups["C_cipher_suite_change"]))
    items = outcome.investigation.cryptographic_fingerprints
    comparison = compare_fingerprints(items[0], items[1])
    assert comparison.match is FingerprintMatch.CONFLICTING_COMPONENTS
    assert "cipher_suite" in comparison.conflicting_components


def test_configuration_fingerprint_ignores_the_certificate(
    group_dir: Path, groups: dict
) -> None:
    """A renewal changes the certificate, not the configuration."""
    outcome = analyze_batch(paths_for(group_dir, groups["E_certificate_rotation_same_key"]))
    items = outcome.investigation.cryptographic_fingerprints
    assert items[0].fingerprint_id != items[1].fingerprint_id
    assert configuration_fingerprint(items[0]) == configuration_fingerprint(items[1])


def test_configuration_fingerprint_is_none_without_a_negotiation(
    investigations: dict[str, Investigation],
) -> None:
    item = next(
        f
        for f in investigations["I_missing_server_hello"].cryptographic_fingerprints
        if f.completeness is FingerprintCompleteness.INSUFFICIENT
    )
    assert configuration_fingerprint(item) is None


# ---------------------------------------------------------------------------
# Identity: exact equality only, and never a merge
# ---------------------------------------------------------------------------
def test_entities_are_endpoints_not_connections(
    investigations: dict[str, Investigation],
) -> None:
    """Different source ports to one service are one endpoint."""
    investigation = investigations["N_overlapping_time_ranges"]
    assert len(investigation.server_entities) == 1
    entity = investigation.server_entities[0]
    assert len(entity.session_ids) == 2
    assert entity.endpoint.port == 993


def test_a_shared_certificate_never_merges_endpoints(
    investigations: dict[str, Investigation],
) -> None:
    investigation = investigations["F_shared_certificate_distinct_endpoints"]
    assert len(investigation.server_entities) == 2
    ips = {entity.endpoint.ip for entity in investigation.server_entities}
    assert len(ips) == 2
    for entity in investigation.server_entities:
        shared = [
            relationship
            for relationship in entity.relationships
            if relationship.relation.value == "SHARED_CERTIFICATE"
        ]
        assert shared, "the shared certificate must be recorded as a relationship"
        for relationship in shared:
            assert relationship.basis.startswith("certificate_sha256=")
            assert relationship.limitations, (
                "a shared certificate must carry the limitation that stops it "
                "being read as a shared machine"
            )


def test_one_address_with_two_services_is_two_entities(
    investigations: dict[str, Investigation],
) -> None:
    investigation = investigations["G_same_ip_multiple_services"]
    assert len(investigation.server_entities) == 2
    assert len({entity.endpoint.ip for entity in investigation.server_entities}) == 1
    assert {entity.endpoint.port for entity in investigation.server_entities} == {993, 465}


def test_identical_configuration_alone_is_not_a_relation_claim(
    investigations: dict[str, Investigation],
) -> None:
    """The central false-correlation case.

    Two unrelated servers with the same settings, different certificates,
    different keys and different names. A configuration match may be recorded;
    nothing stronger may be.
    """
    investigation = investigations["L_unrelated_same_configuration"]
    relations = relations_of(investigation)
    assert relations == {"CONFIGURATION_MATCH"}
    for entity in investigation.server_entities:
        for relationship in entity.relationships:
            assert relationship.limitations, (
                "a configuration match must say why it is weak evidence"
            )


def test_entity_ids_are_stable_and_order_independent(
    group_dir: Path, groups: dict
) -> None:
    fixture = groups["F_shared_certificate_distinct_endpoints"]
    paths = paths_for(group_dir, fixture)
    forward = analyze_batch(paths).investigation
    backward = analyze_batch(list(reversed(paths))).investigation
    assert [entity.entity_id for entity in forward.server_entities] == [
        entity.entity_id for entity in backward.server_entities
    ]


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------
def test_a_different_client_offer_blocks_attribution(
    investigations: dict[str, Investigation],
) -> None:
    """Gate 8: different offers are handled conservatively."""
    event = next(
        item
        for item in investigations["D_different_client_offers"].drift_events
        if item.kind.value == "NEGOTIATED_CIPHER_SUITE"
    )
    assert event.status is DriftStatus.INCONCLUSIVE
    assert event.client_offers_comparable is False
    assert event.client_offer_context, "the offers must be recorded, not just judged"
    assert event.before.value != event.after.value


def test_an_identical_client_offer_permits_attribution(
    investigations: dict[str, Investigation],
) -> None:
    event = next(
        item
        for item in investigations["B_version_downgrade"].drift_events
        if item.kind.value == "NEGOTIATED_VERSION"
    )
    assert event.status is DriftStatus.OBSERVED_CHANGE
    assert event.client_offers_comparable is True
    assert event.before.value == "TLS 1.2"
    assert event.after.value == "TLS 1.0"


def test_certificate_drift_does_not_consult_the_client_offer(
    investigations: dict[str, Investigation],
) -> None:
    """A certificate is presented regardless of what was offered."""
    for event in investigations["E_certificate_rotation_same_key"].drift_events:
        if event.kind.value.startswith("CERTIFICATE"):
            assert event.client_offers_comparable is None, (
                "reporting an offer comparison here would suggest a check that "
                "was never relevant"
            )


def test_a_renewal_is_distinguishable_from_a_rekey(
    investigations: dict[str, Investigation],
) -> None:
    events = {
        item.kind.value: item
        for item in investigations["E_certificate_rotation_same_key"].drift_events
    }
    assert events["CERTIFICATE_FINGERPRINT"].status is DriftStatus.OBSERVED_CHANGE
    assert events["CERTIFICATE_PUBLIC_KEY"].status is DriftStatus.UNCHANGED_WITH_EVIDENCE


def test_unchanged_is_positive_evidence_not_silence(
    investigations: dict[str, Investigation],
) -> None:
    event = next(
        item
        for item in investigations["A_same_configuration"].drift_events
        if item.kind.value == "NEGOTIATED_CIPHER_SUITE"
    )
    assert event.status is DriftStatus.UNCHANGED_WITH_EVIDENCE
    assert event.before.observed and event.after.observed
    assert event.before.value == event.after.value


def test_drift_follows_capture_time_not_argument_order(
    group_dir: Path, groups: dict
) -> None:
    fixture = groups["M_out_of_order_arguments"]
    paths = paths_for(group_dir, fixture)
    for ordering in (paths, list(reversed(paths))):
        investigation = analyze_batch(ordering).investigation
        event = next(
            item
            for item in investigation.drift_events
            if item.kind.value == "NEGOTIATED_CIPHER_SUITE"
        )
        assert event.status is DriftStatus.OBSERVED_CHANGE
        assert event.before.value == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        assert event.after.value == "TLS_RSA_WITH_AES_128_CBC_SHA"


def test_every_drift_event_explains_and_qualifies_itself(
    investigations: dict[str, Investigation],
) -> None:
    for investigation in investigations.values():
        for event in investigation.drift_events:
            assert event.explanation.strip()
            assert event.before.capture_id and event.after.capture_id
            if event.status is DriftStatus.OBSERVED_CHANGE:
                assert event.before.observed and event.after.observed
                assert event.limitations


def test_a_withheld_score_is_reported_as_incomparable(
    group_dir: Path, groups: dict
) -> None:
    """A score withheld for low coverage is an evidence gap, not a change."""
    paths = paths_for(group_dir, groups["A_same_configuration"])
    same = analyze_batch(paths).investigation
    score_events = [e for e in same.drift_events if e.kind.value == "POSTURE_SCORE"]
    assert score_events and all(
        event.status is DriftStatus.UNCHANGED_WITH_EVIDENCE for event in score_events
    )

    # Re-analyse the second capture under a different policy by raising the
    # minimum RSA size, which changes the policy fingerprint.
    first = analyze_capture(paths[0])
    second = analyze_capture(paths[1], config=AnalysisConfig(minimum_score_coverage_percent=80))
    assert first.assessment is not None and second.assessment is not None
    assert (
        first.assessment.policy.policy_fingerprint
        != second.assessment.policy.policy_fingerprint
    )

    from securemailscope.intelligence.engine import _build_investigation

    mixed = _build_investigation(
        [first, second], [], [], AnalysisConfig()
    ).investigation
    score_events = [e for e in mixed.drift_events if e.kind.value == "POSTURE_SCORE"]
    # Raising the coverage floor to 80% withholds the second score entirely.
    # The comparison must still appear, as explicitly incomparable: a score
    # that silently vanished between two reports would leave a reader to
    # guess why.
    assert score_events, "a score comparison must still be reported, as incomparable"
    for event in score_events:
        assert event.status is DriftStatus.NOT_COMPARABLE
        assert event.before.observed is not event.after.observed
        assert "coverage" in event.explanation.lower()


def test_score_drift_across_different_policies_is_not_comparable(
    group_dir: Path, groups: dict
) -> None:
    """Both sides scored, but under different criteria: still not comparable."""
    paths = paths_for(group_dir, groups["A_same_configuration"])
    first = analyze_capture(paths[0])
    second = analyze_capture(
        paths[1], config=AnalysisConfig(disabled_rules="TLS-PROTO-002")
    )
    assert first.assessment is not None and second.assessment is not None
    assert (
        first.assessment.policy.policy_fingerprint
        != second.assessment.policy.policy_fingerprint
    )
    assert first.assessment.sessions[0].posture_score.score is not None
    assert second.assessment.sessions[0].posture_score.score is not None

    from securemailscope.intelligence.engine import _build_investigation

    mixed = _build_investigation([first, second], [], [], AnalysisConfig()).investigation
    score_events = [e for e in mixed.drift_events if e.kind.value == "POSTURE_SCORE"]
    assert score_events
    for event in score_events:
        assert event.status is DriftStatus.NOT_COMPARABLE
        assert "policy" in event.explanation.lower()


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
def test_correlation_ids_are_stable_and_order_independent(
    group_dir: Path, groups: dict
) -> None:
    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    forward = analyze_batch(paths).investigation
    backward = analyze_batch(list(reversed(paths))).investigation
    assert [item.correlation_id for item in forward.session_correlations] == [
        item.correlation_id for item in backward.session_correlations
    ]


def test_every_correlation_names_its_basis_and_its_limits(
    investigations: dict[str, Investigation],
) -> None:
    for investigation in investigations.values():
        for item in investigation.session_correlations:
            assert "=" in item.relationship_basis, (
                "a correlation must name the property and value that linked it"
            )
            assert len(item.related_session_ids) >= 2
            assert item.related_capture_ids
            assert item.limitations


def test_correlations_never_claim_intent_or_ownership(
    investigations: dict[str, Investigation],
) -> None:
    """A correlation groups observations. It names no actor."""
    forbidden = (
        "attacker",
        "adversary",
        "campaign",
        "coordinated",
        "malicious",
        "same organisation",
        "same organization",
        "same owner",
        "threat actor",
    )
    for investigation in investigations.values():
        for item in investigation.session_correlations:
            text = " ".join((item.relationship_basis, *item.limitations)).lower()
            for word in forbidden:
                if word in text:
                    # Permitted only as an explicit denial.
                    assert (
                        f"not {word}" in text
                        or f"no {word}" in text
                        or "does not establish" in text
                        or "is inferred" in text
                    ), f"{item.correlation_id} uses {word!r} as a claim"


def test_evidence_is_deduplicated_within_a_correlation(
    investigations: dict[str, Investigation],
) -> None:
    """One finding backed by several records must not look like several."""
    for investigation in investigations.values():
        for item in investigation.session_correlations:
            keys = [
                (reference.packet_number, reference.timestamp_ns)
                for reference in item.supporting_evidence
            ]
            assert len(keys) == len(set(keys)), item.correlation_id


def test_mixed_policy_versions_are_disclosed(group_dir: Path, groups: dict) -> None:
    """Findings judged by different criteria must say so when grouped."""
    from securemailscope.intelligence.engine import _build_investigation

    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    first = analyze_capture(paths[0])
    second = analyze_capture(
        paths[1], config=AnalysisConfig(disabled_rules="MAIL-004")
    )
    investigation = _build_investigation(
        [first, second], [], [], AnalysisConfig()
    ).investigation
    shared = [
        item
        for item in investigation.session_correlations
        if item.correlation_type.value == "SHARED_RULE_FAILURE"
    ]
    assert shared
    for item in shared:
        assert item.policy_versions, "a correlation over findings must name their policies"


def test_a_single_session_never_correlates_with_itself(
    investigations: dict[str, Investigation],
) -> None:
    for investigation in investigations.values():
        for item in investigation.session_correlations:
            assert len(set(item.related_session_ids)) >= 2


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
def test_timeline_is_ordered_and_densely_indexed(
    investigations: dict[str, Investigation],
) -> None:
    for investigation in investigations.values():
        timeline = investigation.evidence_timeline
        assert [event.order_index for event in timeline] == list(range(len(timeline)))
        stamps = [
            event.timestamp_ns for event in timeline if event.timestamp_ns is not None
        ]
        assert stamps == sorted(stamps), "events with a timestamp must be in order"


def test_timeline_events_carry_real_packet_provenance(
    group_dir: Path, groups: dict, investigations: dict[str, Investigation]
) -> None:
    """Gate 11: valid timestamps and packet references."""
    for name, investigation in investigations.items():
        counts = {}
        for path in paths_for(group_dir, groups[name]):
            try:
                result = analyze_capture(path)
            except SecureMailScopeError:
                # Group T deliberately includes a file that is not a capture.
                continue
            counts[result.capture.capture_id] = result.capture.packet_count
        for event in investigation.evidence_timeline:
            for reference in event.packet_refs:
                limit = counts.get(event.capture_id)
                if limit is None:
                    continue
                assert 1 <= reference.packet_number <= limit, (
                    f"{event.event_id} cites packet {reference.packet_number} of "
                    f"{limit}"
                )
                assert reference.timestamp_ns > 0


def test_derived_timeline_events_name_their_sources(
    investigations: dict[str, Investigation],
) -> None:
    derived = {"CRYPTO_PARAMETERS_SELECTED", "SECURITY_FINDING", "CONFIGURATION_DRIFT"}
    seen = False
    for investigation in investigations.values():
        for event in investigation.evidence_timeline:
            if event.event_type.value not in derived:
                continue
            seen = True
            assert event.derived_from, (
                f"{event.event_type.value} is derived and must name its sources"
            )
            assert event.evidence_status == "INFERRED"
    assert seen, "no derived events were produced, so nothing was checked"


def test_timeline_ordering_is_stable_for_equal_timestamps(
    group_dir: Path, groups: dict
) -> None:
    """Several handshake messages routinely share one packet's timestamp."""
    paths = paths_for(group_dir, groups["A_same_configuration"])
    runs = [
        [event.event_id for event in analyze_batch(paths).investigation.evidence_timeline]
        for _ in range(3)
    ]
    assert runs[0] == runs[1] == runs[2]
    investigation = analyze_batch(paths).investigation
    by_stamp: dict[int, int] = {}
    for event in investigation.evidence_timeline:
        if event.timestamp_ns is not None:
            by_stamp[event.timestamp_ns] = by_stamp.get(event.timestamp_ns, 0) + 1
    assert max(by_stamp.values()) > 1, "the fixture must actually contain a tie"


def test_no_timestamp_is_invented(investigations: dict[str, Investigation]) -> None:
    for investigation in investigations.values():
        for event in investigation.evidence_timeline:
            if event.timestamp is None:
                assert event.timestamp_ns is None
            if event.timestamp_ns is None:
                assert event.timestamp is None


def test_clock_limitations_are_stated(
    investigations: dict[str, Investigation],
) -> None:
    text = " ".join(investigations["N_overlapping_time_ranges"].limitations).lower()
    assert "clock" in text
    assert "synchronis" in text or "synchroniz" in text
    assert "modification time" in text


# ---------------------------------------------------------------------------
# Blast radius
# ---------------------------------------------------------------------------
def test_blast_radius_never_double_counts_a_duplicate_capture(
    investigations: dict[str, Investigation],
) -> None:
    """Gate 13."""
    for radius in investigations["K_duplicate_capture"].blast_radius:
        assert radius.capture_count == 1
        assert radius.session_count == 1
        assert radius.entity_count == 1


def test_blast_radius_counts_one_endpoint_per_service(
    investigations: dict[str, Investigation],
) -> None:
    """Two sessions from different source ports are one endpoint."""
    investigation = investigations["N_overlapping_time_ranges"]
    for radius in investigation.blast_radius:
        assert radius.entity_count == 1


def test_blast_radius_states_its_scope_and_method(
    investigations: dict[str, Investigation],
) -> None:
    for investigation in investigations.values():
        for radius in investigation.blast_radius:
            assert radius.scope_statement == SCOPE_STATEMENT
            assert "distinct" in radius.counting_method
            assert radius.limitations
            joined = " ".join(radius.limitations).lower()
            assert "not captured" in joined or "outside the captures" in joined


def test_blast_radius_claims_nothing_about_the_wider_estate(
    investigations: dict[str, Investigation],
) -> None:
    forbidden = ("enterprise", "all users", "every server", "organisation-wide")
    for investigation in investigations.values():
        for radius in investigation.blast_radius:
            text = " ".join(
                (radius.scope_statement, radius.counting_method, *radius.limitations)
            ).lower()
            for word in forbidden:
                assert word not in text, f"{radius.subject} claims {word!r}"


# ---------------------------------------------------------------------------
# Batch semantics, limits and privacy
# ---------------------------------------------------------------------------
def test_results_do_not_depend_on_argument_order(
    group_dir: Path, groups: dict
) -> None:
    """Gate: deterministic ordering independent of input-file argument order."""
    for name in ("Q_same_finding_across_endpoints", "F_shared_certificate_distinct_endpoints"):
        paths = paths_for(group_dir, groups[name])
        forward = analyze_batch(paths).investigation
        backward = analyze_batch(list(reversed(paths))).investigation
        assert forward.investigation_id == backward.investigation_id
        for field in (
            "server_entities",
            "cryptographic_fingerprints",
            "drift_events",
            "session_correlations",
            "blast_radius",
        ):
            left = getattr(forward, field)
            right = getattr(backward, field)
            assert [item.model_dump(mode="json") for item in left] == [
                item.model_dump(mode="json") for item in right
            ], f"{name}: {field} depends on argument order"


def test_repeated_investigations_are_byte_identical(
    group_dir: Path, groups: dict
) -> None:
    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    documents = []
    for _ in range(3):
        document = analyze_batch(paths).investigation.model_dump(mode="json")
        # created_at is the one documented nondeterministic field.
        document.pop("created_at", None)
        documents.append(json.dumps(document, sort_keys=True))
    assert documents[0] == documents[1] == documents[2]


def test_a_duplicate_capture_is_analysed_once(
    group_dir: Path, groups: dict
) -> None:
    fixture = groups["K_duplicate_capture"]
    outcome = analyze_batch(paths_for(group_dir, fixture))
    assert len(outcome.results) == 1, "the duplicate must not be analysed twice"
    record = next(
        item
        for item in outcome.investigation.capture_inventory
        if item.status is CaptureStatus.DUPLICATE
    )
    assert record.duplicate_of_source
    assert record.capture_id == outcome.results[0].capture.capture_id


def test_a_failed_capture_stays_in_the_inventory(
    group_dir: Path, groups: dict
) -> None:
    investigation = analyze_batch(
        paths_for(group_dir, groups["T_malformed_batch_member"])
    ).investigation
    failed = [
        item
        for item in investigation.capture_inventory
        if item.status is CaptureStatus.FAILED
    ]
    assert len(failed) == 1
    assert failed[0].failure_reason
    assert "CAPTURE_FAILED" in {
        warning.code for warning in investigation.intelligence_warnings
    }


def test_a_missing_file_is_recorded_not_raised(tmp_path: Path) -> None:
    investigation = analyze_batch([tmp_path / "nope.pcap"]).investigation
    assert [item.status for item in investigation.capture_inventory] == [
        CaptureStatus.FAILED
    ]


def test_capture_evidence_survives_the_batch(group_dir: Path, groups: dict) -> None:
    """Gate 2: capture identities and evidence remain intact."""
    fixture = groups["A_same_configuration"]
    paths = paths_for(group_dir, fixture)
    outcome = analyze_batch(paths)
    standalone = [analyze_capture(path) for path in paths]
    for batched, alone in zip(outcome.results, standalone, strict=True):
        assert batched.capture.capture_id == alone.capture.capture_id
        assert batched.capture.packet_count == alone.capture.packet_count
        assert [s.session_id for s in batched.sessions] == [
            s.session_id for s in alone.sessions
        ]
        assert batched.tls[0].model_dump(mode="json") == alone.tls[0].model_dump(
            mode="json"
        )


def test_the_capture_limit_warns_rather_than_dropping_silently(
    group_dir: Path, groups: dict
) -> None:
    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    investigation = analyze_batch(
        paths, config=AnalysisConfig(max_batch_captures=1)
    ).investigation
    codes = {warning.code for warning in investigation.intelligence_warnings}
    assert "BATCH_CAPTURE_LIMIT" in codes
    assert len(investigation.capture_inventory) == 1


def test_the_timeline_limit_warns_rather_than_truncating_silently(
    group_dir: Path, groups: dict
) -> None:
    paths = paths_for(group_dir, groups["A_same_configuration"])
    investigation = analyze_batch(
        paths, config=AnalysisConfig(max_timeline_events=3)
    ).investigation
    assert len(investigation.evidence_timeline) == 3
    assert "TIMELINE_LIMIT" in {
        warning.code for warning in investigation.intelligence_warnings
    }


def test_the_correlation_limit_warns_rather_than_truncating_silently(
    group_dir: Path, groups: dict
) -> None:
    paths = paths_for(group_dir, groups["A_same_configuration"])
    investigation = analyze_batch(
        paths, config=AnalysisConfig(max_batch_correlations=1)
    ).investigation
    assert len(investigation.session_correlations) == 1
    assert "CORRELATION_LIMIT" in {
        warning.code for warning in investigation.intelligence_warnings
    }


def test_no_credential_material_reaches_an_investigation(tmp_path: Path) -> None:
    """The M2 redaction guarantee must hold through the new layer."""
    import hashlib

    from securemailscope.testing.fixtures import build_fixtures

    specs = {spec.name: spec for spec in build_fixtures()}
    names = [
        "P_M_auth_before_tls",
        "P_N_no_plaintext_after_upgrade",
        "P_P_data_body_fake_starttls",
    ]
    paths = []
    forbidden: set[str] = set()
    for name in names:
        spec = specs[name]
        path = tmp_path / spec.filename
        path.write_bytes(spec.data)
        paths.append(path)
        forbidden.update(spec.forbidden_strings)
    assert forbidden, "the chosen fixtures must actually carry dummy credentials"
    assert hashlib.sha256  # the import is used above; keeps the intent explicit

    outcome = analyze_batch(paths)
    serialised = json.dumps(investigation_to_dict(outcome), ensure_ascii=False)
    for secret in forbidden:
        assert secret not in serialised, f"{secret!r} reached the investigation output"


def test_the_engine_opens_no_socket(group_dir: Path, groups: dict) -> None:
    """The intelligence layer must be as passive as everything beneath it."""
    import socket

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the intelligence layer attempted a network connection")

    original = socket.socket
    socket.socket = refuse  # type: ignore[assignment,misc]
    try:
        analyze_batch(paths_for(group_dir, groups["F_shared_certificate_distinct_endpoints"]))
    finally:
        socket.socket = original  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Output contract and CLI
# ---------------------------------------------------------------------------
def test_the_investigation_document_carries_every_required_block(
    group_dir: Path, groups: dict
) -> None:
    outcome = analyze_batch(paths_for(group_dir, groups["Q_same_finding_across_endpoints"]))
    document = investigation_to_dict(outcome)
    investigation = document["investigation"]
    for key in (
        "investigation_id",
        "capture_inventory",
        "server_entities",
        "cryptographic_fingerprints",
        "drift_events",
        "session_correlations",
        "evidence_timeline",
        "blast_radius",
        "intelligence_warnings",
    ):
        assert key in investigation, f"missing required block {key}"
    assert investigation["scope_statement"] == SCOPE_STATEMENT
    assert investigation["fingerprint_algorithm_version"] == FINGERPRINT_ALGORITHM_VERSION


def test_individual_capture_reports_are_preserved_unchanged(
    group_dir: Path, groups: dict
) -> None:
    """Gate: forensic evidence is never replaced by a summarised label."""
    outcome = analyze_batch(paths_for(group_dir, groups["A_same_configuration"]))
    document = investigation_to_dict(outcome)
    assert len(document["captures"]) == 2
    for capture in document["captures"]:
        for key in ("capture", "sessions", "tls", "inventory", "assessment"):
            assert key in capture, f"M1-M4 block {key} was dropped in batch mode"
        assert capture["tls"][0]["cipher_suite"]["selected"] is not None
        assert capture["tool"]["report_schema_version"] == "1.4.0"


def test_cli_batch_analysis_end_to_end(
    group_dir: Path, groups: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from securemailscope.cli import main

    destination = tmp_path / "investigation.json"
    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    exit_code = main(
        ["analyze-batch", *[str(path) for path in paths], "-o", str(destination)]
    )
    assert exit_code == 0
    document = json.loads(destination.read_text(encoding="utf-8"))
    investigation = document["investigation"]
    assert len(investigation["server_entities"]) == 2
    assert len(document["captures"]) == 2
    radius = next(
        item for item in investigation["blast_radius"] if item["subject"] == "TLS-PROTO-001"
    )
    assert (radius["session_count"], radius["entity_count"], radius["capture_count"]) == (
        2,
        2,
        2,
    )
    printed = capsys.readouterr().err
    assert "2 analysed" in printed
    assert SCOPE_STATEMENT in printed


def test_cli_batch_reports_a_failed_member(
    group_dir: Path, groups: dict, capsys: pytest.CaptureFixture[str]
) -> None:
    from securemailscope.cli import main

    paths = paths_for(group_dir, groups["T_malformed_batch_member"])
    exit_code = main(
        ["analyze-batch", *[str(path) for path in paths], "-o", "/dev/null"]
    )
    assert exit_code == 0
    printed = capsys.readouterr().err
    assert "1 failed" in printed
    assert "FAILED" in printed


def test_cli_batch_can_omit_capture_reports(
    group_dir: Path, groups: dict, tmp_path: Path
) -> None:
    from securemailscope.cli import main

    destination = tmp_path / "small.json"
    paths = paths_for(group_dir, groups["A_same_configuration"])
    assert (
        main(
            [
                "analyze-batch",
                *[str(path) for path in paths],
                "-o",
                str(destination),
                "--no-capture-reports",
                "--quiet",
            ]
        )
        == 0
    )
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert "captures" not in document
    assert document["investigation"]["server_entities"]


def test_a_selection_is_never_dated_before_the_message_that_made_it(
    investigations: dict[str, Investigation],
) -> None:
    """A negotiated-parameters event must not precede its own ServerHello."""
    checked = False
    for investigation in investigations.values():
        by_session: dict[str, dict[str, int]] = {}
        for event in investigation.evidence_timeline:
            if event.session_id is None or event.timestamp_ns is None:
                continue
            by_session.setdefault(event.session_id, {})[event.event_type.value] = (
                event.timestamp_ns
            )
        for stamps in by_session.values():
            server_hello = stamps.get("SERVER_HELLO")
            selected = stamps.get("CRYPTO_PARAMETERS_SELECTED")
            if server_hello is None or selected is None:
                continue
            checked = True
            assert selected >= server_hello, (
                "the negotiated parameters were dated before the ServerHello"
            )
    assert checked, "no session had both events, so nothing was checked"


# ---------------------------------------------------------------------------
# M5 corrective audit: correlation identifier scope
# ---------------------------------------------------------------------------
def test_disjoint_groups_of_the_same_type_do_not_share_an_id(
    group_dir: Path, groups: dict
) -> None:
    """Regression: correlation ids must be scoped to their members.

    Derived from type and basis alone, two investigations that each contain
    sessions failing ``TLS-PROTO-001`` produced the *same* identifier for two
    entirely disjoint groups. Anyone diffing the reports would have read them
    as one correlation that had grown.
    """
    first = analyze_batch(
        paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    ).investigation
    second = analyze_batch(
        paths_for(group_dir, groups["B_version_downgrade"])
    ).investigation

    def by_rule(investigation: Investigation) -> dict[str, tuple[str, frozenset[str]]]:
        return {
            item.relationship_basis: (
                item.correlation_id,
                frozenset(item.related_session_ids),
            )
            for item in investigation.session_correlations
            if item.correlation_type.value == "SHARED_RULE_FAILURE"
        }

    left, right = by_rule(first), by_rule(second)
    shared_bases = set(left) & set(right)
    assert shared_bases, "the fixtures must share at least one failing rule"
    for basis in shared_bases:
        left_id, left_members = left[basis]
        right_id, right_members = right[basis]
        assert left_members.isdisjoint(right_members), (
            "precondition: the two groups must have no session in common"
        )
        assert left_id != right_id, (
            f"{basis}: disjoint correlations share the identifier {left_id}"
        )


def test_the_same_grouping_keeps_its_id_across_runs(
    group_dir: Path, groups: dict
) -> None:
    """The property scoping was added to preserve: identical groupings diff."""
    paths = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    first = analyze_batch(paths).investigation
    second = analyze_batch(list(reversed(paths))).investigation
    assert [item.correlation_id for item in first.session_correlations] == [
        item.correlation_id for item in second.session_correlations
    ]


def test_a_correlation_id_changes_when_its_membership_changes(
    group_dir: Path, groups: dict
) -> None:
    """Adding a session to a group makes it a different correlation."""
    from securemailscope.intelligence.engine import _build_investigation

    two = paths_for(group_dir, groups["Q_same_finding_across_endpoints"])
    results = [analyze_capture(path) for path in two]
    smaller = _build_investigation(results, [], [], AnalysisConfig()).investigation

    extra = paths_for(group_dir, groups["K_duplicate_capture"])[:1]
    larger = _build_investigation(
        [*results, analyze_capture(extra[0])], [], [], AnalysisConfig()
    ).investigation

    def ids_by_basis(investigation: Investigation) -> dict[str, str]:
        return {
            item.relationship_basis: item.correlation_id
            for item in investigation.session_correlations
            if item.correlation_type.value == "SHARED_RULE_FAILURE"
        }

    before, after = ids_by_basis(smaller), ids_by_basis(larger)
    grown = [
        basis
        for basis in set(before) & set(after)
        if before[basis] != after[basis]
    ]
    assert grown, "a correlation that gained a member must get a new identifier"
