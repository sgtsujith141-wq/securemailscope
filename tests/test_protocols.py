"""Manifest-driven verification of the M2 email protocol layer.

Expectations come from the committed fixture manifests, which are hand-derived
from how each dialogue was constructed -- not recorded from engine output.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from securemailscope import analyze_capture
from securemailscope.reporting.json_report import result_to_json

from .conftest import Fixture

PROTOCOL_FIXTURES = [
    "P_A_smtp_starttls_accepted",
    "P_B_smtp_starttls_rejected",
    "P_C_smtp_multiline_220",
    "P_D_imap_starttls_accepted",
    "P_E_imap_wrong_tag_ok",
    "P_F_pop3_stls_accepted",
    "P_G_pop3_stls_rejected",
    "P_H_smtp_nonstandard_port",
    "P_I_pop3_on_imap_port",
    "P_J_starttls_no_response",
    "P_K_gap_during_upgrade",
    "P_L_tls_bytes_in_accept_packet",
    "P_M_auth_before_tls",
    "P_N_no_plaintext_after_upgrade",
    "P_O_implicit_tls_incomplete",
    "P_P_data_body_fake_starttls",
    "P_Q_imap_literal_fake_commands",
    "P_R_pop3_message_fake_stls",
    "P_S_commands_split_across_segments",
    "P_T_midstream_smtp",
]


def _expected(fixture: Fixture) -> list[dict[str, Any]]:
    expected = fixture.manifest.get("expected_protocols")
    assert expected is not None, f"{fixture.name} declares no protocol expectations"
    return expected


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_packet_counts_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    assert result.capture.packet_count == fixture.manifest["expected_packet_count"]
    assert result.capture.tcp_packet_count == fixture.manifest["expected_tcp_packet_count"]
    assert result.capture.capture_id == "sha256:" + fixture.manifest["capture_sha256"]


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_detection_matches_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    expected_all = _expected(fixture)
    assert len(result.protocols) >= len(expected_all)

    for expected in expected_all:
        analysis = result.protocols[expected["session_index"]]
        label = f"{fixture.name}/session{expected['session_index']}"
        detection = analysis.detection
        assert detection.protocol.value == expected["protocol"], f"{label}: protocol"
        assert detection.status.value == expected["detection_status"], f"{label}: status"
        assert (
            detection.confidence_basis == expected["confidence_basis"]
        ), f"{label}: confidence basis"
        assert analysis.parse_state.value == expected["parse_state"], f"{label}: parse state"
        assert detection.port_hint == expected["port_hint"], f"{label}: port hint"
        assert (
            detection.port_hint_agrees == expected["port_hint_agrees"]
        ), f"{label}: port hint agreement"

        # A port number must never be enough to reach CONFIRMED.
        if detection.status.value == "CONFIRMED":
            assert detection.confidence_basis != "SERVER_PORT_ONLY"
            assert detection.evidence_status.value == "OBSERVED"
            assert detection.evidence_refs, f"{label}: CONFIRMED needs packet evidence"
        if detection.status.value in {"PROBABLE", "PORT_HINT"}:
            assert detection.limitations, f"{label}: inferred detection needs limitations"


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_upgrade_state_and_boundaries_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.protocols[expected["session_index"]]
        label = f"{fixture.name}/session{expected['session_index']}"
        expected_upgrade = expected["upgrade"]

        if expected_upgrade is None:
            assert analysis.upgrade is None, f"{label}: no upgrade should be reported"
            continue

        upgrade = analysis.upgrade
        assert upgrade is not None, f"{label}: an upgrade was expected"
        assert upgrade.mechanism.value == expected_upgrade["mechanism"], f"{label}: mechanism"
        assert upgrade.state.value == expected_upgrade["state"], f"{label}: state"
        assert (upgrade.advertised is not None) == expected_upgrade["advertised"], (
            f"{label}: advertisement"
        )
        assert (upgrade.requested is not None) == expected_upgrade["requested"], (
            f"{label}: request"
        )
        assert upgrade.response_code == expected_upgrade["response_code"], f"{label}: code"
        assert len(upgrade.tls_records) == expected_upgrade["tls_record_count"], (
            f"{label}: TLS record count"
        )

        # M2 never analyses a handshake, whatever the framing showed.
        assert upgrade.handshake_analyzed is False
        assert upgrade.handshake_analysis_status == "NOT_IMPLEMENTED"
        assert upgrade.negotiated_parameters_available is False
        assert upgrade.limitations, f"{label}: an upgrade must state its limitations"

        if expected_upgrade["server_boundary_offset"] is not None:
            assert upgrade.server_boundary is not None, f"{label}: server boundary missing"
            assert (
                upgrade.server_boundary.stream_offset
                == expected_upgrade["server_boundary_offset"]
            ), f"{label}: server boundary offset"
            assert (
                upgrade.server_boundary.basis == expected_upgrade["server_boundary_basis"]
            ), f"{label}: server boundary basis"
        if expected_upgrade["client_boundary_offset"] is not None:
            assert upgrade.client_boundary is not None, f"{label}: client boundary missing"
            assert (
                upgrade.client_boundary.stream_offset
                == expected_upgrade["client_boundary_offset"]
            ), f"{label}: client boundary offset"
            assert (
                upgrade.client_boundary.basis == expected_upgrade["client_boundary_basis"]
            ), f"{label}: client boundary basis"


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_key_events_present_with_exact_offsets_and_provenance(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.protocols[expected["session_index"]]
        label = f"{fixture.name}/session{expected['session_index']}"

        for expected_event in expected["key_events"]:
            matches = [
                event
                for event in analysis.events
                if event.event_type.value == expected_event["event_type"]
                and event.direction.value == expected_event["direction"]
                and event.stream_offset == expected_event["stream_offset"]
            ]
            seen = [
                (event.event_type.value, event.direction.value, event.stream_offset)
                for event in analysis.events
            ]
            assert matches, (
                f"{label}: no {expected_event['event_type']} at "
                f"{expected_event['direction']} offset {expected_event['stream_offset']}; "
                f"saw {seen}"
            )
            event = matches[0]
            if expected_event["end_offset"] is not None:
                assert event.end_offset == expected_event["end_offset"], f"{label}: end offset"
            if expected_event["command_verb"] is not None:
                assert event.command_verb == expected_event["command_verb"]
            if expected_event["reply_code"] is not None:
                assert event.reply_code == expected_event["reply_code"]
            if expected_event["tag"] is not None:
                assert event.tag == expected_event["tag"]
            # Provenance is mandatory on every event derived from bytes.
            assert event.packet_refs, f"{label}: event carries no packet reference"
            assert all(ref.packet_number >= 1 for ref in event.packet_refs)
            assert event.first_timestamp is not None
            assert event.first_timestamp.tzinfo is not None

        present = {event.event_type.value for event in analysis.events}
        for forbidden in expected["forbidden_event_types"]:
            assert forbidden not in present, f"{label}: {forbidden} must not be reported"


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_authentication_observations_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.protocols[expected["session_index"]]
        label = f"{fixture.name}/session{expected['session_index']}"
        expected_auth = expected["authentication"]
        assert len(analysis.authentication) == len(expected_auth), (
            f"{label}: authentication observation count; "
            f"saw {[(o.command_verb, o.stream_offset) for o in analysis.authentication]}"
        )
        for observation, wanted in zip(analysis.authentication, expected_auth, strict=True):
            assert observation.command_verb == wanted["command_verb"], f"{label}: verb"
            assert observation.direction.value == wanted["direction"], f"{label}: direction"
            assert observation.stream_offset == wanted["stream_offset"], f"{label}: offset"
            assert (
                observation.occurred_before_tls_upgrade == wanted["before_upgrade"]
            ), f"{label}: before-upgrade flag"
            assert observation.mechanism == wanted["mechanism"], f"{label}: mechanism"
            assert (
                observation.continuation_exchanges == wanted["continuation_exchanges"]
            ), f"{label}: continuation count"
            # The guarantee, asserted rather than trusted.
            assert observation.credentials_recorded is False
            assert observation.packet_refs
            assert observation.limitations


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_warning_codes_match_manifest(fixture: Fixture) -> None:
    result = analyze_capture(fixture.path)
    for expected in _expected(fixture):
        analysis = result.protocols[expected["session_index"]]
        observed = {warning.code.value for warning in analysis.warnings}
        assert observed == set(expected["expected_warning_codes"]), (
            f"{fixture.name}: protocol warning codes"
        )


@pytest.mark.parametrize("fixture", PROTOCOL_FIXTURES, indirect=True)
def test_no_credential_material_reaches_the_report(fixture: Fixture) -> None:
    """Dummy credentials in a fixture must not appear anywhere in the output."""
    forbidden = fixture.manifest["forbidden_strings"]
    if not forbidden:
        pytest.skip("fixture carries no credential material")
    result = analyze_capture(fixture.path)
    text = result_to_json(result)
    for secret in forbidden:
        assert secret not in text, f"{fixture.name}: {secret!r} leaked into the report"
    # Also check every warning message and detail individually, since those are
    # the places a stray f-string would put capture bytes.
    for analysis in result.protocols:
        for warning in analysis.warnings:
            blob = warning.message + json.dumps(warning.details)
            for secret in forbidden:
                assert secret not in blob, f"{fixture.name}: {secret!r} leaked into a warning"
        for event in analysis.events:
            for secret in forbidden:
                assert secret not in event.detail
