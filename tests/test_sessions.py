"""Connection identification: separation, direction and tuple reuse."""

from __future__ import annotations

from securemailscope import analyze_capture
from securemailscope.models.evidence import WarningCode
from securemailscope.models.tcp import Endpoint
from securemailscope.network.flows import flow_id_for, normalize
from tests.narrowing import present

from .conftest import Fixture


def test_normalisation_is_order_independent() -> None:
    a = Endpoint(ip="192.0.2.10", port=49152)
    b = Endpoint(ip="198.51.100.25", port=25)
    assert normalize(a, b) == normalize(b, a)
    assert flow_id_for(normalize(a, b)) == flow_id_for(normalize(b, a))


def test_different_tuples_get_different_flow_ids() -> None:
    a = Endpoint(ip="192.0.2.10", port=49152)
    b = Endpoint(ip="198.51.100.25", port=25)
    c = Endpoint(ip="192.0.2.10", port=49153)
    assert flow_id_for(normalize(a, b)) != flow_id_for(normalize(c, b))


def test_independent_connections_are_kept_separate(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["G_two_connections"].path)
    assert len(result.sessions) == 2
    flow_ids = {session.flow.flow_id for session in result.sessions}
    session_ids = {session.session_id for session in result.sessions}
    assert len(flow_ids) == 2
    assert len(session_ids) == 2
    # Interleaving must not leak bytes between them.
    assert result.sessions[0].client_to_server.bytes_reconstructed == 10
    assert result.sessions[1].client_to_server.bytes_reconstructed == 17


def test_tuple_reuse_produces_two_sessions_on_one_flow(
    fixtures: dict[str, Fixture],
) -> None:
    result = analyze_capture(fixtures["J_tuple_reuse"].path)
    assert len(result.sessions) == 2
    first, second = result.sessions
    assert first.flow.flow_id == second.flow.flow_id, "same five-tuple, so one flow id"
    assert first.session_id != second.session_id, "distinct connections, distinct sessions"
    assert (first.flow_instance, second.flow_instance) == (1, 2)
    assert first.handshake.client_isn == 1000
    assert second.handshake.client_isn == 9000
    assert first.client_to_server.bytes_reconstructed == 7
    assert second.client_to_server.bytes_reconstructed == 8
    assert result.inventory.tuple_reuse_count == 1
    codes = {w.code for w in result.warnings} | {
        w.code for s in result.sessions for w in s.warnings
    }
    assert WarningCode.TUPLE_REUSE in codes


def test_direction_is_preserved_after_normalisation(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["A_complete_connection"].path)
    session = result.sessions[0]
    c2s = session.client_to_server
    s2c = session.server_to_client
    assert c2s.source == session.flow.client
    assert c2s.destination == session.flow.server
    assert s2c.source == session.flow.server
    assert s2c.destination == session.flow.client
    assert c2s.bytes_reconstructed == 21
    assert s2c.bytes_reconstructed == 24


def test_roles_are_observed_when_a_syn_is_present(fixtures: dict[str, Fixture]) -> None:
    session = analyze_capture(fixtures["A_complete_connection"].path).sessions[0]
    assert session.flow.role_status.value == "OBSERVED"
    assert session.flow.role_basis == "TCP_SYN"
    assert session.handshake.complete is True
    assert session.client_to_server.base_status.value == "OBSERVED"


def test_midstream_capture_is_labelled_inferred(fixtures: dict[str, Fixture]) -> None:
    session = analyze_capture(fixtures["M_midstream"].path).sessions[0]
    assert session.completeness.value == "MIDSTREAM"
    assert session.flow.role_status.value == "INFERRED"
    assert session.handshake.syn_observed is False
    assert session.client_to_server.base_status.value == "INFERRED"
    assert session.client_to_server.base_basis == "LOWEST_OBSERVED_SEQUENCE"
    assert any("capture began after" in note for note in session.completeness_notes)


def test_ipv6_sessions_are_reconstructed(fixtures: dict[str, Fixture]) -> None:
    session = analyze_capture(fixtures["L_ipv6_connection"].path).sessions[0]
    assert session.flow.address_family.value == "IPv6"
    assert session.flow.client.ip == "2001:db8::10"
    assert session.client_to_server.bytes_reconstructed == 21


def test_session_ids_are_stable_across_runs(fixtures: dict[str, Fixture]) -> None:
    path = fixtures["J_tuple_reuse"].path
    first = [session.session_id for session in analyze_capture(path).sessions]
    second = [session.session_id for session in analyze_capture(path).sessions]
    assert first == second


def test_protocol_hints_are_labelled_as_hints(fixtures: dict[str, Fixture]) -> None:
    result = analyze_capture(fixtures["G_two_connections"].path)
    hints = [
        present(session.protocol_hint, "a protocol hint")
        for session in result.sessions
    ]
    assert [hint.value for hint in hints] == ["HINT:SMTP", "HINT:IMAP"]
    for hint in hints:
        assert hint.status.value == "INFERRED"
        assert hint.basis == "SERVER_PORT"
        assert hint.limitations, "an inferred value must state its limitations"
        assert any("NOT a confirmed" in text for text in hint.limitations)
