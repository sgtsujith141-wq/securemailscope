"""End-to-end tests that execute the installed CLI as a subprocess."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import Fixture


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the CLI the way a user would, through the installed entry point."""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell, test-controlled input
        [sys.executable, "-m", "securemailscope", *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.integration
def test_analyze_writes_a_json_report(fixtures: dict[str, Fixture], tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    completed = run_cli(
        "analyze", str(fixtures["A_complete_connection"].path), "--output", str(output)
    )
    assert completed.returncode == 0, completed.stderr
    assert output.is_file()

    report = json.loads(output.read_text())
    assert report["capture"]["packet_count"] == 11
    assert report["inventory"]["session_count"] == 1
    session = report["sessions"][0]
    assert session["flow"]["client"] == {"ip": "192.0.2.10", "port": 49152}
    assert session["flow"]["server"] == {"ip": "198.51.100.25", "port": 25}
    assert session["completeness"] == "COMPLETE"
    assert session["client_to_server"]["bytes_reconstructed"] == 21
    assert session["server_to_client"]["bytes_reconstructed"] == 24
    assert session["protocol_hint"]["value"] == "HINT:SMTP"
    assert session["protocol_hint"]["status"] == "INFERRED"
    # The summary goes to stderr so stdout stays clean for piping.
    assert "sessions     : 1" in completed.stderr


@pytest.mark.integration
def test_analyze_writes_json_to_stdout_without_output(
    fixtures: dict[str, Fixture],
) -> None:
    completed = run_cli("analyze", str(fixtures["A_complete_connection"].path), "--quiet")
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["tool"]["name"] == "securemailscope"
    assert completed.stderr == ""


@pytest.mark.integration
def test_analyze_reports_gaps_and_conflicts(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    output = tmp_path / "gaps.json"
    completed = run_cli(
        "analyze", str(fixtures["F_missing_segment"].path), "-o", str(output), "--quiet"
    )
    assert completed.returncode == 0, completed.stderr
    stream = json.loads(output.read_text())["sessions"][0]["client_to_server"]
    assert stream["gaps"] == [
        {
            "stream_offset": 5,
            "length": 7,
            "reason": "MISSING_SEGMENT",
            "content_status": "UNKNOWN",
            "preceding_packet": stream["gaps"][0]["preceding_packet"],
            "following_packet": stream["gaps"][0]["following_packet"],
        }
    ]
    assert stream["gaps"][0]["preceding_packet"]["packet_number"] == 4
    assert stream["gaps"][0]["following_packet"]["packet_number"] == 5


@pytest.mark.integration
def test_invalid_capture_exits_with_input_error(fixtures: dict[str, Fixture]) -> None:
    completed = run_cli("analyze", str(fixtures["I2_not_a_capture"].path))
    assert completed.returncode == 2
    assert "input error" in completed.stderr
    assert completed.stdout == ""


@pytest.mark.integration
def test_missing_file_exits_with_input_error(tmp_path: Path) -> None:
    completed = run_cli("analyze", str(tmp_path / "absent.pcap"))
    assert completed.returncode == 2
    assert "does not exist" in completed.stderr


@pytest.mark.integration
def test_status_reports_unimplemented_stages() -> None:
    completed = run_cli("status")
    assert completed.returncode == 0
    status = json.loads(completed.stdout)
    # M3 implements TLS analysis for the observable plaintext portion only.
    assert status["TLS_ANALYSIS"] == "PARTIAL"
    assert status["CERTIFICATE_REVOCATION"] == "NOT_IMPLEMENTED"
    # M4 assesses within a capture; combining findings across hosts is M5.
    assert status["RISK_ASSESSMENT"] == "PARTIAL"
    assert status["EVIDENCE_CORRELATION"] == "NOT_IMPLEMENTED"
    assert status["ML_ANALYSIS"] == "NOT_IMPLEMENTED"


@pytest.mark.integration
def test_fixture_generation_is_reproducible(tmp_path: Path) -> None:
    """Two independent generations must produce identical bytes."""
    first = tmp_path / "one"
    second = tmp_path / "two"
    for destination in (first, second):
        completed = run_cli(
            "fixtures",
            "--capture-dir",
            str(destination / "captures"),
            "--manifest-dir",
            str(destination / "manifests"),
        )
        assert completed.returncode == 0, completed.stderr

    # Only fixtures that declare byte reproducibility are compared: live
    # OpenSSL handshakes and randomised ECDSA signatures differ every run by
    # design, and their manifests record no hash.
    reproducible = {
        json.loads(path.read_text())["filename"]
        for path in (first / "manifests").glob("*.json")
        if json.loads(path.read_text()).get("byte_reproducible", True)
    }
    assert reproducible, "no reproducible fixtures were generated"
    for name in sorted(reproducible):
        assert (first / "captures" / name).read_bytes() == (
            second / "captures" / name
        ).read_bytes(), f"{name} is not reproducible"


@pytest.mark.integration
def test_committed_manifests_match_regenerated_ones(tmp_path: Path) -> None:
    """The manifests in the repository must not drift from the generator."""
    completed = run_cli(
        "fixtures",
        "--capture-dir",
        str(tmp_path / "captures"),
        "--manifest-dir",
        str(tmp_path / "manifests"),
    )
    assert completed.returncode == 0, completed.stderr
    committed_dir = Path(__file__).parent / "fixtures" / "manifests"
    volatile = {
        # Certificate serials and fingerprints are stable, but a fresh CA is
        # created per build, so issuer/subject key identifiers and signature
        # bytes differ. Only structural expectations are compared for those.
        "expected_timestamps_ns",
    }
    for regenerated in sorted((tmp_path / "manifests").glob("*.json")):
        committed = committed_dir / regenerated.name
        assert committed.is_file(), f"{regenerated.name} is not committed"
        left = json.loads(committed.read_text())
        right = json.loads(regenerated.read_text())
        if not right.get("byte_reproducible", True):
            for key in volatile:
                left.pop(key, None)
                right.pop(key, None)
        assert left == right, (
            f"{regenerated.name} differs from the committed manifest; "
            "run `make fixtures` and review the change"
        )


# ---------------------------------------------------------------------------
# M2: application protocol layer
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_analyze_reports_starttls_state(fixtures: dict[str, Fixture], tmp_path: Path) -> None:
    output = tmp_path / "starttls.json"
    completed = run_cli(
        "analyze", str(fixtures["P_A_smtp_starttls_accepted"].path), "-o", str(output)
    )
    assert completed.returncode == 0, completed.stderr

    report = json.loads(output.read_text())
    assert report["tool"]["report_schema_version"] == "1.3.0"
    # M1 data is still present and unchanged in shape.
    assert report["sessions"][0]["client_to_server"]["bytes_reconstructed"] > 0
    assert "runs" in report["sessions"][0]["client_to_server"]

    analysis = report["protocols"][0]
    assert analysis["session_id"] == report["sessions"][0]["session_id"]
    assert analysis["detection"]["protocol"] == "SMTP"
    assert analysis["detection"]["status"] == "CONFIRMED"
    assert analysis["parse_state"] == "HANDED_OFF_TO_TLS"

    upgrade = analysis["upgrade"]
    assert upgrade["mechanism"] == "STARTTLS"
    assert upgrade["state"] == "TLS_BYTES_OBSERVED"
    assert upgrade["handshake_analyzed"] is False
    assert upgrade["negotiated_parameters_available"] is False
    assert upgrade["server_boundary"]["basis"] == "SERVER_SUCCESS_REPLY_END"
    assert upgrade["client_boundary"]["basis"] == "FIRST_TLS_RECORD"
    assert len(upgrade["tls_records"]) == 2

    assert report["protocol_inventory"]["confirmed_smtp_count"] == 1
    assert report["protocol_inventory"]["tls_handshakes_analysed"] == 0
    assert "STARTTLS: TLS_BYTES_OBSERVED" in completed.stderr
    # The M2 wording was replaced by the richer M3 summary, which still says
    # plainly that completion and revocation are not verified.
    assert "not verified : handshake completion" in completed.stderr
    assert "revocation" in completed.stderr


@pytest.mark.integration
def test_analyze_never_emits_credentials(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    """A capture full of dummy credentials must produce a clean report."""
    fixture = fixtures["P_M_auth_before_tls"]
    output = tmp_path / "auth.json"
    completed = run_cli("analyze", str(fixture.path), "-o", str(output))
    assert completed.returncode == 0, completed.stderr

    everything = output.read_text() + completed.stdout + completed.stderr
    for secret in fixture.manifest["forbidden_strings"]:
        assert secret not in everything, f"{secret!r} leaked through the CLI"

    analysis = json.loads(output.read_text())["protocols"][0]
    observation = analysis["authentication"][0]
    assert observation["command_verb"] == "AUTH"
    assert observation["mechanism"] == "LOGIN"
    assert observation["occurred_before_tls_upgrade"] is True
    assert observation["continuation_exchanges"] == 2
    assert observation["credentials_recorded"] is False
    assert "auth attempts: 1 observed" in completed.stderr


@pytest.mark.integration
def test_analyze_reports_inconclusive_upgrade_honestly(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    output = tmp_path / "gap.json"
    completed = run_cli(
        "analyze", str(fixtures["P_K_gap_during_upgrade"].path), "-o", str(output), "--quiet"
    )
    assert completed.returncode == 0, completed.stderr
    analysis = json.loads(output.read_text())["protocols"][0]
    assert analysis["upgrade"]["state"] == "INCOMPLETE"
    assert analysis["parse_state"] == "INCOMPLETE"
    assert analysis["upgrade"].get("server_boundary") is None


@pytest.mark.integration
def test_no_protocol_events_flag_shrinks_the_report(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    fixture = fixtures["P_A_smtp_starttls_accepted"]
    full = tmp_path / "full.json"
    slim = tmp_path / "slim.json"
    assert run_cli("analyze", str(fixture.path), "-o", str(full), "--quiet").returncode == 0
    assert (
        run_cli(
            "analyze",
            str(fixture.path),
            "-o",
            str(slim),
            "--quiet",
            "--no-protocol-events",
        ).returncode
        == 0
    )
    full_data = json.loads(full.read_text())
    slim_data = json.loads(slim.read_text())
    assert full_data["protocols"][0]["events"]
    assert "events" not in slim_data["protocols"][0]
    # The conclusions survive the trimming.
    assert slim_data["protocols"][0]["upgrade"]["state"] == "TLS_BYTES_OBSERVED"
    assert slim_data["protocols"][0]["detection"]["status"] == "CONFIRMED"


@pytest.mark.integration
def test_status_reports_m2_stages() -> None:
    completed = run_cli("status")
    assert completed.returncode == 0
    status = json.loads(completed.stdout)
    assert status["EMAIL_PROTOCOL_PARSING"] == "IMPLEMENTED"
    assert status["STARTTLS_DETECTION"] == "IMPLEMENTED"
    assert status["TLS_RECORD_FRAMING"] == "IMPLEMENTED"
    assert status["TLS_ANALYSIS"] == "PARTIAL"
    # M4 turns certificate observations into judgements.
    assert status["CERTIFICATE_ASSESSMENT"] == "IMPLEMENTED"
    assert status["SECURITY_RULE_EVALUATION"] == "IMPLEMENTED"


# ---------------------------------------------------------------------------
# M3: TLS and certificate layer
# ---------------------------------------------------------------------------
@pytest.mark.integration
def test_analyze_reports_tls12_cryptographic_evidence(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    output = tmp_path / "tls12.json"
    completed = run_cli(
        "analyze", str(fixtures["T_A_tls12_complete_handshake"].path), "-o", str(output)
    )
    assert completed.returncode == 0, completed.stderr

    report = json.loads(output.read_text())
    assert report["tool"]["report_schema_version"] == "1.3.0"
    analysis = report["tls"][0]
    assert analysis["session_id"] == report["sessions"][0]["session_id"]
    assert analysis["version"]["selected_version"]["name"] == "TLS 1.2"
    assert (
        analysis["cipher_suite"]["selected"]["name"]
        == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    )
    assert analysis["cipher_suite"]["key_exchange"] == "ECDHE"
    assert analysis["key_exchange"]["method"] == "ECDHE"
    assert analysis["forward_secrecy"]["status"] == "EPHEMERAL_OBSERVED"
    assert analysis["forward_secrecy"]["handshake_completion_observable"] is False

    certificate = analysis["certificates"]["certificates"][0]
    assert certificate["subject"].startswith("CN=")
    assert certificate["public_key"]["algorithm"] == "EC"
    assert len(certificate["sha256_fingerprint"]) == 64
    assert certificate["packet_refs"]

    assert report["tls_inventory"]["tls12_count"] == 1
    assert report["tls_inventory"]["handshakes_cryptographically_verified"] == 0
    assert report["tls_inventory"]["revocation_checks_performed"] == 0
    assert "TLS: TLS 1.2" in completed.stderr


@pytest.mark.integration
def test_analyze_reports_tls13_limits_honestly(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    output = tmp_path / "tls13.json"
    completed = run_cli(
        "analyze", str(fixtures["T_D_tls13_negotiation"].path), "-o", str(output), "--quiet"
    )
    assert completed.returncode == 0, completed.stderr

    analysis = json.loads(output.read_text())["tls"][0]
    assert analysis["version"]["selected_version"]["name"] == "TLS 1.3"
    assert analysis["version"]["selected_source"] == "SUPPORTED_VERSIONS_EXTENSION"
    assert analysis["cipher_suite"]["decomposition_applicable"] is False
    assert "key_exchange" not in analysis["cipher_suite"]
    assert analysis["certificates"]["visibility"] == "ENCRYPTED_TLS13"
    assert "encrypted under handshake traffic keys" in (
        analysis["certificates"]["visibility_explanation"]
    )
    assert analysis["certificates"]["certificates"] == []


@pytest.mark.integration
def test_analyze_with_trust_store_and_identity(
    fixtures: dict[str, Fixture], tmp_path: Path, trust_store_pem: Path
) -> None:
    output = tmp_path / "validated.json"
    completed = run_cli(
        "analyze",
        str(fixtures["T_T_hostname_scenarios"].path),
        "-o",
        str(output),
        "--trust-store",
        str(trust_store_pem),
        "--expected-server-identity",
        "mail.example.invalid",
    )
    assert completed.returncode == 0, completed.stderr

    validation = json.loads(output.read_text())["tls"][0]["certificates"]["validation"]
    assert validation["certificate_observed"]["status"] == "PASSED"
    assert validation["validity_dates_checked"]["status"] == "PASSED"
    assert validation["chain_verified"]["status"] == "PASSED"
    assert validation["hostname_verified"]["status"] == "PASSED"
    assert validation["revocation_checked"]["status"] == "NOT_AVAILABLE"
    assert validation["trust_store"]["configured"] is True
    assert validation["reference_identity_source"] == "OPERATOR_SUPPLIED"
    assert "1 chain-verified" in completed.stderr
    assert "1 hostname-verified" in completed.stderr


@pytest.mark.integration
def test_no_tls_records_flag_trims_the_report(
    fixtures: dict[str, Fixture], tmp_path: Path
) -> None:
    full = tmp_path / "full.json"
    slim = tmp_path / "slim.json"
    fixture = fixtures["T_A_tls12_complete_handshake"]
    assert run_cli("analyze", str(fixture.path), "-o", str(full), "--quiet").returncode == 0
    assert (
        run_cli(
            "analyze", str(fixture.path), "-o", str(slim), "--quiet", "--no-tls-records"
        ).returncode
        == 0
    )
    assert json.loads(full.read_text())["tls"][0]["records"]
    slim_analysis = json.loads(slim.read_text())["tls"][0]
    assert "records" not in slim_analysis
    # The conclusions survive the trimming.
    assert slim_analysis["forward_secrecy"]["status"] == "EPHEMERAL_OBSERVED"
    assert slim_analysis["certificates"]["visibility"] == "OBSERVED"
