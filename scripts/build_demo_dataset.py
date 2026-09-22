#!/usr/bin/env python3
"""Build the reproducible demonstration dataset (M9 section 7).

Every capture here is produced by the project's own fixture generators -- the
same ones the test suite uses -- so nothing is crafted specially for the demo
and the analyzer has no idea it is being demonstrated. There is no demo mode,
no special-cased filename and no recorded output: the walkthrough runs the real
pipeline over these bytes and shows whatever it finds.

The captures are written to ``demo/captures/`` and are **gitignored**, exactly
like the test fixtures. What is committed is this script and
``demo/manifest.json``, which records for each capture what it is meant to
demonstrate and what the engine actually observed when the dataset was built.
Anyone can regenerate the identical set with::

    python scripts/build_demo_dataset.py

The dataset deliberately contains both a sound configuration and weak ones. A
weak configuration is a *configuration*, not an attack: nothing in this dataset
represents an intrusion, and the manifest says so for each entry.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securemailscope.config import AnalysisConfig
from securemailscope.intelligence import analyze_batch
from securemailscope.pipeline import analyze_capture
from securemailscope.testing.investigation_fixtures import (
    build_investigation_fixtures,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "generated"
DEMO = ROOT / "demo"
CAPTURES = DEMO / "captures"


@dataclass(frozen=True)
class DemoEntry:
    """One capture in the demonstration set."""

    order: int
    filename: str
    source: str
    demonstrates: str
    why_it_matters: str


#: Single-capture entries, copied from the generated test fixtures.
SINGLES: tuple[DemoEntry, ...] = (
    DemoEntry(
        1,
        "01-secure-baseline.pcap",
        "t_r_valid_trusted_chain.pcap",
        "A sound TLS configuration with a certificate that verifies against a "
        "supplied trust store.",
        "A posture tool that only ever reports problems is not measuring "
        "anything. This is the control: it shows what a clean result looks "
        "like, so a finding elsewhere means something.",
    ),
    DemoEntry(
        2,
        "02-weak-legacy-tls.pcap",
        "aa_tls10_static_rsa.pcap",
        "TLS 1.0 with static RSA key exchange: an obsolete protocol version "
        "and no forward secrecy, in one session.",
        "The central case. Several independent rules fail on the same "
        "session, each citing the packet it read the evidence from.",
    ),
    DemoEntry(
        3,
        "03-broken-cipher.pcap",
        "ac_rc4_weak_cipher.pcap",
        "A negotiated RC4 cipher suite.",
        "A prohibited primitive, distinct from an out-of-date protocol "
        "version. Shows the rules separating two different kinds of weakness.",
    ),
    DemoEntry(
        4,
        "04-starttls-upgrade.pcap",
        "p_a_smtp_starttls_accepted.pcap",
        "An SMTP session that advertises STARTTLS, requests it, and completes "
        "the upgrade.",
        "The email-specific path. Port numbers are never trusted: the "
        "protocol is identified from the dialogue, and the exact packet where "
        "plaintext stops is recorded.",
    ),
    DemoEntry(
        5,
        "05-starttls-refused.pcap",
        "p_b_smtp_starttls_rejected.pcap",
        "An SMTP session where STARTTLS is advertised, requested, and refused "
        "by the server.",
        "The interesting negative. The session stays in plaintext, and the "
        "tool must say the upgrade was attempted and failed rather than "
        "reporting that no upgrade was offered.",
    ),
    DemoEntry(
        6,
        "06-tls12-certificate.pcap",
        "t_a_tls12_complete_handshake.pcap",
        "A complete TLS 1.2 handshake whose certificate chain is visible on "
        "the wire.",
        "Certificate evidence: subject, issuer, validity dates, key size and "
        "signature algorithm, all read from bytes that were actually "
        "transmitted.",
    ),
    DemoEntry(
        7,
        "07-tls13-encrypted-certificate.pcap",
        "t_e_tls13_encrypted_certificate.pcap",
        "A TLS 1.3 handshake, where the Certificate message is encrypted.",
        "The honest limitation. TLS 1.3 encrypts the certificate, so no "
        "passive tool can read it. The report states NOT_AVAILABLE with the "
        "reason rather than leaving a blank or guessing.",
    ),
)

#: The multi-capture investigation, taken whole from an intelligence fixture.
DRIFT_GROUP = "B_version_downgrade"
DRIFT_PREFIX = "08-drift"


def _copy_singles() -> list[dict[str, Any]]:
    entries = []
    for entry in SINGLES:
        source = FIXTURES / entry.source
        if not source.is_file():
            raise SystemExit(
                f"{source} is missing. Run: python scripts/generate_fixtures.py"
            )
        destination = CAPTURES / entry.filename
        shutil.copyfile(source, destination)
        entries.append(
            {
                "order": entry.order,
                "file": entry.filename,
                "generated_from": entry.source,
                "generator": "securemailscope.testing (project fixture generator)",
                "demonstrates": entry.demonstrates,
                "why_it_matters": entry.why_it_matters,
                "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                "size_bytes": destination.stat().st_size,
            }
        )
    return entries


def _write_drift() -> list[dict[str, Any]]:
    fixtures = {item.name: item for item in build_investigation_fixtures()}
    if DRIFT_GROUP not in fixtures:
        raise SystemExit(f"investigation fixture {DRIFT_GROUP} is not available")
    fixture = fixtures[DRIFT_GROUP]

    entries = []
    for index, (name, payload) in enumerate(fixture.captures, start=1):
        filename = f"{DRIFT_PREFIX}-{index}-{name}"
        destination = CAPTURES / filename
        destination.write_bytes(payload)
        entries.append(
            {
                "order": 8,
                "file": filename,
                "generated_from": f"{DRIFT_GROUP}/{name}",
                "generator": fixture.generation,
                "demonstrates": (
                    "Part of a two-capture investigation of one endpoint, "
                    "an hour apart."
                ),
                "why_it_matters": (
                    "The client offers the same suites in both captures, and "
                    "the server selects TLS 1.2 and then TLS 1.0. Because the "
                    "offer did not change, the difference is attributable to "
                    "the server, and drift is reported as OBSERVED_CHANGE "
                    "rather than as a guess."
                ),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload),
            }
        )
    return entries


def _observe(entries: list[dict[str, Any]]) -> None:
    """Run the real pipeline over each capture and record what it found.

    These are observations, not expectations: the manifest reports what the
    engine produced on the day the dataset was built, so a reader can tell
    whether a later run still agrees.
    """
    config = AnalysisConfig()
    for entry in entries:
        path = CAPTURES / entry["file"]
        result = analyze_capture(path, config=config)
        assessment = result.assessment
        tls = result.tls[0] if result.tls else None
        entry["observed"] = {
            "sessions": len(result.sessions),
            "tls_sessions": len(result.tls),
            "findings": len(assessment.findings) if assessment else 0,
            "severities": sorted(
                {finding.severity.value for finding in assessment.findings}
            )
            if assessment
            else [],
            "posture_score": (
                assessment.posture_score.score if assessment else None
            ),
            "negotiated_version": (
                tls.version.selected_version.name
                if tls and tls.version.selected_version
                else None
            ),
            "negotiated_suite": (
                tls.cipher_suite.selected.name
                if tls and tls.cipher_suite.selected
                else None
            ),
            "score_status": (
                assessment.posture_score.status.value if assessment else None
            ),
            "certificate_visibility": (
                tls.certificates.visibility.value if tls else None
            ),
            "certificates_observed": (
                len(tls.certificates.certificates) if tls else 0
            ),
        }


def main() -> int:
    if CAPTURES.exists():
        shutil.rmtree(CAPTURES)
    CAPTURES.mkdir(parents=True)

    entries = _copy_singles() + _write_drift()
    print(f"wrote {len(entries)} capture(s) to {CAPTURES.relative_to(ROOT)}")

    print("running the real pipeline over each one...")
    _observe(entries)

    # The drift investigation, analysed as one batch.
    drift_paths = [CAPTURES / e["file"] for e in entries if e["file"].startswith(DRIFT_PREFIX)]
    outcome = analyze_batch(drift_paths, config=AnalysisConfig())
    investigation = outcome.investigation
    drift_summary = {
        "captures": [path.name for path in drift_paths],
        "server_entities": len(investigation.server_entities),
        "drift_observations": len(investigation.drift_events),
        "drift_statuses": sorted(
            {event.status.value for event in investigation.drift_events}
        ),
        "timeline_events": len(investigation.evidence_timeline),
        "correlations": len(investigation.session_correlations),
    }

    manifest = {
        "schema": "smsdemo/1",
        "purpose": (
            "A reproducible demonstration dataset for SecureMailScope. Every "
            "capture is synthetic and generated by the project's own fixture "
            "generators. No real mail traffic, from any person or "
            "organisation, is present."
        ),
        "regenerate_with": "python scripts/build_demo_dataset.py",
        "captures_are_gitignored": True,
        "no_special_casing": (
            "The analyzer has no demo mode and does not recognise these "
            "filenames. The observations below are the real pipeline's output."
        ),
        "not_attacks": (
            "A weak configuration is a configuration. Nothing in this dataset "
            "represents an intrusion, an exploit or attacker activity, and no "
            "finding here should be described as a detected attack."
        ),
        "captures": entries,
        "drift_investigation": drift_summary,
    }
    (DEMO / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"\n{'file':40} {'sess':>5} {'TLS':>4} {'find':>5} {'score':>6}  version")
    print("-" * 82)
    for entry in entries:
        o = entry["observed"]
        score = o["posture_score"]
        print(
            f"{entry['file']:40} {o['sessions']:>5} {o['tls_sessions']:>4} "
            f"{o['findings']:>5} {str(score) if score is not None else '-':>6}  "
            f"{o['negotiated_version'] or '-'}"
        )
    print(f"\ndrift investigation: {drift_summary['drift_observations']} observation(s), "
          f"statuses {drift_summary['drift_statuses']}")
    print(f"manifest: {(DEMO / 'manifest.json').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
