"""Command line interface.

    securemailscope analyze capture.pcap --output result.json

Everything the CLI does is local and passive.  User-supplied paths are handled
as :class:`~pathlib.Path` values and are never interpolated into a shell
command; no subprocess is spawned anywhere in this package.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .config import AnalysisConfig
from .errors import InputError, SecureMailScopeError
from .models.analysis import STAGE_STATUS, AnalysisResult
from .models.tcp import SessionCompleteness
from .reporting.json_report import result_to_json, write_json_report

__all__ = ["main", "build_parser"]

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INPUT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securemailscope",
        description=(
            "Passive cryptographic security posture assessment for captured email "
            "traffic. Analysis is entirely local: no captured host is contacted and "
            "no capture data leaves this machine."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Implementation status of the analysis stages:\n  "
            + "\n  ".join(f"{name:<26} {status}" for name, status in STAGE_STATUS.items())
        ),
    )
    parser.add_argument("--version", action="version", version=f"securemailscope {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyse a pcap/pcapng file and emit a session inventory as JSON.",
        description=(
            "Reads a capture, reconstructs TCP sessions with full packet provenance "
            "and writes a JSON report. Application payload bytes are never included "
            "in the report."
        ),
    )
    analyze.add_argument("capture", type=Path, help="Path to a .pcap or .pcapng file.")
    analyze.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write the JSON report here instead of standard output.",
    )
    analyze.add_argument(
        "--compact", action="store_true", help="Emit single-line JSON instead of indented."
    )
    analyze.add_argument(
        "--no-segments",
        action="store_true",
        help="Omit per-packet segment provenance lists (smaller reports).",
    )
    analyze.add_argument(
        "--no-protocol-events",
        action="store_true",
        help="Omit per-line protocol event lists (smaller reports).",
    )
    analyze.add_argument(
        "--no-tls-records",
        action="store_true",
        help="Omit per-record TLS framing lists (smaller reports).",
    )
    analyze.add_argument(
        "--no-rule-results",
        action="store_true",
        help="Omit the per-session rule result lists, keeping findings and the score.",
    )

    assessment = analyze.add_argument_group(
        "security assessment",
        "Turns the forensic observations into judgements under a named, versioned "
        "policy. The observations themselves are reported unchanged either way.",
    )
    assessment.add_argument(
        "--no-ml",
        action="store_true",
        help="Skip the machine-learning layer. The forensic and assessment "
        "results are complete either way; this only removes the 'ml' block.",
    )
    assessment.add_argument(
        "--model-directory",
        type=Path,
        default=None,
        metavar="DIR",
        help="Load model artifacts from this directory instead of the packaged "
        "one. Artifacts are integrity-checked and version-checked either way.",
    )
    assessment.add_argument(
        "--no-assessment",
        action="store_true",
        help="Skip the assessment layer and report forensic observations only.",
    )
    assessment.add_argument(
        "--policy-reference-time",
        choices=("capture", "current"),
        default="capture",
        help="Which clock the rules judge certificate validity against. 'capture' "
        "(default) asks whether the certificate was valid when the traffic was "
        "recorded, which is the forensic question. 'current' asks whether it is "
        "valid now. The mode is recorded in the policy block. Distinct from "
        "--assess-current-time, which adds a second validity report without "
        "changing what the rules conclude.",
    )
    assessment.add_argument(
        "--disable-rules",
        default=None,
        metavar="IDS",
        help="Comma-separated rule ids to disable, e.g. TLS-PROTO-002,MAIL-004. "
        "Recorded as a policy override in the report.",
    )
    assessment.add_argument(
        "--minimum-score-coverage",
        type=int,
        default=None,
        metavar="PERCENT",
        help="Weighted coverage below which no numeric score is reported "
        "(default 50). Below it the engine reports SCORE_UNAVAILABLE.",
    )

    tls = analyze.add_argument_group(
        "TLS and certificate analysis",
        "Certificate validation is off unless you supply the inputs it needs: there is "
        "no default trust store and no default expected identity.",
    )
    tls.add_argument(
        "--trust-store",
        type=Path,
        default=None,
        metavar="PEM",
        help="PEM file of trust anchors for chain verification. Without it, chain "
        "verification reports NOT_AVAILABLE rather than using a store it cannot name.",
    )
    tls.add_argument(
        "--expected-server-identity",
        default=None,
        metavar="NAME",
        help="The server identity you expect the certificate to name. Without it, "
        "hostname verification reports NOT_AVAILABLE; the destination IP is never used.",
    )
    tls.add_argument(
        "--trust-observed-sni",
        action="store_true",
        help="Use the SNI observed in the ClientHello as the expected identity. Opt-in: "
        "SNI is what the client asked for, not an authorised expectation.",
    )
    tls.add_argument(
        "--assess-current-time",
        action="store_true",
        help="Also report certificate validity against the clock at analysis time, "
        "alongside the capture-time assessment.",
    )
    analyze.add_argument(
        "--quiet", action="store_true", help="Suppress the human-readable summary on stderr."
    )

    limits = analyze.add_argument_group(
        "resource limits", "Override the documented defaults; all values are hard ceilings."
    )
    limits.add_argument("--max-capture-bytes", type=int, default=None)
    limits.add_argument("--max-packets", type=int, default=None)
    limits.add_argument("--max-packet-bytes", type=int, default=None)
    limits.add_argument("--max-total-payload-bytes", type=int, default=None)
    limits.add_argument("--max-session-payload-bytes", type=int, default=None)
    limits.add_argument("--max-concurrent-sessions", type=int, default=None)
    limits.add_argument("--max-total-sessions", type=int, default=None)
    limits.add_argument("--max-segments-per-direction", type=int, default=None)
    limits.add_argument("--max-line-bytes", type=int, default=None)
    limits.add_argument("--max-literal-bytes", type=int, default=None)
    limits.add_argument("--max-message-body-bytes", type=int, default=None)

    batch = subparsers.add_parser(
        "analyze-batch",
        help="Analyse several captures together and correlate the evidence.",
        description=(
            "Runs the ordinary single-capture pipeline over each capture, then "
            "correlates the results: cryptographic fingerprints, server "
            "entities, drift between captures, cross-session correlations, an "
            "evidence timeline and blast radius. Every individual capture "
            "report is carried through unchanged. Captures are identified by "
            "content hash, so the same file supplied twice is analysed once."
        ),
    )
    batch.add_argument("captures", nargs="+", type=Path, help="Capture files to analyse.")
    batch.add_argument(
        "-o", "--output", type=Path, default=None, help="Write the investigation JSON here."
    )
    batch.add_argument("--compact", action="store_true", help="Write JSON without indentation.")
    batch.add_argument(
        "--no-capture-reports",
        action="store_true",
        help="Emit only the investigation, omitting the per-capture forensic reports. "
        "The reports are complete when included; this only shrinks the file.",
    )
    batch.add_argument("--no-segments", action="store_true")
    batch.add_argument("--no-protocol-events", action="store_true")
    batch.add_argument("--no-tls-records", action="store_true")
    batch.add_argument("--no-rule-results", action="store_true")
    batch.add_argument(
        "--with-segments",
        action="store_true",
        help="Include per-segment provenance in the embedded capture reports.",
    )
    batch.add_argument(
        "--max-batch-captures",
        type=int,
        default=None,
        metavar="N",
        help="Maximum captures to analyse. Exceeding it warns explicitly.",
    )
    batch.add_argument(
        "--max-timeline-events",
        type=int,
        default=None,
        metavar="N",
        help="Maximum timeline events to report. Truncation warns explicitly.",
    )
    batch.add_argument(
        "--max-batch-correlations", type=int, default=None, metavar="N"
    )
    batch.add_argument("--trust-store", type=Path, default=None)
    batch.add_argument("--expected-server-identity", default=None)
    batch.add_argument("--no-assessment", action="store_true")
    batch.add_argument("--no-ml", action="store_true")
    batch.add_argument(
        "--quiet", action="store_true", help="Suppress the human-readable summary on stderr."
    )

    fixtures = subparsers.add_parser(
        "fixtures",
        help="Regenerate the deterministic synthetic test captures and manifests.",
        description=(
            "Generates the synthetic captures used by the test suite. Output is "
            "byte-identical on every run; no network access is involved."
        ),
    )
    fixtures.add_argument(
        "--capture-dir",
        type=Path,
        default=Path("tests/fixtures/generated"),
        help="Where to write the generated capture files (gitignored).",
    )
    fixtures.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path("tests/fixtures/manifests"),
        help="Where to write the expectation manifests (committed).",
    )

    subparsers.add_parser(
        "status", help="Print the implementation status of each analysis stage."
    )
    return parser


def _config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    """Environment first, then explicit command line overrides."""
    base = AnalysisConfig.from_env()
    overrides = {
        name: getattr(args, name)
        for name in (
            "max_capture_bytes",
            "max_packets",
            "max_packet_bytes",
            "max_total_payload_bytes",
            "max_session_payload_bytes",
            "max_concurrent_sessions",
            "max_total_sessions",
            "max_segments_per_direction",
            "max_line_bytes",
            "max_literal_bytes",
            "max_message_body_bytes",
            "max_batch_captures",
            "max_batch_correlations",
            "max_timeline_events",
        )
        if getattr(args, name, None) is not None
    }
    if getattr(args, "no_assessment", False):
        overrides["assess_security"] = False
    if getattr(args, "no_ml", False):
        overrides["enable_ml"] = False
    if getattr(args, "model_directory", None) is not None:
        overrides["model_directory"] = str(args.model_directory)
    if getattr(args, "policy_reference_time", "capture") == "current":
        overrides["assess_at_current_time"] = True
    if getattr(args, "disable_rules", None):
        overrides["disabled_rules"] = args.disable_rules
    if getattr(args, "minimum_score_coverage", None) is not None:
        overrides["minimum_score_coverage_percent"] = args.minimum_score_coverage
    if getattr(args, "trust_store", None) is not None:
        overrides["trust_store_path"] = str(args.trust_store)
    if getattr(args, "expected_server_identity", None):
        overrides["expected_server_identity"] = args.expected_server_identity
    if getattr(args, "trust_observed_sni", False):
        overrides["trust_observed_sni_as_identity"] = True
    if getattr(args, "assess_current_time", False):
        overrides["assess_certificates_at_current_time"] = True
    if not overrides:
        return base
    from dataclasses import replace

    return replace(base, **overrides)


def _summarise(result: AnalysisResult, stream: TextIO) -> None:
    capture = result.capture
    inventory = result.inventory
    print(f"capture      : {capture.source_name}", file=stream)
    print(f"capture id   : {capture.capture_id}", file=stream)
    print(
        f"format       : {capture.file_format.value}"
        + (f" ({capture.byte_order}-endian)" if capture.byte_order else ""),
        file=stream,
    )
    print(
        f"packets      : {capture.packet_count} "
        f"({capture.tcp_packet_count} TCP, {capture.non_ip_packet_count} non-IP, "
        f"{capture.non_tcp_packet_count} non-TCP, {capture.malformed_packet_count} malformed)",
        file=stream,
    )
    if capture.first_packet_timestamp and capture.last_packet_timestamp:
        print(
            f"time range   : {capture.first_packet_timestamp.isoformat()} .. "
            f"{capture.last_packet_timestamp.isoformat()}",
            file=stream,
        )
    print(
        f"sessions     : {inventory.session_count} "
        f"(complete {inventory.complete_session_count}, "
        f"partial {inventory.partial_session_count}, "
        f"midstream {inventory.midstream_session_count}, "
        f"truncated {inventory.truncated_session_count})",
        file=stream,
    )
    print(
        f"reconstructed: {inventory.total_bytes_reconstructed} bytes, "
        f"{inventory.total_gap_count} gap(s), "
        f"{inventory.total_overlap_conflict_count} overlap conflict(s)",
        file=stream,
    )
    if capture.truncated:
        print("NOTE         : capture parsing stopped early; results are incomplete.", file=stream)

    protocols = {analysis.session_id: analysis for analysis in result.protocols}
    inventory_p = result.protocol_inventory
    print(
        f"protocols    : SMTP {inventory_p.confirmed_smtp_count} confirmed, "
        f"IMAP {inventory_p.confirmed_imap_count} confirmed, "
        f"POP3 {inventory_p.confirmed_pop3_count} confirmed, "
        f"{inventory_p.probable_count} probable, "
        f"{inventory_p.port_hint_only_count} port-hint only, "
        f"{inventory_p.unknown_count} unknown",
        file=stream,
    )
    print(
        f"tls upgrades : {inventory_p.upgrade_advertised_count} advertised, "
        f"{inventory_p.upgrade_requested_count} requested, "
        f"{inventory_p.upgrade_accepted_count} accepted, "
        f"{inventory_p.upgrade_rejected_count} rejected, "
        f"{inventory_p.upgrade_incomplete_count} inconclusive; "
        f"{inventory_p.tls_bytes_observed_count} with TLS bytes observed",
        file=stream,
    )
    if inventory_p.implicit_tls_session_count:
        print(
            f"implicit tls : {inventory_p.implicit_tls_session_count} session(s) TLS-framed "
            "from the first byte (inner protocol not determinable)",
            file=stream,
        )
    if inventory_p.authentication_observation_count:
        print(
            f"auth attempts: {inventory_p.authentication_observation_count} observed, "
            f"{inventory_p.authentication_before_upgrade_count} with no accepted TLS "
            "upgrade in effect (no credential material recorded)",
            file=stream,
        )
    tls_by_session = {analysis.session_id: analysis for analysis in result.tls}
    tls_inv = result.tls_inventory
    if tls_inv.tls_session_count:
        print(
            f"tls sessions : {tls_inv.tls_session_count} "
            f"({tls_inv.implicit_tls_count} implicit, "
            f"{tls_inv.starttls_upgrade_count} via STARTTLS); "
            f"TLS 1.3 {tls_inv.tls13_count}, TLS 1.2 {tls_inv.tls12_count}, "
            f"legacy {tls_inv.legacy_version_count}",
            file=stream,
        )
        print(
            f"certificates : {tls_inv.certificates_observed_count} observed, "
            f"{tls_inv.certificates_encrypted_count} encrypted under TLS 1.3; "
            f"{tls_inv.chain_verified_count} chain-verified, "
            f"{tls_inv.hostname_verified_count} hostname-verified",
            file=stream,
        )
        print(
            f"forward sec. : {tls_inv.forward_secret_count} with an ephemeral exchange, "
            f"{tls_inv.static_rsa_count} with static RSA",
            file=stream,
        )
        print(
            "not verified : handshake completion (needs key material) and revocation "
            "(no OCSP/CRL fetching by design)",
            file=stream,
        )
    else:
        print("tls sessions : none observed", file=stream)

    for session in result.sessions:
        analysis = protocols.get(session.session_id)
        marker = "" if session.completeness is SessionCompleteness.COMPLETE else " *"
        if analysis is not None:
            label = f"{analysis.detection.protocol.value}/{analysis.detection.status.value}"
        else:  # pragma: no cover - every session gets an analysis
            label = "no protocol analysis"
        print(
            f"  {session.session_id}  {session.flow.client} -> {session.flow.server}  "
            f"{session.completeness.value}{marker}  "
            f"c2s={session.client_to_server.bytes_reconstructed}B "
            f"s2c={session.server_to_client.bytes_reconstructed}B  [{label}]",
            file=stream,
        )
        tls_analysis = tls_by_session.get(session.session_id)
        if tls_analysis is not None:
            version = tls_analysis.version.selected_version
            version_label = version.name or version.hex_value if version else "UNKNOWN"
            suite = tls_analysis.cipher_suite.selected
            suite_label = (suite.name or suite.hex_value) if suite else "no suite selected"
            print(
                f"      TLS: {version_label}  {suite_label}  "
                f"kx={tls_analysis.key_exchange.method}  "
                f"fs={tls_analysis.forward_secrecy.status.value}  "
                f"cert={tls_analysis.certificates.visibility.value}",
                file=stream,
            )
        if analysis is not None and analysis.upgrade is not None:
            upgrade = analysis.upgrade
            boundaries = []
            if upgrade.client_boundary is not None:
                boundaries.append(
                    f"client@{upgrade.client_boundary.stream_offset}"
                    f"({upgrade.client_boundary.basis})"
                )
            if upgrade.server_boundary is not None:
                boundaries.append(
                    f"server@{upgrade.server_boundary.stream_offset}"
                    f"({upgrade.server_boundary.basis})"
                )
            suffix = ("  boundaries " + ", ".join(boundaries)) if boundaries else ""
            print(
                f"      {upgrade.mechanism.value}: {upgrade.state.value}{suffix}",
                file=stream,
            )

    assessment = result.assessment
    if assessment is not None:
        score = assessment.posture_score
        print(
            f"policy       : {assessment.policy.policy_id} "
            f"v{assessment.policy.policy_version} "
            f"({assessment.policy.assessment_mode.value} mode)"
            + (
                f"  overrides: {', '.join(assessment.policy.overrides_applied)}"
                if assessment.policy.overrides_applied
                else ""
            ),
            file=stream,
        )
        tally = assessment.tally
        print(
            f"controls     : {tally.evaluated} evaluated of {tally.total_applicable} "
            f"applicable ({tally.passed} passed, {tally.failed} failed, "
            f"{tally.unknown} unknown); coverage "
            f"{assessment.coverage.coverage_ratio:.0%}",
            file=stream,
        )
        if score.status.value == "AVAILABLE":
            print(
                f"posture score: {score.score}/100 ({score.band.value}) -- a "
                "project-defined metric over the analysed evidence only",
                file=stream,
            )
        else:
            print(
                f"posture score: SCORE_UNAVAILABLE -- {score.explanation}",
                file=stream,
            )
        if assessment.findings:
            print(f"findings     : {len(assessment.findings)}", file=stream)
            for entry in assessment.prioritised_findings:
                print(
                    f"  {entry.priority.value}  {entry.rule_id:15s} "
                    f"{entry.severity.value:8s} {entry.confidence.value:10s} "
                    f"x{entry.observed_session_count}",
                    file=stream,
                )
        else:
            print("findings     : none", file=stream)
        if assessment.remediations:
            print(
                "remediations : "
                + ", ".join(item.remediation_id for item in assessment.remediations),
                file=stream,
            )

    ml = result.ml
    if ml is not None:
        if ml.ml_status.value != "COMPLETED":
            print(f"ml           : {ml.ml_status.value}", file=stream)
            for warning in ml.ml_warnings:
                print(f"               {warning.code}: {warning.message}", file=stream)
        else:
            anomalous = [
                item for item in ml.anomaly_results if item.status.value == "ANOMALOUS"
            ]
            skipped = [
                item
                for item in ml.anomaly_results
                if item.status.value == "NOT_EVALUABLE"
            ]
            model = ml.anomaly_model
            print(
                "ml           : "
                + (
                    f"{len(anomalous)} session(s) unusual against the model's "
                    f"reference population"
                    if anomalous
                    else "no session unusual against the model's reference population"
                )
                + (f"; {len(skipped)} not evaluable" if skipped else ""),
                file=stream,
            )
            if model is not None:
                print(
                    f"               model {model.model_id} {model.model_version} "
                    f"({model.algorithm}), trained on "
                    f"{model.training_sample_count} synthetic sessions",
                    file=stream,
                )
            for item in anomalous[:3]:
                print(
                    f"               unusual: session {item.session_id} "
                    f"(seen in {item.raw_score:.1%} of the reference population)",
                    file=stream,
                )
            print(
                "               ML inferences, not observations. They change no "
                "finding or score above.",
                file=stream,
            )

    total_warnings = (
        len(result.warnings)
        + sum(len(s.warnings) for s in result.sessions)
        + sum(len(a.warnings) for a in result.protocols)
        + sum(len(a.warnings) for a in result.tls)
    )
    if total_warnings:
        print(f"warnings     : {total_warnings} (see the JSON report)", file=stream)


def _run_analyze(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from .pipeline import analyze_capture

    config = _config_from_args(args)
    result = analyze_capture(args.capture, config=config)
    include_segments = not args.no_segments
    include_events = not args.no_protocol_events
    include_records = not args.no_tls_records
    include_rule_results = not args.no_rule_results
    indent = None if args.compact else 2

    if args.output is not None:
        path = write_json_report(
            result,
            args.output,
            indent=indent,
            include_segments=include_segments,
            include_protocol_events=include_events,
            include_tls_records=include_records,
            include_rule_results=include_rule_results,
        )
        if not args.quiet:
            print(f"report       : {path}", file=err)
    else:
        print(
            result_to_json(
                result,
                indent=indent,
                include_segments=include_segments,
                include_protocol_events=include_events,
                include_tls_records=include_records,
                include_rule_results=include_rule_results,
            ),
            file=out,
        )
    if not args.quiet:
        _summarise(result, err)
    return EXIT_OK


def _run_fixtures(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    from .testing.fixtures import write_fixtures

    specs = write_fixtures(args.capture_dir, args.manifest_dir)
    for spec in specs:
        print(f"{spec.name:28s} {spec.filename:32s} sha256:{spec.sha256}", file=out)
    print(
        f"{len(specs)} fixture(s) written to {args.capture_dir} "
        f"with manifests in {args.manifest_dir}",
        file=err,
    )
    print(
        f"synthetic trust anchor: {args.capture_dir / 'synthetic-root.pem'} "
        "(public certificate only; pass it to --trust-store to demonstrate "
        "chain verification)",
        file=err,
    )
    return EXIT_OK


def _run_status(out: TextIO) -> int:
    print(json.dumps(STAGE_STATUS, indent=2), file=out)
    return EXIT_OK


def _run_analyze_batch(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    """Analyse several captures together and report the correlated evidence."""
    from .intelligence import analyze_batch
    from .reporting.json_report import investigation_to_dict, write_investigation_report

    config = _config_from_args(args)
    outcome = analyze_batch(list(args.captures), config=config)
    investigation = outcome.investigation
    indent = None if args.compact else 2
    include_captures = not args.no_capture_reports

    if args.output is not None:
        path = write_investigation_report(
            outcome,
            args.output,
            indent=indent,
            include_captures=include_captures,
            include_segments=args.with_segments,
            include_protocol_events=not args.no_protocol_events,
            include_tls_records=not args.no_tls_records,
            include_rule_results=not args.no_rule_results,
        )
        if not args.quiet:
            print(f"investigation written to {path}", file=err)
    else:
        document = investigation_to_dict(
            outcome,
            include_captures=include_captures,
            include_segments=args.with_segments,
            include_protocol_events=not args.no_protocol_events,
            include_tls_records=not args.no_tls_records,
            include_rule_results=not args.no_rule_results,
        )
        print(json.dumps(document, indent=indent), file=out)

    if not args.quiet:
        _print_investigation_summary(investigation, err)
    return EXIT_OK


def _print_investigation_summary(investigation: Any, err: TextIO) -> None:
    """A short, honest summary. Every count names what it counted."""
    analysed = [
        record
        for record in investigation.capture_inventory
        if record.status.value == "ANALYZED"
    ]
    duplicates = [
        record
        for record in investigation.capture_inventory
        if record.status.value == "DUPLICATE"
    ]
    failed = [
        record
        for record in investigation.capture_inventory
        if record.status.value == "FAILED"
    ]

    print(f"investigation  {investigation.investigation_id}", file=err)
    print(
        f"captures       {len(analysed)} analysed"
        + (f", {len(duplicates)} duplicate" if duplicates else "")
        + (f", {len(failed)} failed" if failed else ""),
        file=err,
    )
    for record in failed:
        print(f"  FAILED       {record.source_name}: {record.failure_reason}", file=err)
    for record in duplicates:
        print(
            f"  duplicate    {record.source_name} (same bytes as "
            f"{record.duplicate_of_source}); counted once",
            file=err,
        )

    print(
        f"endpoints      {len(investigation.server_entities)} observed "
        "(ip, port); never merged on a shared certificate, key or name",
        file=err,
    )
    complete = sum(
        1
        for item in investigation.cryptographic_fingerprints
        if item.completeness.value == "COMPLETE"
    )
    print(
        f"fingerprints   {len(investigation.cryptographic_fingerprints)} "
        f"({complete} complete, "
        f"{len(investigation.cryptographic_fingerprints) - complete} partial or "
        "insufficient)",
        file=err,
    )

    by_status: dict[str, int] = {}
    for event in investigation.drift_events:
        by_status[event.status.value] = by_status.get(event.status.value, 0) + 1
    if by_status:
        print(
            "drift          "
            + ", ".join(f"{count} {status}" for status, count in sorted(by_status.items())),
            file=err,
        )
    for event in investigation.drift_events:
        if event.status.value == "OBSERVED_CHANGE":
            print(f"  change       {event.kind.value} on {event.entity_id}", file=err)

    print(f"correlations   {len(investigation.session_correlations)}", file=err)
    print(f"timeline       {len(investigation.evidence_timeline)} events", file=err)
    for radius in investigation.blast_radius[:5]:
        print(
            f"  {radius.subject:<16} {radius.session_count} session(s) across "
            f"{radius.entity_count} endpoint(s), {radius.capture_count} capture(s)",
            file=err,
        )
    if len(investigation.blast_radius) > 5:
        print(f"  ... {len(investigation.blast_radius) - 5} more", file=err)
    print(f"scope          {investigation.scope_statement}", file=err)
    for warning in investigation.intelligence_warnings:
        print(f"warning        {warning.code}: {warning.message}", file=err)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out, err = sys.stdout, sys.stderr

    try:
        if args.command == "analyze":
            return _run_analyze(args, out, err)
        if args.command == "analyze-batch":
            return _run_analyze_batch(args, out, err)
        if args.command == "fixtures":
            return _run_fixtures(args, out, err)
        if args.command == "status":
            return _run_status(out)
    except InputError as exc:
        print(f"securemailscope: input error: {exc}", file=err)
        return EXIT_INPUT_ERROR
    except SecureMailScopeError as exc:
        print(f"securemailscope: {exc}", file=err)
        return EXIT_ERROR
    except OSError as exc:
        print(f"securemailscope: file system error: {exc}", file=err)
        return EXIT_INPUT_ERROR

    parser.error(f"unknown command {args.command!r}")
    return EXIT_ERROR  # pragma: no cover - argparse exits first


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
