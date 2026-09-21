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
from typing import TextIO

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
        )
        if getattr(args, name, None) is not None
    }
    if args.trust_store is not None:
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
    indent = None if args.compact else 2

    if args.output is not None:
        path = write_json_report(
            result,
            args.output,
            indent=indent,
            include_segments=include_segments,
            include_protocol_events=include_events,
            include_tls_records=include_records,
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out, err = sys.stdout, sys.stderr

    try:
        if args.command == "analyze":
            return _run_analyze(args, out, err)
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
