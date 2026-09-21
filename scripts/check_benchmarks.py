#!/usr/bin/env python3
"""Judge benchmark results against the committed acceptance thresholds (M8 section 16).

The thresholds live in ``benchmarks/thresholds.json`` and were committed before
the results they judge. This script only compares; it never adjusts a threshold
to obtain a pass, and it exits non-zero when a gated threshold fails.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _by_profile(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["profile"]: row for row in record["results"]}


def _scaling_exponent(a: dict[str, Any], b: dict[str, Any]) -> float:
    """Fit time ~ packets**k through two measured points."""
    packet_ratio = b["packets"] / a["packets"]
    time_ratio = b["seconds_median"] / a["seconds_median"]
    return math.log(time_ratio) / math.log(packet_ratio)


def _growth_kb_per_packet(a: dict[str, Any], b: dict[str, Any]) -> float:
    delta_mb = b["peak_rss_mb"] - a["peak_rss_mb"]
    delta_packets = b["packets"] - a["packets"]
    return (delta_mb * 1024) / delta_packets


def _verdict(
    spec: dict[str, Any],
    profile: str,
    observed: float | bool | None,
    excluded: set[str],
) -> dict[str, Any]:
    base = {
        "id": spec["id"],
        "profile": profile,
        "metric": spec["metric"],
        "observed": observed,
        "threshold": spec["value"],
        "operator": spec["operator"],
        "gated": profile not in excluded,
    }
    if observed is None:
        return {**base, "status": "NOT_MEASURED"}
    operator, limit = spec["operator"], spec["value"]
    if operator == ">=":
        ok = observed >= limit
    elif operator == "<=":
        ok = observed <= limit
    elif operator == "==":
        ok = observed == limit
    else:  # pragma: no cover - guarded by the schema
        raise ValueError(f"unknown operator {operator!r}")
    return {**base, "status": "PASS" if ok else "FAIL"}


def _observe(
    spec: dict[str, Any], profile: str, rows: dict[str, dict[str, Any]]
) -> float | bool | None:
    metric = spec["metric"]
    row = rows.get(profile)
    if row is None:
        return None
    if metric in ("packets_per_second", "peak_rss_mb", "correct"):
        return row[metric]
    if metric == "max_report_bytes":
        sizes = row.get("report_bytes") or {}
        return max(sizes.values()) if sizes else None
    if metric == "max_over_min_ratio":
        if not row["seconds_min"]:
            return None
        return round(row["seconds_max"] / row["seconds_min"], 3)
    raise ValueError(f"unknown per-profile metric {metric!r}")  # pragma: no cover


PAIRWISE = {"time_scaling_exponent", "rss_growth_kb_per_packet"}


def evaluate(record: dict[str, Any], thresholds: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _by_profile(record)
    excluded = set(thresholds.get("excluded_from_pass_fail", {}))
    verdicts: list[dict[str, Any]] = []

    for spec in thresholds["thresholds"]:
        if spec["metric"] in PAIRWISE:
            pair = [rows.get(name) for name in spec["applies_to"]]
            label = "->".join(spec["applies_to"])
            if len(pair) != 2 or any(row is None for row in pair):
                verdicts.append(_verdict(spec, label, None, excluded))
                continue
            first, second = pair
            assert first is not None and second is not None
            value = (
                _scaling_exponent(first, second)
                if spec["metric"] == "time_scaling_exponent"
                else _growth_kb_per_packet(first, second)
            )
            verdicts.append(_verdict(spec, label, round(value, 3), excluded))
            continue
        for profile in spec["applies_to"]:
            verdicts.append(
                _verdict(spec, profile, _observe(spec, profile, rows), excluded)
            )
    return verdicts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=ROOT / "benchmarks/results.json")
    parser.add_argument(
        "--thresholds", type=Path, default=ROOT / "benchmarks/thresholds.json"
    )
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/verdicts.json")
    args = parser.parse_args()

    record = json.loads(args.results.read_text())
    thresholds = json.loads(args.thresholds.read_text())
    verdicts = evaluate(record, thresholds)

    args.output.write_text(
        json.dumps(
            {
                "thresholds_defined_on": thresholds["defined_on"],
                "results_generated_at": record.get("generated_at"),
                "environment": record["environment"],
                "verdicts": verdicts,
            },
            indent=2,
        )
        + "\n"
    )

    width = max(len(str(v["profile"])) for v in verdicts)
    print(f"{'id':4} {'profile':{width}} {'metric':26} {'observed':>12} "
          f"{'':2} {'threshold':>10}  status")
    print("-" * (width + 70))
    for verdict in verdicts:
        observed = verdict["observed"]
        shown = "n/a" if observed is None else (
            str(observed) if isinstance(observed, bool) else f"{observed:,.3f}"
        )
        flag = "" if verdict["gated"] else "  (not gated)"
        print(
            f"{verdict['id']:4} {verdict['profile']:{width}} {verdict['metric']:26} "
            f"{shown:>12} {verdict['operator']:2} {verdict['threshold']!s:>10}  "
            f"{verdict['status']}{flag}"
        )

    failed = [v for v in verdicts if v["gated"] and v["status"] != "PASS"]
    print()
    if failed:
        print(f"{len(failed)} gated threshold(s) not met:")
        for verdict in failed:
            print(f"  {verdict['id']} on {verdict['profile']}: {verdict['status']}")
        return 1
    print("all gated thresholds met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
