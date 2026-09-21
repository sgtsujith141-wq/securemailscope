#!/usr/bin/env python3
"""Run the SecureMailScope performance benchmark suite (M8 section 3).

Usage::

    python scripts/run_benchmarks.py                 # small, medium, large
    python scripts/run_benchmarks.py --profile all   # adds the stress profile
    python scripts/run_benchmarks.py --repeats 5

The stress profile is opt-in. It generates 24,000 packets and has been observed
to hold well over a gigabyte of resident memory, so it is never part of the
default run and never part of the test suite.

Captures are generated into a temporary directory and deleted afterwards; none
of them is written into the repository. Results land in ``benchmarks/results.json``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from securemailscope.benchmarks.corpus import PROFILES
from securemailscope.benchmarks.harness import (
    DEFAULT_REPEATS,
    run_suite,
    write_results,
)

DEFAULT_PROFILES = ("small", "medium", "large")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        default=",".join(DEFAULT_PROFILES),
        help="comma-separated profile names, or 'all' to include stress",
    )
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="skip report generation timing",
    )
    parser.add_argument(
        "--output", type=Path, default=Path("benchmarks/results.json")
    )
    args = parser.parse_args()

    if args.profile == "all":
        selected = PROFILES
    else:
        wanted = {name.strip() for name in args.profile.split(",") if name.strip()}
        unknown = wanted - {p.name for p in PROFILES}
        if unknown:
            parser.error(f"unknown profile(s): {', '.join(sorted(unknown))}")
        selected = tuple(p for p in PROFILES if p.name in wanted)

    record = run_suite(
        selected, repeats=args.repeats, with_reports=not args.no_reports
    )
    write_results(record, args.output)

    print("environment:")
    for key, value in record["environment"].items():
        print(f"  {key:12} {value}")
    print()
    header = (
        f"{'profile':8} {'packets':>8} {'bytes':>11} {'median s':>9} {'min':>7} "
        f"{'max':>7} {'pkt/s':>8} {'MB/s':>6} {'RSS MB':>8}  correct"
    )
    print(header)
    print("-" * len(header))
    for row in record["results"]:
        print(
            f"{row['profile']:8} {row['packets']:>8,} {row['capture_bytes']:>11,} "
            f"{row['seconds_median']:>9.3f} {row['seconds_min']:>7.3f} "
            f"{row['seconds_max']:>7.3f} {row['packets_per_second']:>8,.0f} "
            f"{row['bytes_per_second'] / 1e6:>6.2f} {row['peak_rss_mb']:>8.1f}  "
            f"{row['correct']}"
        )
    print()
    for row in record["results"]:
        print(f"{row['profile']}:")
        for stage in row["stages"]:
            flag = "  (within run-to-run noise)" if stage["within_noise"] else ""
            print(
                f"  {stage['name']:30} total {stage['seconds']:>8.3f}s  "
                f"added {stage['added_seconds']:>+8.3f}s{flag}"
            )
        sizes = ", ".join(f"{k} {v:,} B" for k, v in row["report_bytes"].items())
        print(f"  reports: {sizes or 'not generated'}")
        for note in row["notes"]:
            print(f"  NOTE: {note}")
        print()
    return 0 if all(row["correct"] for row in record["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
