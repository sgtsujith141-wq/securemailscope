#!/usr/bin/env python3
"""Regenerate the synthetic test captures and their expectation manifests.

    python scripts/generate_fixtures.py

Captures land in ``tests/fixtures/generated/`` (gitignored) and manifests in
``tests/fixtures/manifests/`` (committed).  Generation is byte-deterministic
and involves no network access whatsoever.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

from securemailscope.testing.fixtures import write_fixtures  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--capture-dir", type=Path, default=REPO_ROOT / "tests" / "fixtures" / "generated"
    )
    parser.add_argument(
        "--manifest-dir", type=Path, default=REPO_ROOT / "tests" / "fixtures" / "manifests"
    )
    args = parser.parse_args(argv)

    specs = write_fixtures(args.capture_dir, args.manifest_dir)
    width = max(len(spec.name) for spec in specs)
    for spec in specs:
        print(f"{spec.name:<{width}}  {len(spec.data):>6} B  sha256:{spec.sha256}")
    print(f"\n{len(specs)} fixtures -> {args.capture_dir}")
    print(f"{len(specs)} manifests -> {args.manifest_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
