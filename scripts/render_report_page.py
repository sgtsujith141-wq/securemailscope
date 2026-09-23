#!/usr/bin/env python3
"""Rasterise the first page of an exported PDF report.

The submission deck shows the PDF itself, not a screenshot of a viewer, so the
image has to come from the file the product produced. There is no pure-Python
PDF rasteriser in this project's dependencies and adding one would grow the
release tooling for a single image, so this drives a renderer already present
on the machine and says plainly when none is.

Renderers tried, in order:

  * ``pdftoppm`` (poppler), if installed -- portable and exact;
  * ``qlmanage``, macOS only, which renders through Quartz.

Both produce a PNG of page one at the requested width. Neither is installed by
this project, and the script exits non-zero rather than writing a placeholder
if neither is available: a missing image is obvious, a fake one is not.

    python scripts/render_report_page.py local-evidence/report.pdf out.png
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _with_pdftoppm(pdf: Path, out: Path, width: int) -> bool:
    binary = shutil.which("pdftoppm")
    if binary is None:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        stem = Path(tmp) / "page"
        subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
            [binary, "-png", "-f", "1", "-l", "1", "-scale-to-x", str(width),
             "-scale-to-y", "-1", str(pdf), str(stem)],
            check=True,
        )
        produced = sorted(Path(tmp).glob("page*.png"))
        if not produced:
            return False
        out.write_bytes(produced[0].read_bytes())
    return True


def _with_qlmanage(pdf: Path, out: Path, width: int) -> bool:
    binary = shutil.which("qlmanage")
    if binary is None or sys.platform != "darwin":
        return False
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
            [binary, "-t", "-s", str(width), "-o", tmp, str(pdf)],
            check=True,
            capture_output=True,
        )
        produced = sorted(Path(tmp).glob("*.png"))
        if not produced:
            return False
        out.write_bytes(produced[0].read_bytes())
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pdf", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--width", type=int, default=1400)
    args = parser.parse_args()

    pdf = args.pdf if args.pdf.is_absolute() else ROOT / args.pdf
    out = args.out if args.out.is_absolute() else ROOT / args.out
    if not pdf.exists():
        print(f"no such PDF: {pdf}", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)

    def shown(path: Path) -> str:
        """Repository-relative where possible; absolute otherwise.

        `Path.relative_to` raises for a path outside the repository, and an
        output directory outside it is a perfectly ordinary thing to ask for.
        """
        try:
            return str(path.relative_to(ROOT))
        except ValueError:
            return str(path)

    for render in (_with_pdftoppm, _with_qlmanage):
        if render(pdf, out, args.width):
            print(f"{shown(out)}  <-  {shown(pdf)} page 1")
            return 0

    print(
        "no PDF renderer available. Install poppler (`brew install poppler`, "
        "`apt install poppler-utils`) and re-run. Nothing was written.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
