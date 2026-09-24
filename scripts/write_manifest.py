#!/usr/bin/env python3
"""Write the SHA-256 manifest of every submission artifact (M9 section 13)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: Generated crops are an input to the deck build, not an artifact.
EXCLUDE = {"crops"}
#: Files the operating system leaves behind. They are gitignored, so hashing
#: them would put entries in the manifest for files nobody receiving this
#: package would ever have.
EXCLUDE_NAMES = {".DS_Store", "Thumbs.db", "SHA256SUMS"}

#: The three files a judge actually receives. They get their own checksum
#: file in the format `sha256sum -c` reads, so the package can be verified
#: with one command and without this repository.
DELIVERABLES = (
    "SecureMailScope-SIH26159-Zero-Day.pptx",
    "SecureMailScope-SIH26159-Zero-Day.pdf",
    "SecureMailScope-SIH26159-Demo.mp4",
)


def main() -> int:
    targets = sorted(
        path
        for path in (ROOT / "submission").rglob("*")
        if path.is_file()
        and not EXCLUDE & set(path.parts)
        and path.name not in EXCLUDE_NAMES
    )
    rows = [
        {
            "path": str(path.relative_to(ROOT)),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in targets
    ]
    stamp = datetime.now(UTC).replace(microsecond=0).isoformat()

    lines = [
        "# Submission artifact manifest",
        "",
        "SHA-256 of every file in `submission/`. Regenerate with:",
        "",
        "    python scripts/write_manifest.py",
        "",
        f"Generated {stamp}",
        "",
        "| File | Bytes | SHA-256 |",
        "|---|---:|---|",
        *(f"| `{row['path']}` | {row['bytes']:,} | `{row['sha256']}` |" for row in rows),
        "",
        f"**{len(rows)} files.**",
        "",
    ]
    (ROOT / "submission/final/MANIFEST.md").write_text("\n".join(lines))
    (ROOT / "submission/final/manifest.json").write_text(
        json.dumps({"generated_at": stamp, "files": rows}, indent=2) + "\n"
    )
    final = ROOT / "submission" / "final"
    sums = []
    for name in DELIVERABLES:
        path = final / name
        if not path.is_file():
            raise SystemExit(f"missing deliverable: {path.relative_to(ROOT)}")
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}")
    (final / "SHA256SUMS").write_text("\n".join(sums) + "\n")

    print(f"{len(rows)} files hashed")
    for line in sums:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
