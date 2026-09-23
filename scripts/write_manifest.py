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


def main() -> int:
    targets = sorted(
        path
        for path in (ROOT / "submission").rglob("*")
        if path.is_file() and not EXCLUDE & set(path.parts)
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
    print(f"{len(rows)} files hashed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
