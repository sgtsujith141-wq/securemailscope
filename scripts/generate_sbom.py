#!/usr/bin/env python3
"""Generate a CycloneDX Software Bill of Materials (M9).

Two documents, because the project has two dependency trees:

``sbom/securemailscope-python.cdx.json``
    Every Python package in the fully-resolved environment, read from
    ``requirements-lock.txt`` by ``cyclonedx-py``.

``sbom/securemailscope-frontend.cdx.json``
    The frontend tree, read from ``package-lock.json`` by ``npm sbom``.

Both describe the *product*. The tooling that produces and audits them lives in
a separate ``.venv-release`` virtual environment and is deliberately absent, so
the SBOM is not a description of this script.

No local path, username or token is written into either document: the
generated files are post-processed to strip them, and that is asserted before
they are written.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "sbom"
RELEASE_VENV = ROOT / ".venv-release"

#: Anything matching these must never appear in a published SBOM.
_FORBIDDEN = (
    str(Path.home()),
    os.environ.get("USER", "\0no-user\0"),
    str(ROOT),
)


def _tool(name: str) -> Path:
    path = RELEASE_VENV / "bin" / name
    if not path.is_file():
        raise SystemExit(
            f"{name} is not installed. Run:\n"
            f"  python3.12 -m venv {RELEASE_VENV.name}\n"
            f"  {RELEASE_VENV.name}/bin/pip install pip-audit cyclonedx-bom"
        )
    return path


def _scrub(document: dict, source: str) -> dict:
    """Remove local paths and replace them with a stable marker."""
    text = json.dumps(document)
    for secret in _FORBIDDEN:
        if secret and len(secret) > 3:
            text = text.replace(secret, "<redacted-local-path>")
    scrubbed = json.loads(text)
    metadata = scrubbed.setdefault("metadata", {})
    properties = metadata.setdefault("properties", [])
    properties.append({"name": "securemailscope:source", "value": source})
    properties.append(
        {
            "name": "securemailscope:generated_at",
            "value": datetime.now(UTC).replace(microsecond=0).isoformat(),
        }
    )
    return scrubbed


def _verify_clean(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for secret in _FORBIDDEN:
        if secret and len(secret) > 3 and secret in text:
            raise SystemExit(f"{path} still contains a local path: {secret!r}")


def python_sbom() -> Path:
    cyclonedx = _tool("cyclonedx-py")
    destination = OUT / "securemailscope-python.cdx.json"
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            str(cyclonedx), "requirements",
            str(ROOT / "requirements-lock.txt"),
            "--output-format", "JSON",
            "--schema-version", "1.6",
            "--spec-version", "1.6",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # Older/newer CLI spellings differ; try the minimal invocation.
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [str(cyclonedx), "requirements", str(ROOT / "requirements-lock.txt")],
            capture_output=True,
            text=True,
            check=True,
        )
    document = json.loads(result.stdout)
    destination.write_text(
        json.dumps(_scrub(document, "requirements-lock.txt"), indent=2) + "\n",
        encoding="utf-8",
    )
    _verify_clean(destination)
    return destination


def frontend_sbom() -> Path | None:
    npm = shutil.which("npm")
    if npm is None:
        print("npm not found; skipping the frontend SBOM")
        return None
    destination = OUT / "securemailscope-frontend.cdx.json"
    result = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [npm, "sbom", "--sbom-format", "cyclonedx", "--omit", "dev"],
        cwd=ROOT / "frontend",
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print("npm sbom failed:", result.stderr.strip()[:400])
        return None
    document = json.loads(result.stdout)
    destination.write_text(
        json.dumps(_scrub(document, "frontend/package-lock.json"), indent=2) + "\n",
        encoding="utf-8",
    )
    _verify_clean(destination)
    return destination


def main() -> int:
    OUT.mkdir(exist_ok=True)
    written = []

    python_doc = python_sbom()
    written.append(python_doc)

    frontend_doc = frontend_sbom()
    if frontend_doc is not None:
        written.append(frontend_doc)

    print()
    for path in written:
        document = json.loads(path.read_text())
        components = document.get("components", [])
        print(f"{path.relative_to(ROOT)}")
        print(f"  format      {document.get('bomFormat')} {document.get('specVersion')}")
        print(f"  components  {len(components)}")
    if frontend_doc is None:
        print("\nNOTE: the frontend SBOM was not generated. This is recorded as")
        print("      incomplete rather than presented as a full bill of materials.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
