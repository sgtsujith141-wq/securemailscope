#!/usr/bin/env python3
"""Write the dependency lock files (M9).

Two artefacts, with different jobs:

``requirements-lock.txt``
    Every package in the fully-resolved environment, pinned exactly. It makes
    two installs resolve to the same *versions*.

``requirements-lock-hashes.txt``
    The same set, each pin carrying the SHA-256 of every artefact PyPI will
    serve for it, in ``pip install --require-hashes`` form. This makes two
    installs resolve to the same *bytes*, so an index that served a different
    file under the same version would be refused rather than installed.

Writing hashes needs the network: every artefact is downloaded and hashed. The
plain lock file does not.
"""

from __future__ import annotations

import argparse
import hashlib
import platform
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTRAS = "dev,backend,reporting-tests,ml"
#: Never locked: the project installs itself in editable mode.
SELF = "securemailscope"


def _frozen() -> list[tuple[str, str]]:
    output = subprocess.run(  # noqa: S603 - fixed argv, this interpreter only
        [sys.executable, "-m", "pip", "list", "--format=freeze"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    pins = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "==" not in line or line.startswith("-e "):
            continue
        name, version = line.split("==", 1)
        if name.lower().replace("_", "-") == SELF:
            continue
        pins.append((name, version))
    return sorted(pins, key=lambda pair: pair[0].lower())


def _header(kind: str) -> str:
    pip_version = subprocess.run(  # noqa: S603 - fixed argv, this interpreter only
        [sys.executable, "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()[1]
    lines = [
        f"# {kind}",
        "#",
        f"# Generated from a venv built by 'pip install -e .[{EXTRAS}]'",
        f"# on {date.today().isoformat()} with Python {platform.python_version()} "
        f"and pip {pip_version}.",
        "#",
    ]
    return "\n".join(lines)


def write_plain(path: Path) -> int:
    pins = _frozen()
    body = "\n".join(f"{name}=={version}" for name, version in pins)
    path.write_text(
        _header(
            "Fully-resolved Python environment for SecureMailScope, including\n"
            "# transitive dependencies. Regenerate with: make lock"
        )
        + "\n# Versions are pinned exactly. For byte-level pinning see\n"
        "# requirements-lock-hashes.txt.\n#\n"
        + body
        + "\n",
        encoding="utf-8",
    )
    return len(pins)


def write_hashes(path: Path) -> int:
    """Download every pinned artefact and record its SHA-256."""
    pins = _frozen()
    entries: list[str] = []
    skipped: list[str] = []

    with tempfile.TemporaryDirectory() as directory:
        for name, version in pins:
            target = Path(directory) / f"{name}-{version}"
            target.mkdir(parents=True, exist_ok=True)
            # The name and version come from pip's own freeze output, not
            # from user input, and are passed as separate argv entries.
            result = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    sys.executable, "-m", "pip", "download",
                    f"{name}=={version}",
                    "--no-deps", "--dest", str(target),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            artefacts = sorted(p for p in target.iterdir() if p.is_file())
            if result.returncode != 0 or not artefacts:
                skipped.append(f"{name}=={version}")
                continue
            digests = [
                hashlib.sha256(artefact.read_bytes()).hexdigest()
                for artefact in artefacts
            ]
            joined = " \\\n".join(f"    --hash=sha256:{d}" for d in digests)
            entries.append(f"{name}=={version} \\\n{joined}")
            print(f"  {name}=={version}  ({len(digests)} artefact(s))", flush=True)

    note = ""
    if skipped:
        note = (
            "# NOT HASHED -- no artefact could be downloaded for these, so they\n"
            "# are absent from this file and `--require-hashes` would reject an\n"
            "# install that needs them:\n"
            + "".join(f"#   {item}\n" for item in skipped)
            + "#\n"
        )

    path.write_text(
        _header(
            "Hash-pinned Python requirements for SecureMailScope.\n"
            "# Regenerate with: make hashes  (requires network access)\n"
            "#\n"
            "# Install with:\n"
            "#   pip install --require-hashes -r requirements-lock-hashes.txt\n"
            "#\n"
            "# Every artefact PyPI serves for a pin is listed. An index serving\n"
            "# different bytes under the same version is refused, not installed."
        )
        + "\n"
        + note
        + "\n".join(entries)
        + "\n",
        encoding="utf-8",
    )
    if skipped:
        print(f"WARNING: {len(skipped)} package(s) could not be hashed: {skipped}")
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hashes",
        action="store_true",
        help="also write requirements-lock-hashes.txt (downloads every wheel)",
    )
    args = parser.parse_args()

    count = write_plain(ROOT / "requirements-lock.txt")
    print(f"requirements-lock.txt: {count} packages")

    if args.hashes:
        print("downloading artefacts to hash them...")
        hashed = write_hashes(ROOT / "requirements-lock-hashes.txt")
        print(f"requirements-lock-hashes.txt: {hashed} packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
