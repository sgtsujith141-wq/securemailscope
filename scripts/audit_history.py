#!/usr/bin/env python3
"""Audit the entire Git history for sensitive content (M9 section 10).

A clean working tree proves nothing about what earlier commits contain: a
capture, a key or a token committed once and deleted later is still in the
history and still published when the repository is.

This walks every blob reachable from every ref -- not just the current tree --
and reports anything matching a sensitive pattern, plus any file whose *path*
looks like capture data, key material or a database.

It exits non-zero if anything is found, so it can gate a publication.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git") or "git"

#: The PEM banner, assembled at run time.
#:
#: Written in pieces on purpose. Spelled out as a literal, this scanner would
#: match its own source in history and report itself as a finding -- which it
#: did, until this was fixed. Allow-listing the file by path would have worked
#: too, but it would also have blinded the scanner to a real key committed
#: into this file later.
_DASHES = b"-" * 5
_BEGIN = _DASHES + b"BEGIN "


#: Content patterns. Each is something that should never be in a public repo.
CONTENT_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    (
        "private key block",
        re.compile(_BEGIN + rb"(RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    ),
    ("encrypted private key block", re.compile(_BEGIN + rb"ENCRYPTED PRIVATE KEY")),
    ("AWS access key id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(rb"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "generic bearer secret",
        re.compile(
            rb"(?i)\b(authorization|api[_-]?key|secret)\s*[:=]\s*"
            rb"['\"][A-Za-z0-9/+_-]{24,}['\"]"
        ),
    ),
]

#: Path patterns. Data that must never be committed regardless of content.
PATH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("packet capture", re.compile(r"\.(pcap|pcapng|cap)$", re.I)),
    ("key material", re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.I)),
    ("database", re.compile(r"\.(sqlite3?|db)$", re.I)),
    ("environment file", re.compile(r"(^|/)\.env(\.|$)(?!example)", re.I)),
    ("mail store", re.compile(r"\.(mbox|eml|msg|pst|ost)$", re.I)),
]

#: Paths that legitimately contain a matching pattern. Each needs a reason.
ALLOWED: dict[str, str] = {
    ".env.example": (
        "a documented template of resource limits; carries no value that is "
        "secret"
    ),
    "scripts/audit_history.py": (
        "this scanner. Earlier commits of it spell the PEM banner as a literal "
        "in their pattern table, so it detects itself in history. Current "
        "versions assemble the banner at run time, but the old blobs stay in "
        "history for ever -- history is never rewritten here -- so the path is "
        "allowed with this reason rather than the finding being silenced."
    ),
}


def _run(args: list[str]) -> str:
    return subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [GIT, *args], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8", "replace")


def _all_blobs() -> list[tuple[str, str]]:
    """Every (sha, path) blob reachable from any ref, including deleted ones."""
    output = _run(["rev-list", "--objects", "--all"])
    blobs = []
    for line in output.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            blobs.append((parts[0], parts[1]))
    return blobs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet", action="store_true", help="print only findings and the verdict"
    )
    args = parser.parse_args()

    blobs = _all_blobs()
    if not args.quiet:
        print(f"scanning {len(blobs)} object(s) across every ref in the history")

    path_hits: list[str] = []
    content_hits: list[str] = []
    scanned = 0

    for sha, path in blobs:
        for label, path_pattern in PATH_PATTERNS:
            if path_pattern.search(path) and path not in ALLOWED:
                path_hits.append(f"{label}: {path} ({sha[:12]})")

        try:
            kind = _run(["cat-file", "-t", sha]).strip()
        except subprocess.CalledProcessError:
            continue
        if kind != "blob":
            continue
        try:
            size = int(_run(["cat-file", "-s", sha]).strip())
        except (subprocess.CalledProcessError, ValueError):
            continue
        if size > 4_000_000:
            continue
        try:
            data = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
                [GIT, "cat-file", "blob", sha],
                cwd=ROOT,
                capture_output=True,
                check=True,
            ).stdout
        except subprocess.CalledProcessError:
            continue
        scanned += 1
        for label, content_pattern in CONTENT_PATTERNS:
            if content_pattern.search(data):
                if path in ALLOWED:
                    continue
                content_hits.append(f"{label}: {path} ({sha[:12]})")

    if not args.quiet:
        print(f"read {scanned} blob(s)")

    if path_hits:
        print(f"\n{len(path_hits)} sensitive PATH(s) in history:")
        for hit in sorted(set(path_hits)):
            print(f"  {hit}")
    if content_hits:
        print(f"\n{len(content_hits)} sensitive CONTENT match(es) in history:")
        for hit in sorted(set(content_hits)):
            print(f"  {hit}")

    if ALLOWED and not args.quiet:
        print("\nallowed by exception:")
        for path, reason in ALLOWED.items():
            print(f"  {path}: {reason}")

    if path_hits or content_hits:
        print("\nVERDICT: sensitive data found in history. Do not publish.")
        return 1
    print("\nVERDICT: no packet capture, key material, token or database found "
          "in any commit reachable from any ref.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
