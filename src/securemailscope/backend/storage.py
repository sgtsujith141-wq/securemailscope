"""Private capture storage (M7).

Captures are evidence. They may contain anything, and they must not be
reachable by a browser, guessable by name, or writable outside one directory.

* **Server-generated identifiers.** The uploaded filename is recorded for
  display and never touches the filesystem. Paths are built from a random
  token, so a name like ``../../etc/passwd`` or ``foo.pcap\\x00.html`` cannot
  steer a write.
* **Outside the repository and outside anything served.** The default root is
  under the user's data directory, not the project tree. Nothing in this
  module can be reached by a static-file route because there is no static-file
  route over it.
* **Limits enforced while reading, not after.** The size cap is applied to the
  stream chunk by chunk, so an oversized upload is abandoned mid-flight
  instead of being written to disk and measured afterwards.
* **The extension is not trusted.** Format is decided by the container magic
  bytes, using the same detector the analyzer uses.
* **Restrictive permissions** where the platform supports them: 0700 on the
  directories, 0600 on the files.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final

from ..ingestion.formats import CaptureFormat, detect_format

__all__ = [
    "CaptureStorage",
    "StoredCapture",
    "UploadRejected",
    "DEFAULT_STORAGE_ROOT",
    "MAGIC_PREFIXES",
]

#: Deliberately outside the repository and outside any served directory.
DEFAULT_STORAGE_ROOT: Final = Path.home() / ".securemailscope" / "storage"

_CHUNK: Final = 1 << 20

#: pcap (both byte orders, both timestamp resolutions) and pcapng.
MAGIC_PREFIXES: Final = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)


class UploadRejected(Exception):
    """An upload that will not be stored, with a reason safe to show a user."""


class UploadTooLarge(UploadRejected):
    """The upload exceeded the configured size limit.

    Kept distinct from the other rejections so the API can answer 413 rather
    than 422. A client that cannot tell "too big" from "not a capture" cannot
    tell the user to split the file rather than to check its format.
    """


@dataclass(frozen=True)
class StoredCapture:
    storage_id: str
    original_name: str
    path: Path
    size_bytes: int
    sha256: str
    file_format: str


def _safe_display_name(name: str) -> str:
    """A display-only name.

    Never used to build a path; sanitised anyway so it cannot carry control
    characters or separators into a UI, a log or a report.
    """
    cleaned = "".join(
        character
        for character in (name or "capture")
        if character.isalnum() or character in "._- "
    ).strip()
    return (cleaned or "capture")[:120]


class CaptureStorage:
    def __init__(
        self, root: Path | str = DEFAULT_STORAGE_ROOT, *, max_bytes: int = 512 << 20
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.captures = self.root / "captures"
        self.reports = self.root / "reports"
        self.max_bytes = max_bytes
        for directory in (self.root, self.captures, self.reports):
            directory.mkdir(parents=True, exist_ok=True)
            self._restrict(directory, 0o700)

    @staticmethod
    def _restrict(path: Path, mode: int) -> None:
        # Best effort: some filesystems and platforms do not support it, and
        # failing an upload because a permission bit could not be set would be
        # worse than storing the file with the platform's default.
        with suppress(OSError, NotImplementedError):
            os.chmod(path, mode)

    def path_for(self, storage_id: str) -> Path:
        """Resolve a storage id to a path inside the capture directory.

        The id is validated as hex and the resolved path is confirmed to be
        inside the root. Two independent checks, because either alone has been
        a CVE in something.
        """
        if not storage_id or len(storage_id) > 64 or not all(
            character in "0123456789abcdef" for character in storage_id
        ):
            raise UploadRejected("invalid storage identifier")
        candidate = (self.captures / f"{storage_id}.bin").resolve()
        if self.captures.resolve() not in candidate.parents:
            raise UploadRejected("storage identifier resolves outside the store")
        return candidate

    def store(self, stream: BinaryIO, original_name: str) -> StoredCapture:
        """Stream an upload to private storage, enforcing limits as it reads."""
        storage_id = secrets.token_hex(16)
        target = self.path_for(storage_id)
        digest = hashlib.sha256()
        total = 0
        head = b""

        try:
            with target.open("wb") as handle:
                self._restrict(target, 0o600)
                while True:
                    chunk = stream.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise UploadTooLarge(
                            f"the upload exceeds the configured limit of "
                            f"{self.max_bytes} bytes and was abandoned before it "
                            "was fully written"
                        )
                    if len(head) < 8:
                        head += chunk[: 8 - len(head)]
                    digest.update(chunk)
                    handle.write(chunk)

            if total == 0:
                raise UploadRejected("the uploaded file is empty")
            if not any(head.startswith(prefix) for prefix in MAGIC_PREFIXES):
                raise UploadRejected(
                    "this file is not a pcap or pcapng capture. The container "
                    "magic bytes do not match either format; the file extension "
                    "is not consulted."
                )
            detected = detect_format(target)[0]
            if detected is CaptureFormat.UNKNOWN:
                raise UploadRejected("the capture container format is not recognised")
        except Exception:
            target.unlink(missing_ok=True)
            raise

        return StoredCapture(
            storage_id=storage_id,
            original_name=_safe_display_name(original_name),
            path=target,
            size_bytes=total,
            sha256=digest.hexdigest(),
            file_format=detected.value,
        )

    def store_report(self, data: bytes, export_id: str, suffix: str) -> Path:
        """Write a generated report into private storage."""
        if not all(character in "0123456789abcdef" for character in export_id):
            raise UploadRejected("invalid export identifier")
        if suffix not in ("json", "html", "pdf"):
            raise UploadRejected("unsupported report format")
        path = (self.reports / f"{export_id}.{suffix}").resolve()
        if self.reports.resolve() not in path.parents:
            raise UploadRejected("export identifier resolves outside the store")
        path.write_bytes(data)
        self._restrict(path, 0o600)
        return path

    def delete_capture(self, storage_id: str) -> bool:
        """Remove a stored capture. Explicit user action only."""
        path = self.path_for(storage_id)
        if not path.is_file():
            return False
        path.unlink()
        return True

    def usage_bytes(self) -> int:
        return sum(
            item.stat().st_size for item in self.captures.glob("*.bin") if item.is_file()
        )
