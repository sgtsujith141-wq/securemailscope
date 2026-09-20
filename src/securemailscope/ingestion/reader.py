"""Capture source: validation, identity and bounded streaming iteration.

This is the only place in the engine that touches the filesystem for capture
input.  It performs, in order:

1. path validation (regular file, readable, resolved -- no traversal)
2. size check against ``max_capture_bytes`` *before* any parsing
3. SHA-256 of the original bytes, which becomes the ``capture_id``
4. content-based format detection
5. bounded streaming iteration of packet records

No shell command is ever constructed from a user-supplied path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..errors import (
    CaptureNotFoundError,
    CaptureTooLargeError,
    MalformedCaptureError,
    UnsupportedCaptureFormatError,
)
from ..models.capture import CaptureFormat, InterfaceInfo
from ..models.evidence import Severity, WarningCode
from .formats import detect_format
from .frames import RawFrame
from .pcap_reader import PcapReader
from .pcapng_reader import PcapngReader

__all__ = ["CaptureSource", "open_capture"]

_HASH_CHUNK: Final = 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


class CaptureSource:
    """A validated capture file, ready to be iterated once.

    Instances are single-use: :meth:`frames` opens the file, streams it and
    closes it.  Nothing is buffered beyond one packet at a time.
    """

    def __init__(
        self,
        path: Path,
        *,
        config: AnalysisConfig,
        sink: WarningSink,
        capture_id: str,
        file_size: int,
        file_format: CaptureFormat,
        byte_order: str | None,
    ) -> None:
        self.path = path
        self.config = config
        self.sink = sink
        self.capture_id = capture_id
        self.file_size = file_size
        self.file_format = file_format
        self.byte_order = byte_order
        self.interfaces: tuple[InterfaceInfo, ...] = ()
        self.truncated = False
        self.packets_read = 0

    @property
    def source_name(self) -> str:
        """Base name only. Directory components never reach a report."""
        return self.path.name

    def frames(self) -> Iterator[RawFrame]:
        with self.path.open("rb") as handle:
            if self.file_format is CaptureFormat.PCAPNG:
                reader: PcapngReader | PcapReader = PcapngReader(
                    handle, config=self.config, sink=self.sink
                )
            else:
                reader = PcapReader(handle, config=self.config, sink=self.sink)

            try:
                reader.read_header()
            except ValueError as exc:
                raise MalformedCaptureError(str(exc)) from exc

            self.byte_order = reader.byte_order or self.byte_order

            for frame in reader.frames():
                if self.packets_read >= self.config.max_packets:
                    self.truncated = True
                    self.sink.add(
                        WarningCode.LIMIT_PACKET_COUNT,
                        f"Stopped after {self.config.max_packets} packets "
                        "(max_packets limit); the remainder of the capture was not analysed.",
                        severity=Severity.ERROR,
                        limit=self.config.max_packets,
                    )
                    break
                self.packets_read += 1
                yield frame

            self.interfaces = tuple(reader.interfaces)
            self.truncated = self.truncated or reader.truncated


def open_capture(
    path: Path | str,
    *,
    config: AnalysisConfig,
    sink: WarningSink,
) -> CaptureSource:
    """Validate ``path`` and return a :class:`CaptureSource`.

    Raises a specific :class:`~securemailscope.errors.InputError` subclass for
    every rejection reason so callers can report precisely what was wrong.
    """
    resolved = Path(path).expanduser().resolve(strict=False)

    if not resolved.exists():
        raise CaptureNotFoundError(f"capture file does not exist: {resolved}")
    if not resolved.is_file():
        raise CaptureNotFoundError(f"capture path is not a regular file: {resolved}")

    file_size = resolved.stat().st_size
    if file_size == 0:
        raise MalformedCaptureError(f"capture file is empty: {resolved}")
    if file_size > config.max_capture_bytes:
        raise CaptureTooLargeError(
            f"capture is {file_size} bytes, above the configured maximum of "
            f"{config.max_capture_bytes} bytes"
        )

    try:
        file_format, byte_order = detect_format(resolved)
    except OSError as exc:
        raise CaptureNotFoundError(f"capture file is not readable: {resolved}") from exc

    if file_format is CaptureFormat.UNKNOWN:
        raise UnsupportedCaptureFormatError(
            f"{resolved.name} is not a libpcap or pcapng capture "
            "(file contents did not match any supported magic number)"
        )

    capture_id = "sha256:" + _sha256_file(resolved)
    sink.bind_capture(capture_id)

    return CaptureSource(
        resolved,
        config=config,
        sink=sink,
        capture_id=capture_id,
        file_size=file_size,
        file_format=file_format,
        byte_order=byte_order,
    )
