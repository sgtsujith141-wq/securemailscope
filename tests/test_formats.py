"""Format detection must depend on contents, never on the file extension."""

from __future__ import annotations

from pathlib import Path

import pytest

from securemailscope.ingestion.formats import detect_format, detect_format_from_bytes
from securemailscope.models.capture import CaptureFormat
from securemailscope.testing.writers import write_pcap, write_pcapng


@pytest.mark.parametrize(
    ("head", "expected_format", "expected_order"),
    [
        (b"\xd4\xc3\xb2\xa1" + bytes(20), CaptureFormat.PCAP, "little"),
        (b"\xa1\xb2\xc3\xd4" + bytes(20), CaptureFormat.PCAP, "big"),
        (b"\x4d\x3c\xb2\xa1" + bytes(20), CaptureFormat.PCAP_NS, "little"),
        (b"\xa1\xb2\x3c\x4d" + bytes(20), CaptureFormat.PCAP_NS, "big"),
        (
            b"\x0a\x0d\x0d\x0a" + bytes(4) + b"\x4d\x3c\x2b\x1a",
            CaptureFormat.PCAPNG,
            "little",
        ),
        (b"\x0a\x0d\x0d\x0a" + bytes(4) + b"\x1a\x2b\x3c\x4d", CaptureFormat.PCAPNG, "big"),
    ],
)
def test_magic_numbers_are_classified(
    head: bytes, expected_format: CaptureFormat, expected_order: str
) -> None:
    assert detect_format_from_bytes(head) == (expected_format, expected_order)


@pytest.mark.parametrize(
    "head",
    [
        b"",
        b"\x00",
        b"PK\x03\x04" + bytes(20),  # a zip archive
        b"NOT A CAPTURE FILE\n",
        b"\x0a\x0d\x0d\x0a" + bytes(4) + b"\xde\xad\xbe\xef",  # pcapng, bad BOM
        b"\x0a\x0d\x0d\x0a",  # pcapng SHB truncated before its BOM
    ],
)
def test_non_captures_are_rejected(head: bytes) -> None:
    assert detect_format_from_bytes(head) == (CaptureFormat.UNKNOWN, None)


def test_extension_is_irrelevant(tmp_path: Path) -> None:
    """A pcapng named .pcap is still a pcapng, and vice versa."""
    misnamed_ng = tmp_path / "actually_pcapng.pcap"
    misnamed_ng.write_bytes(write_pcapng([]))
    assert detect_format(misnamed_ng)[0] is CaptureFormat.PCAPNG

    misnamed_pcap = tmp_path / "actually_pcap.pcapng"
    misnamed_pcap.write_bytes(write_pcap([]))
    assert detect_format(misnamed_pcap)[0] is CaptureFormat.PCAP
