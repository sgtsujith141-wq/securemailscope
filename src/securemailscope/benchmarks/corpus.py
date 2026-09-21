"""Synthetic benchmark captures with controlled ground truth (M8).

Four sizes, each generated from a fixed seed so a measurement is reproducible.
The ground truth -- how many sessions, how many with TLS, how many carrying a
certificate -- is known by construction, so a benchmark also checks the engine
read what was written rather than only timing it.

Sizes were chosen from what this generator can produce in a few seconds, and
they are stated rather than described as "typical": nothing here claims to
represent real mail traffic volumes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..testing.certs import CAPTURE_EPOCH, SyntheticCA
from ..testing.dialogue import Dialogue
from ..testing.tls_messages import (
    CONTENT_HANDSHAKE,
    TLS10,
    TLS12,
    TLS13,
    certificate_message,
    client_hello,
    record,
    server_hello,
    server_hello_done,
)
from ..testing.writers import write_pcap

__all__ = ["CaptureProfile", "PROFILES", "build_capture"]

BASE_NS: Final = int(CAPTURE_EPOCH.timestamp()) * 1_000_000_000

#: A spread of suites so the engine exercises several registry paths rather
#: than one hot loop.
_SUITES: Final = (0xC02B, 0xC030, 0x009C, 0x002F, 0x0005, 0x1301, 0x1303)
_SEED: Final = 20260921


@dataclass(frozen=True)
class CaptureProfile:
    """One benchmark capture, with the ground truth it was built from."""

    name: str
    label: str
    sessions: int
    #: Sessions that also carry a plaintext SMTP dialogue before STARTTLS.
    plaintext_sessions: int
    description: str


PROFILES: Final[tuple[CaptureProfile, ...]] = (
    CaptureProfile(
        "small", "Small", 25, 5,
        "A single mail server's traffic over a short window.",
    ),
    CaptureProfile(
        "medium", "Medium", 200, 40,
        "A busier capture point, or a longer window.",
    ),
    CaptureProfile(
        "large", "Large", 1_000, 200,
        "The largest size this tool is intended for on a laptop.",
    ),
    CaptureProfile(
        "stress", "Stress", 4_000, 800,
        "Beyond the intended range, to find where limits engage.",
    ),
)

_SMTP_GREETING = b"220 mail.example ESMTP ready\r\n"
_SMTP_EHLO = b"EHLO client.example\r\n"
_SMTP_CAPS = b"250-mail.example Hello\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 HELP\r\n"
_SMTP_STARTTLS = b"STARTTLS\r\n"
_SMTP_READY = b"220 2.0.0 Ready to start TLS\r\n"


def build_capture(profile: CaptureProfile, directory: Path) -> tuple[Path, dict[str, int]]:
    """Generate one benchmark capture. Returns its path and ground truth.

    Sessions are interleaved in time, so the reassembler sees many concurrent
    flows rather than a tidy sequence -- which is what a real capture point
    produces and what actually exercises the session table.
    """
    rng = random.Random(_SEED)  # noqa: S311 - reproducibility, not cryptography
    authority = SyntheticCA()
    leaves = [
        authority.issue(f"mail{index}.example.invalid", serial=9000 + index)
        for index in range(8)
    ]

    packets: list[tuple[int, bytes]] = []
    truth = {"sessions": 0, "tls_sessions": 0, "certificate_sessions": 0, "plaintext_sessions": 0}

    for index in range(profile.sessions):
        plaintext = index < profile.plaintext_sessions
        suite = _SUITES[index % len(_SUITES)]
        tls13 = suite in (0x1301, 0x1303)
        version = TLS13 if tls13 else (TLS10 if index % 11 == 0 else TLS12)
        # Interleave: each session starts a little after the last, so their
        # packets are mixed together in capture order.
        start = BASE_NS + index * 250_000 + rng.randrange(0, 50_000)
        dialogue = Dialogue(
            client_ip=f"192.0.2.{10 + (index % 200)}",
            server_ip=f"198.51.100.{10 + (index % 40)}",
            client_port=32768 + (index % 20000),
            server_port=25 if plaintext else 993,
            handshake=True,
            start_ns=start,
        )
        truth["sessions"] += 1

        if plaintext:
            dialogue.send_server(_SMTP_GREETING)
            dialogue.send_client(_SMTP_EHLO)
            dialogue.send_server(_SMTP_CAPS)
            dialogue.send_client(_SMTP_STARTTLS)
            dialogue.send_server(_SMTP_READY)
            truth["plaintext_sessions"] += 1

        hello_version = TLS12 if tls13 else version
        dialogue.send_client(
            record(
                CONTENT_HANDSHAKE,
                client_hello(
                    legacy_version=hello_version,
                    cipher_suites=list(_SUITES),
                    server_name=f"mail{index % 8}.example.invalid",
                    supported_versions=[TLS13, TLS12] if tls13 else None,
                    key_share_groups=[0x001D] if tls13 else None,
                ),
                version=hello_version,
            )
        )
        flight = server_hello(
            legacy_version=TLS12 if tls13 else version,
            cipher_suite=suite,
            supported_version=TLS13 if tls13 else None,
            key_share_group=0x001D if tls13 else None,
        )
        if not tls13:
            flight += certificate_message([leaves[index % 8].der]) + server_hello_done()
            truth["certificate_sessions"] += 1
        dialogue.send_server(record(CONTENT_HANDSHAKE, flight, version=hello_version))
        truth["tls_sessions"] += 1
        packets.extend(dialogue.packets)

    # Capture order is timestamp order, as a real capture point would write it.
    packets.sort(key=lambda item: item[0])
    path = directory / f"benchmark-{profile.name}.pcap"
    path.write_bytes(write_pcap(packets))
    truth["packets"] = len(packets)
    truth["bytes"] = path.stat().st_size
    return path, truth
