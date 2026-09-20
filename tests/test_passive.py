"""The engine must be passive and must stay passive.

Scapy is a packet *crafting* library first: building an Ethernet layer with an
unresolved destination MAC makes it send a live ARP or Neighbour Solicitation.
These tests assert the guard that prevents that is installed and effective,
and that the analysis path never spawns a subprocess.
"""

from __future__ import annotations

import subprocess

import pytest

from securemailscope import analyze_capture
from securemailscope.scapy_guard import PassiveModeViolation, guard_installed

from .conftest import Fixture


def test_guard_is_installed_on_import() -> None:
    assert guard_installed() is True


def test_neighbour_resolution_raises_instead_of_sending() -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    with pytest.raises(PassiveModeViolation):
        bytes(Ether() / IP(dst="198.51.100.25") / TCP())


def test_explicit_link_addresses_still_build() -> None:
    """The guard must block only unresolved addresses, not legitimate crafting."""
    from securemailscope.testing.packets import (
        CLIENT_IP,
        CLIENT_MAC,
        SERVER_IP,
        SERVER_MAC,
        ethernet_tcp,
    )

    frame = ethernet_tcp(
        src_mac=CLIENT_MAC,
        dst_mac=SERVER_MAC,
        src_ip=CLIENT_IP,
        dst_ip=SERVER_IP,
        src_port=49152,
        dst_port=25,
        seq=1,
        flags="S",
    )
    assert len(frame) == 54


def test_analysis_spawns_no_subprocess(
    fixtures: dict[str, Fixture], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user-controlled filename must never reach a shell."""

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("analysis attempted to spawn a subprocess")

    monkeypatch.setattr(subprocess, "Popen", explode)
    monkeypatch.setattr(subprocess, "run", explode)
    monkeypatch.setattr(subprocess, "call", explode)

    result = analyze_capture(fixtures["A_complete_connection"].path)
    assert result.inventory.session_count == 1


def test_analysis_opens_no_socket(
    fixtures: dict[str, Fixture], monkeypatch: pytest.MonkeyPatch
) -> None:
    import socket

    def explode(*args: object, **kwargs: object) -> None:
        raise AssertionError("analysis attempted to open a socket")

    monkeypatch.setattr(socket, "socket", explode)
    monkeypatch.setattr(socket, "create_connection", explode)
    monkeypatch.setattr(socket, "getaddrinfo", explode)

    result = analyze_capture(fixtures["G_two_connections"].path)
    assert result.inventory.session_count == 2


def test_shell_metacharacters_in_filename_are_harmless(
    fixtures: dict[str, Fixture], tmp_path: object
) -> None:
    from pathlib import Path

    source = fixtures["A_complete_connection"].path
    assert isinstance(tmp_path, Path)
    hostile = tmp_path / "a; rm -rf $(echo x) `id`.pcap"
    hostile.write_bytes(source.read_bytes())
    result = analyze_capture(hostile)
    assert result.inventory.session_count == 1
    assert result.capture.source_name == hostile.name
