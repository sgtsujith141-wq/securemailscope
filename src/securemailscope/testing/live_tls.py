"""Real, locally negotiated TLS handshakes for fixtures.

These handshakes are produced by the installed OpenSSL through Python's
:mod:`ssl` module using :class:`ssl.MemoryBIO` pairs.  That means:

* the bytes are genuine OpenSSL output, not hand-assembled approximations, so
  the parser is tested against what real implementations actually emit;
* **no socket is created and no packet capture privilege is needed** -- the
  client and server exchange bytes through in-memory buffers;
* the analyzer is never involved. It only ever reads the resulting file.

The flights are returned in the order they were produced, so writing them into
a capture preserves realistic interleaving.

TLS randoms, session identifiers and ephemeral key shares are random by
design, so captures built from these handshakes are **not byte-reproducible**.
Fixtures that use them declare ``byte_reproducible=False`` and are asserted on
their negotiated parameters instead of on a capture hash.
"""

from __future__ import annotations

import contextlib
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from ..models.tcp import Direction

__all__ = [
    "HandshakeCapture",
    "negotiate",
    "negotiate_resumed",
    "tls12_ciphers_available",
]


@dataclass(frozen=True, slots=True)
class HandshakeCapture:
    """Ordered flights plus what the two endpoints agreed on."""

    flights: tuple[tuple[Direction, bytes], ...]
    negotiated_version: str | None
    negotiated_cipher: str | None
    #: True when the client reported the session as resumed.
    resumed: bool = False
    notes: tuple[str, ...] = field(default=())

    @property
    def client_bytes(self) -> int:
        return sum(
            len(data) for direction, data in self.flights
            if direction is Direction.CLIENT_TO_SERVER
        )

    @property
    def server_bytes(self) -> int:
        return sum(
            len(data) for direction, data in self.flights
            if direction is Direction.SERVER_TO_CLIENT
        )


def _context_pair(
    chain: Path,
    key: Path,
    *,
    version: ssl.TLSVersion,
    ciphers: str | None,
    server_hostname: str,
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(chain), str(key))
    server.minimum_version = version
    server.maximum_version = version
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The fixture's purpose is to produce wire bytes; trust decisions are what
    # SecureMailScope is being tested on, so the client here does not verify.
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.minimum_version = version
    client.maximum_version = version
    if ciphers:
        if version is ssl.TLSVersion.TLSv1_3:
            server.set_ciphers("@SECLEVEL=0:ALL")
            client.set_ciphers("@SECLEVEL=0:ALL")
        else:
            server.set_ciphers(ciphers)
            client.set_ciphers(ciphers)
    _ = server_hostname
    return client, server


def negotiate(
    chain: Path,
    key: Path,
    *,
    version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    ciphers: str | None = None,
    server_hostname: str = "mail.example.invalid",
    session: ssl.SSLSession | None = None,
    max_rounds: int = 24,
    contexts: tuple[ssl.SSLContext, ssl.SSLContext] | None = None,
    pump_after_handshake: bool = False,
) -> tuple[HandshakeCapture, ssl.SSLSession | None]:
    """Run one handshake in memory and return its wire flights.

    ``contexts`` reuses an existing (client, server) pair, which TLS 1.3
    resumption requires: a session ticket can only be replayed into the very
    context that issued it.  ``pump_after_handshake`` exchanges a little
    application data afterwards so the server's NewSessionTicket is delivered.
    """
    client_ctx, server_ctx = contexts or _context_pair(
        chain, key, version=version, ciphers=ciphers, server_hostname=server_hostname
    )
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(
        client_in, client_out, server_hostname=server_hostname, session=session
    )
    server = server_ctx.wrap_bio(server_in, server_out, server_side=True)

    flights: list[tuple[Direction, bytes]] = []
    for _ in range(max_rounds):
        progressed = False
        for endpoint, outgoing, incoming, direction in (
            (client, client_out, server_in, Direction.CLIENT_TO_SERVER),
            (server, server_out, client_in, Direction.SERVER_TO_CLIENT),
        ):
            with contextlib.suppress(ssl.SSLWantReadError, ssl.SSLWantWriteError):
                endpoint.do_handshake()
            data = outgoing.read()
            if data:
                flights.append((direction, data))
                incoming.write(data)
                progressed = True
        if not progressed:
            break

    if pump_after_handshake:
        _pump(client, server, client_in, client_out, server_in, server_out, flights)

    negotiated_version = None
    negotiated_cipher = None
    resumed = False
    new_session = None
    try:
        negotiated_version = client.version()
        cipher = client.cipher()
        negotiated_cipher = cipher[0] if cipher else None
        resumed = bool(client.session_reused)
        new_session = client.session
    except ssl.SSLError:  # pragma: no cover - handshake did not complete
        pass

    return (
        HandshakeCapture(
            flights=tuple(flights),
            negotiated_version=negotiated_version,
            negotiated_cipher=negotiated_cipher,
            resumed=resumed,
        ),
        new_session,
    )


def _pump(
    client: ssl.SSLObject,
    server: ssl.SSLObject,
    client_in: ssl.MemoryBIO,
    client_out: ssl.MemoryBIO,
    server_in: ssl.MemoryBIO,
    server_out: ssl.MemoryBIO,
    flights: list[tuple[Direction, bytes]],
) -> None:
    """Exchange a byte so a TLS 1.3 NewSessionTicket reaches the client."""
    try:
        server.write(b"\x00")
    except ssl.SSLError:  # pragma: no cover - handshake did not complete
        return
    data = server_out.read()
    if data:
        flights.append((Direction.SERVER_TO_CLIENT, data))
        client_in.write(data)
    with contextlib.suppress(ssl.SSLWantReadError, ssl.SSLError):
        client.read(1)
    data = client_out.read()
    if data:
        flights.append((Direction.CLIENT_TO_SERVER, data))
        server_in.write(data)


def negotiate_resumed(
    chain: Path,
    key: Path,
    *,
    version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    server_hostname: str = "mail.example.invalid",
) -> HandshakeCapture:
    """Run a handshake, then a second one resuming it, and return the second.

    Both handshakes share one client context because a TLS session ticket is
    only valid within the context that received it.
    """
    contexts = _context_pair(
        chain, key, version=version, ciphers=None, server_hostname=server_hostname
    )
    _, session = negotiate(
        chain,
        key,
        version=version,
        server_hostname=server_hostname,
        contexts=contexts,
        pump_after_handshake=True,
    )
    capture, _ = negotiate(
        chain,
        key,
        version=version,
        server_hostname=server_hostname,
        session=session,
        contexts=contexts,
    )
    return capture


def tls12_ciphers_available(spec: str) -> bool:
    """True when the installed OpenSSL still offers a TLS 1.2 cipher string."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers(spec)
    except ssl.SSLError:
        return False
    return bool(context.get_ciphers())
