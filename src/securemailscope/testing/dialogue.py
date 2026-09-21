"""A conversation builder that tracks TCP sequence numbers and stream offsets.

Writing a twenty-packet SMTP dialogue by hand means twenty sequence-number
calculations, and one slip makes a fixture that tests nothing.  This builder
does the arithmetic and, crucially, reports the *stream offset* of every
payload it emits.

Those offsets come from the fixture's own construction -- "I put this line at
byte 46 of the client stream" -- not from engine output.  A manifest built
from them is still an independent expectation: the engine has to reconstruct
the stream and arrive at the same number by itself.

Gaps are produced by :meth:`Dialogue.drop_client` / :meth:`drop_server`, which
advance the sequence number without emitting a packet -- exactly what a
capture point that missed a segment would leave behind.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fixtures import Conversation
from .packets import BASE_TIMESTAMP_NS, CLIENT_IP, SERVER_IP

__all__ = ["Dialogue", "Sent"]


@dataclass(frozen=True, slots=True)
class Sent:
    """Where a payload landed: packet numbers and stream offsets."""

    packets: tuple[int, ...]
    start_offset: int
    end_offset: int

    @property
    def first_packet(self) -> int:
        return self.packets[0]


class Dialogue:
    """Builds one TCP conversation carrying an application dialogue."""

    def __init__(
        self,
        *,
        client_ip: str = CLIENT_IP,
        server_ip: str = SERVER_IP,
        client_port: int = 49152,
        server_port: int = 25,
        client_isn: int = 1000,
        server_isn: int = 5000,
        handshake: bool = True,
        start_ns: int = BASE_TIMESTAMP_NS,
        step_ns: int = 1_000_000,
    ) -> None:
        self.conversation = Conversation(
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            start_ns=start_ns,
            step_ns=step_ns,
        )
        self._client_seq = client_isn
        self._server_seq = server_isn
        self.client_offset = 0
        self.server_offset = 0
        self._last_client_segment: tuple[int, bytes] | None = None

        if handshake:
            self.conversation.c2s(self._client_seq, 0, "S")
            self.conversation.s2c(self._server_seq, self._client_seq + 1, "SA")
            self._client_seq += 1
            self._server_seq += 1
            self.conversation.c2s(self._client_seq, self._server_seq, "A")
        else:
            # Midstream: the handshake happened before the capture started.
            self._client_seq += 1
            self._server_seq += 1

    # -- properties --------------------------------------------------------
    @property
    def packets(self) -> list[tuple[int, bytes]]:
        return self.conversation.packets

    @property
    def client(self) -> str:
        return self.conversation.client

    @property
    def server(self) -> str:
        return self.conversation.server

    # -- sending -----------------------------------------------------------
    def send_client(self, payload: bytes, *, flags: str = "PA") -> Sent:
        start = self.client_offset
        number = self.conversation.c2s(self._client_seq, self._server_seq, flags, payload)
        self._last_client_segment = (self._client_seq, payload)
        self._client_seq += len(payload)
        self.client_offset += len(payload)
        return Sent(packets=(number,), start_offset=start, end_offset=self.client_offset)

    def send_server(self, payload: bytes, *, flags: str = "PA") -> Sent:
        start = self.server_offset
        number = self.conversation.s2c(self._server_seq, self._client_seq, flags, payload)
        self._server_seq += len(payload)
        self.server_offset += len(payload)
        return Sent(packets=(number,), start_offset=start, end_offset=self.server_offset)

    def send_client_segmented(self, payload: bytes, sizes: list[int]) -> Sent:
        """Send ``payload`` split across several segments, in order."""
        if sum(sizes) != len(payload):
            raise ValueError("segment sizes must sum to the payload length")
        start = self.client_offset
        numbers: list[int] = []
        cursor = 0
        for size in sizes:
            chunk = payload[cursor : cursor + size]
            numbers.append(
                self.conversation.c2s(self._client_seq, self._server_seq, "PA", chunk)
            )
            self._client_seq += size
            self.client_offset += size
            cursor += size
        return Sent(
            packets=tuple(numbers), start_offset=start, end_offset=self.client_offset
        )

    def send_server_segmented(self, payload: bytes, sizes: list[int]) -> Sent:
        if sum(sizes) != len(payload):
            raise ValueError("segment sizes must sum to the payload length")
        start = self.server_offset
        numbers: list[int] = []
        cursor = 0
        for size in sizes:
            chunk = payload[cursor : cursor + size]
            numbers.append(
                self.conversation.s2c(self._server_seq, self._client_seq, "PA", chunk)
            )
            self._server_seq += size
            self.server_offset += size
            cursor += size
        return Sent(
            packets=tuple(numbers), start_offset=start, end_offset=self.server_offset
        )

    def send_server_out_of_order(self, payload: bytes, sizes: list[int]) -> Sent:
        """Send segments so the *second* arrives before the first."""
        if len(sizes) != 2 or sum(sizes) != len(payload):
            raise ValueError("out-of-order sending expects exactly two segments")
        start = self.server_offset
        first, second = payload[: sizes[0]], payload[sizes[0] :]
        second_number = self.conversation.s2c(
            self._server_seq + sizes[0], self._client_seq, "PA", second
        )
        first_number = self.conversation.s2c(
            self._server_seq, self._client_seq, "PA", first
        )
        self._server_seq += len(payload)
        self.server_offset += len(payload)
        return Sent(
            packets=(first_number, second_number),
            start_offset=start,
            end_offset=self.server_offset,
        )

    def send_server_conflicting(self, first: bytes, second: bytes, overlap: int) -> Sent:
        """Send two overlapping server segments whose overlap disagrees.

        The second segment starts ``overlap`` bytes before the first ends and
        carries different bytes there, which is the TCP-level ambiguity the
        reassembler reports as an overlap conflict.
        """
        if overlap <= 0 or overlap > min(len(first), len(second)):
            raise ValueError("overlap must fit inside both segments")
        start = self.server_offset
        first_number = self.conversation.s2c(self._server_seq, self._client_seq, "PA", first)
        second_seq = self._server_seq + len(first) - overlap
        second_number = self.conversation.s2c(second_seq, self._client_seq, "PA", second)
        self._server_seq = second_seq + len(second)
        self.server_offset = start + len(first) - overlap + len(second)
        return Sent(
            packets=(first_number, second_number),
            start_offset=start,
            end_offset=self.server_offset,
        )

    def retransmit_last_client(self) -> int:
        """Resend the previous client segment with a fresh IP ID."""
        if self._last_client_segment is None:
            raise ValueError("nothing has been sent by the client yet")
        sequence, payload = self._last_client_segment
        return self.conversation.c2s(sequence, self._server_seq, "PA", payload)

    # -- loss --------------------------------------------------------------
    def drop_client(self, payload: bytes) -> Sent:
        """Advance the client sequence without emitting: the capture missed it."""
        start = self.client_offset
        self._client_seq += len(payload)
        self.client_offset += len(payload)
        return Sent(packets=(), start_offset=start, end_offset=self.client_offset)

    def drop_server(self, payload: bytes) -> Sent:
        start = self.server_offset
        self._server_seq += len(payload)
        self.server_offset += len(payload)
        return Sent(packets=(), start_offset=start, end_offset=self.server_offset)

    # -- control -----------------------------------------------------------
    def ack_client(self) -> int:
        return self.conversation.c2s(self._client_seq, self._server_seq, "A")

    def ack_server(self) -> int:
        return self.conversation.s2c(self._server_seq, self._client_seq, "A")

    def close(self) -> None:
        """Graceful FIN/FIN teardown."""
        self.conversation.c2s(self._client_seq, self._server_seq, "FA")
        self._client_seq += 1
        self.conversation.s2c(self._server_seq, self._client_seq, "A")
        self.conversation.s2c(self._server_seq, self._client_seq, "FA")
        self._server_seq += 1
        self.conversation.c2s(self._client_seq, self._server_seq, "A")
