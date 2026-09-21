"""Gap-safe, bounded line reader over reconstructed TCP payload.

The M1 reassembler hands each direction a list of *contiguous runs*.  More
than one run means the stream has holes.  Everything in this module exists to
make it structurally impossible for a protocol parser to read across one of
those holes:

* A line is only ever assembled from bytes inside a single run.  When a run
  ends without a terminator the line is returned ``complete=False``, and the
  next line reports ``preceded_by_gap=True`` with the size of the hole.
* :meth:`StreamCursor.skip_bytes` -- used for IMAP literals -- stops at a run
  boundary and says so, rather than skipping into unrelated bytes.
* Bytes overlapping an unresolved TCP overlap conflict are flagged
  ``ambiguous``; a parser must not treat them as unambiguous evidence.

Bounds are enforced here too: a line longer than ``max_line_bytes`` is
truncated, reported, and the reader resynchronises at the next terminator
inside the same run rather than buffering without limit.

Nothing in this module retains, logs or reports line content.  Content is
handed to the parser and dropped; only offsets, lengths and packet references
survive.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..models.evidence import PacketReference, Severity, WarningCode
from ..models.tcp import Direction, DirectionalStream, OverlapConflict, ReassembledSegment

__all__ = [
    "PacketIndex",
    "DirectionalBuffer",
    "StreamLine",
    "SkipOutcome",
    "StreamCursor",
    "DialogueDriver",
    "DirectedLine",
    "merge_span",
]


class PacketIndex:
    """Maps a stream byte range back to the packets that carried it."""

    __slots__ = ("_starts", "_segments")

    def __init__(self, segments: Sequence[ReassembledSegment]) -> None:
        ordered = sorted(segments, key=lambda s: (s.stream_offset, s.length))
        self._segments = ordered
        self._starts = [segment.stream_offset for segment in ordered]

    def refs(self, start: int, end: int) -> tuple[PacketReference, ...]:
        """Packet references for ``[start, end)``, in capture order, deduplicated.

        An empty range resolves to the packet containing ``start``, so a
        zero-length marker still carries provenance.
        """
        if not self._segments:
            return ()
        if end <= start:
            end = start + 1
        index = bisect_right(self._starts, start) - 1
        if index < 0:
            index = 0
        seen: dict[int, PacketReference] = {}
        while index < len(self._segments):
            segment = self._segments[index]
            if segment.stream_offset >= end:
                break
            if segment.stream_offset + segment.length > start:
                seen.setdefault(segment.source.packet_number, segment.source)
            index += 1
        return tuple(seen[number] for number in sorted(seen))


@dataclass(frozen=True, slots=True)
class DirectionalBuffer:
    """Random-access view over one direction's reconstructed runs."""

    direction: Direction
    runs: tuple[tuple[int, bytes], ...]
    packets: PacketIndex
    conflicts: tuple[tuple[int, int], ...] = ()

    @classmethod
    def build(
        cls, direction: Direction, runs: Sequence[tuple[int, bytes]], stream: DirectionalStream
    ) -> DirectionalBuffer:
        conflicts = tuple(
            (conflict.stream_offset, conflict.stream_offset + conflict.length)
            for conflict in _sorted_conflicts(stream.overlap_conflicts)
        )
        return cls(
            direction=direction,
            runs=tuple((offset, bytes(data)) for offset, data in runs),
            packets=PacketIndex(stream.segments),
            conflicts=conflicts,
        )

    @property
    def empty(self) -> bool:
        return not self.runs

    @property
    def end_offset(self) -> int:
        if not self.runs:
            return 0
        offset, data = self.runs[-1]
        return offset + len(data)

    def run_index_for(self, offset: int) -> int | None:
        for index, (start, data) in enumerate(self.runs):
            if start <= offset < start + len(data):
                return index
        return None

    def read(self, offset: int, length: int) -> bytes:
        """Bytes from ``offset``, never crossing a run boundary."""
        index = self.run_index_for(offset)
        if index is None:
            return b""
        start, data = self.runs[index]
        local = offset - start
        return data[local : local + length]

    def is_ambiguous(self, start: int, end: int) -> bool:
        return any(not (c_end <= start or c_start >= end) for c_start, c_end in self.conflicts)

    def refs(self, start: int, end: int) -> tuple[PacketReference, ...]:
        return self.packets.refs(start, end)


def _sorted_conflicts(conflicts: Sequence[OverlapConflict]) -> list[OverlapConflict]:
    return sorted(conflicts, key=lambda c: c.stream_offset)


@dataclass(frozen=True, slots=True)
class StreamLine:
    """One protocol line, or the unterminated remainder of one."""

    direction: Direction
    start_offset: int
    end_offset: int
    content: bytes
    terminator: bytes
    complete: bool
    truncated: bool
    ambiguous: bool
    preceded_by_gap: bool
    gap_length: int
    packet_refs: tuple[PacketReference, ...]

    @property
    def first_packet_number(self) -> int:
        return self.packet_refs[0].packet_number if self.packet_refs else 0

    @property
    def first_timestamp(self) -> datetime | None:
        return self.packet_refs[0].timestamp if self.packet_refs else None

    @property
    def last_timestamp(self) -> datetime | None:
        return self.packet_refs[-1].timestamp if self.packet_refs else None

    @property
    def order_key(self) -> tuple[int, int]:
        """Capture order is the ground truth for what was seen first."""
        return self.first_packet_number, self.start_offset

    @property
    def usable(self) -> bool:
        """A line safe to interpret as a protocol record."""
        return self.complete and not self.truncated and not self.ambiguous


@dataclass(frozen=True, slots=True)
class SkipOutcome:
    """Result of skipping a declared byte count (an IMAP literal)."""

    requested: int
    skipped: int
    complete: bool
    stopped_at_gap: bool
    stopped_at_end: bool
    packet_refs: tuple[PacketReference, ...] = ()
    start_offset: int = 0
    end_offset: int = 0


@dataclass
class StreamCursor:
    """Sequential, gap-aware reader over one :class:`DirectionalBuffer`."""

    buffer: DirectionalBuffer
    config: AnalysisConfig
    sink: WarningSink
    session_id: str
    offset: int = 0
    _run_index: int = 0
    _stopped: bool = False
    _pending: tuple[StreamLine, int] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.buffer.runs:
            self.offset = self.buffer.runs[0][0]

    # -- state -------------------------------------------------------------
    @property
    def direction(self) -> Direction:
        return self.buffer.direction

    @property
    def stopped(self) -> bool:
        return self._stopped

    def stop(self) -> None:
        """Stop plaintext reading permanently (e.g. at a TLS boundary)."""
        self._stopped = True
        self._pending = None

    @property
    def exhausted(self) -> bool:
        return self._stopped or self._run_index >= len(self.buffer.runs)

    # -- reading -----------------------------------------------------------
    def peek(self) -> StreamLine | None:
        """The next line, without consuming it. ``None`` when nothing is left."""
        if self._stopped:
            return None
        if self._pending is not None:
            return self._pending[0]
        line = self._read_next()
        return line

    def advance(self) -> StreamLine | None:
        """Consume and return the next line."""
        line = self.peek()
        if line is None:
            return None
        assert self._pending is not None
        _, consume = self._pending
        self._pending = None
        self.offset = line.start_offset + consume
        self._sync_run()
        return line

    def _sync_run(self) -> None:
        while self._run_index < len(self.buffer.runs):
            start, data = self.buffer.runs[self._run_index]
            if self.offset < start + len(data):
                if self.offset < start:
                    self.offset = start
                return
            self._run_index += 1
        self.offset = self.buffer.end_offset

    def _read_next(self) -> StreamLine | None:
        if self._run_index >= len(self.buffer.runs):
            return None
        run_start, data = self.buffer.runs[self._run_index]
        if self.offset < run_start:
            self.offset = run_start
        local = self.offset - run_start
        if local >= len(data):
            self._run_index += 1
            if self._run_index >= len(self.buffer.runs):
                return None
            return self._read_next()

        preceded_by_gap = False
        gap_length = 0
        if self._run_index > 0 and local == 0:
            previous_start, previous_data = self.buffer.runs[self._run_index - 1]
            previous_end = previous_start + len(previous_data)
            if run_start > previous_end:
                preceded_by_gap = True
                gap_length = run_start - previous_end

        limit = self.config.max_line_bytes
        newline = data.find(b"\n", local, local + limit + 1)

        if newline == -1:
            available = len(data) - local
            if available > limit:
                return self._oversized(
                    run_start, data, local, limit, preceded_by_gap, gap_length
                )
            # Unterminated remainder: the run ended mid-line.
            content = data[local:]
            start_offset = run_start + local
            end_offset = start_offset + len(content)
            more_runs = self._run_index + 1 < len(self.buffer.runs)
            line = self._make(
                start_offset,
                end_offset,
                content,
                b"",
                complete=False,
                truncated=False,
                preceded_by_gap=preceded_by_gap,
                gap_length=gap_length,
            )
            if more_runs:
                self.sink.add(
                    WarningCode.PROTOCOL_GAP_IN_DIALOGUE,
                    f"A {self.direction.value} protocol line starting at stream offset "
                    f"{start_offset} is cut short by missing data; it is reported incomplete "
                    "and the bytes after the gap are not joined to it.",
                    session_id=self.session_id,
                    packet_refs=line.packet_refs,
                    stream_offset=start_offset,
                )
            self._pending = (line, len(content))
            return line

        content_end = newline
        terminator = b"\n"
        if content_end > local and data[content_end - 1 : content_end] == b"\r":
            content_end -= 1
            terminator = b"\r\n"
        content = data[local:content_end]
        start_offset = run_start + local
        end_offset = run_start + newline + 1
        line = self._make(
            start_offset,
            end_offset,
            content,
            terminator,
            complete=True,
            truncated=False,
            preceded_by_gap=preceded_by_gap,
            gap_length=gap_length,
        )
        self._pending = (line, end_offset - start_offset)
        return line

    def _oversized(
        self,
        run_start: int,
        data: bytes,
        local: int,
        limit: int,
        preceded_by_gap: bool,
        gap_length: int,
    ) -> StreamLine:
        """A line with no terminator within the limit: truncate and resynchronise."""
        start_offset = run_start + local
        content = data[local : local + limit]
        resume = data.find(b"\n", local + limit)
        consume = (resume + 1 - local) if resume != -1 else (len(data) - local)
        line = self._make(
            start_offset,
            start_offset + limit,
            content,
            b"",
            complete=False,
            truncated=True,
            preceded_by_gap=preceded_by_gap,
            gap_length=gap_length,
        )
        self.sink.add(
            WarningCode.LIMIT_LINE_BYTES,
            f"A {self.direction.value} line at stream offset {start_offset} exceeded the "
            f"{limit}-byte line limit without a terminator; it is reported truncated and "
            "parsing resynchronises at the next line terminator.",
            severity=Severity.ERROR,
            session_id=self.session_id,
            packet_refs=line.packet_refs,
            stream_offset=start_offset,
            limit=limit,
        )
        self._pending = (line, consume)
        return line

    def _make(
        self,
        start_offset: int,
        end_offset: int,
        content: bytes,
        terminator: bytes,
        *,
        complete: bool,
        truncated: bool,
        preceded_by_gap: bool,
        gap_length: int,
    ) -> StreamLine:
        ambiguous = self.buffer.is_ambiguous(start_offset, end_offset)
        if ambiguous:
            self.sink.add(
                WarningCode.PROTOCOL_AMBIGUOUS_BYTES,
                f"A {self.direction.value} protocol line at stream offset {start_offset} "
                "lies in a range where overlapping TCP segments disagreed; it is not "
                "treated as unambiguous protocol evidence.",
                severity=Severity.ERROR,
                session_id=self.session_id,
                stream_offset=start_offset,
            )
        return StreamLine(
            direction=self.direction,
            start_offset=start_offset,
            end_offset=end_offset,
            content=content,
            terminator=terminator,
            complete=complete,
            truncated=truncated,
            ambiguous=ambiguous,
            preceded_by_gap=preceded_by_gap,
            gap_length=gap_length,
            packet_refs=self.buffer.refs(start_offset, end_offset),
        )

    # -- byte-oriented reading (IMAP literals) ------------------------------
    def skip_bytes(self, count: int) -> SkipOutcome:
        """Skip exactly ``count`` bytes, never crossing a run boundary."""
        self._pending = None
        start = self.offset
        if self._stopped or self._run_index >= len(self.buffer.runs):
            return SkipOutcome(
                requested=count,
                skipped=0,
                complete=count == 0,
                stopped_at_gap=False,
                stopped_at_end=True,
                start_offset=start,
                end_offset=start,
            )
        run_start, data = self.buffer.runs[self._run_index]
        available = (run_start + len(data)) - self.offset
        skipped = min(count, max(0, available))
        self.offset += skipped
        more_runs = self._run_index + 1 < len(self.buffer.runs)
        self._sync_run()
        return SkipOutcome(
            requested=count,
            skipped=skipped,
            complete=skipped == count,
            stopped_at_gap=skipped < count and more_runs,
            stopped_at_end=skipped < count and not more_runs,
            packet_refs=self.buffer.refs(start, start + max(skipped, 1)),
            start_offset=start,
            end_offset=start + skipped,
        )


def merge_span(lines: Sequence[StreamLine]) -> StreamLine:
    """Collapse consecutive lines of one multiline record into a single span.

    Used for SMTP multiline replies, POP3 multiline responses and IMAP
    commands continued across a literal: the resulting span covers the whole
    record, so the recorded end offset is the end of its *final* line. That is
    what a TLS transition boundary must be measured from.
    """
    if not lines:
        raise ValueError("merge_span requires at least one line")
    first, last = lines[0], lines[-1]
    seen: dict[int, PacketReference] = {}
    for line in lines:
        for ref in line.packet_refs:
            seen.setdefault(ref.packet_number, ref)
    return StreamLine(
        direction=first.direction,
        start_offset=first.start_offset,
        end_offset=last.end_offset,
        content=b"",
        terminator=last.terminator,
        complete=all(line.complete for line in lines),
        truncated=any(line.truncated for line in lines),
        ambiguous=any(line.ambiguous for line in lines),
        preceded_by_gap=first.preceded_by_gap,
        gap_length=first.gap_length,
        packet_refs=tuple(seen[number] for number in sorted(seen)),
    )


@dataclass(frozen=True, slots=True)
class DirectedLine:
    """A line together with the direction it travelled in."""

    line: StreamLine
    direction: Direction

    @property
    def order_key(self) -> tuple[int, int]:
        return self.line.order_key


class DialogueDriver:
    """Interleaves two cursors into the order the packets were captured in.

    Command/response correlation depends on this: an SMTP reply must be
    matched against the command that was actually outstanding when it arrived,
    and that ordering comes from capture order, not from reading one direction
    to exhaustion first.
    """

    def __init__(self, client: StreamCursor, server: StreamCursor) -> None:
        self.client = client
        self.server = server

    def cursor(self, direction: Direction) -> StreamCursor:
        return self.client if direction is Direction.CLIENT_TO_SERVER else self.server

    def next(self) -> DirectedLine | None:
        """Consume and return whichever direction's next line came first."""
        candidates: list[tuple[tuple[int, int], StreamCursor, StreamLine]] = []
        for cursor in (self.client, self.server):
            line = cursor.peek()
            if line is not None:
                candidates.append((line.order_key, cursor, line))
        if not candidates:
            return None
        # Ties break toward the client: a command precedes its own reply.
        candidates.sort(key=lambda item: (item[0], item[1].direction.value))
        _, cursor, _ = candidates[0]
        consumed = cursor.advance()
        if consumed is None:  # pragma: no cover - peek guaranteed a line
            return None
        return DirectedLine(line=consumed, direction=cursor.direction)

    def stop_all(self) -> None:
        self.client.stop()
        self.server.stop()
