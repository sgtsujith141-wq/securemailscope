"""Bidirectional TCP payload reconstruction for one direction of a connection.

Design notes
------------

**Bytes are stored against extended sequence numbers, not stream offsets.**
Stream offsets are computed once, at :meth:`DirectionalReassembler.finalize`.
That matters for midstream captures: if the first segment we happen to see is
out of order, anchoring offsets on it would push the genuinely-earlier segment
to a negative offset.  Deferring the anchor lets the earliest observed byte
define offset 0 no matter what order the packets arrived in.

**One interval per contributing packet.**  A segment that partially overlaps
stored data is clipped, and only its novel byte ranges are inserted -- each
still attributed to the packet it came from.  Intervals are never merged, so
every reconstructed byte can be traced to the exact frame that carried it.

**Overlap policy: FIRST_OBSERVED_WINS.**  When two packets claim the same
offsets with different bytes, the first observation stays in the stream and
the disagreement is recorded as an :class:`~securemailscope.models.tcp.OverlapConflict`.
Overlapping-segment disagreement is a deliberate evasion technique, so the
ambiguity is evidence and is preserved rather than resolved away.  Only
digests of the competing bytes are kept, never the bytes themselves.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_left
from dataclasses import dataclass, field

from ..config import AnalysisConfig
from ..diagnostics import WarningSink
from ..ingestion.dissect import ParsedPacket, TCPFlags
from ..models.evidence import EvidenceStatus, PacketReference, Severity, WarningCode
from ..models.tcp import (
    ByteRun,
    Direction,
    DirectionalStream,
    Endpoint,
    GapReason,
    OverlapConflict,
    ReassembledSegment,
    ReassemblyGap,
    SegmentDisposition,
)
from .budget import ByteBudget
from .seqspace import SequenceSpace

__all__ = ["DirectionalReassembler"]


@dataclass(slots=True)
class _Interval:
    """A contiguous run of bytes contributed by exactly one packet."""

    start: int  # extended sequence of the first byte
    data: bytes
    packet: PacketReference
    duplicates: list[PacketReference] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.start + len(self.data)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signature(start: int, data: bytes) -> tuple[int, int, bytes]:
    return start, len(data), hashlib.blake2b(data, digest_size=16).digest()


class DirectionalReassembler:
    """Accumulates one direction of a TCP connection."""

    def __init__(
        self,
        *,
        direction: Direction,
        source: Endpoint,
        destination: Endpoint,
        config: AnalysisConfig,
        sink: WarningSink,
        session_budget: ByteBudget,
        global_budget: ByteBudget,
        session_id: str,
    ) -> None:
        self.direction = direction
        self.source = source
        self.destination = destination
        self._config = config
        self._sink = sink
        self._session_budget = session_budget
        self._global_budget = global_budget
        self._session_id = session_id

        self._space: SequenceSpace | None = None
        self._syn_ext: int | None = None
        self._intervals: list[_Interval] = []
        self._starts: list[int] = []  # parallel to _intervals, for bisect
        self._signatures: dict[tuple[int, int, bytes], list[bytes]] = {}
        self._conflicts: list[OverlapConflict] = []
        #: (extended sequence of first byte, segment record awaiting rebasing)
        self._segments: list[tuple[int, ReassembledSegment]] = []
        self._limit_dropped: list[tuple[int, int]] = []
        #: Ranges a packet declared but the capture's snapshot length cut off.
        self._not_captured: list[tuple[int, int]] = []

        self.packet_count = 0
        self.payload_packet_count = 0
        self.retransmission_count = 0
        self.duplicate_count = 0
        self.out_of_order_count = 0
        self.dropped_by_limit_count = 0
        self.truncated_by_limit = False
        self.fin_observed = False
        self.rst_observed = False
        self.snapshot_truncated_count = 0

        self._max_end_ext: int | None = None
        self._peer_ack_ext: int | None = None
        self._first_packet: PacketReference | None = None
        self._last_packet: PacketReference | None = None

    # -- ingestion ---------------------------------------------------------
    def observe(self, packet: ParsedPacket, ref: PacketReference) -> None:
        """Record one packet sent in this direction."""
        self.packet_count += 1
        if self._first_packet is None:
            self._first_packet = ref
        self._last_packet = ref

        if self._space is None:
            self._space = SequenceSpace(packet.seq)

        seq_ext = self._space.extend(packet.seq)

        if packet.flag(TCPFlags.SYN) and self._syn_ext is None:
            self._syn_ext = seq_ext
        if packet.flag(TCPFlags.FIN):
            self.fin_observed = True
        if packet.flag(TCPFlags.RST):
            self.rst_observed = True

        if not packet.payload:
            return

        self.payload_packet_count += 1
        if packet.payload_truncated:
            self.snapshot_truncated_count += 1
            self._sink.add(
                WarningCode.TRUNCATED_PACKET_DATA,
                f"Packet {ref.packet_number} carried {packet.declared_payload_length} payload "
                f"bytes but only {len(packet.payload)} were captured (snapshot length); the "
                "remainder is recorded as a gap.",
                session_id=self._session_id,
                packet_refs=(ref,),
                declared=packet.declared_payload_length,
                captured=len(packet.payload),
            )
        # A SYN occupies the sequence number before any payload it carries.
        data_start = seq_ext + (1 if packet.flag(TCPFlags.SYN) else 0)
        if packet.payload_truncated:
            self._not_captured.append(
                (
                    data_start + len(packet.payload),
                    data_start + packet.declared_payload_length,
                )
            )
        self._insert(data_start, packet, ref)

    def note_peer_ack(self, ack32: int) -> None:
        """Record an acknowledgement the *peer* sent for this direction's data."""
        if self._space is None:
            return
        ack_ext = self._space.project(ack32)
        if self._peer_ack_ext is None or ack_ext > self._peer_ack_ext:
            self._peer_ack_ext = ack_ext

    # -- interval store ----------------------------------------------------
    def _overlapping(self, start: int, end: int) -> list[int]:
        """Indices of stored intervals intersecting ``[start, end)``."""
        index = bisect_left(self._starts, start)
        if index > 0 and self._intervals[index - 1].end > start:
            index -= 1
        result = []
        while index < len(self._intervals) and self._intervals[index].start < end:
            if self._intervals[index].end > start:
                result.append(index)
            index += 1
        return result

    def _insert_interval(self, interval: _Interval) -> None:
        index = bisect_left(self._starts, interval.start)
        self._intervals.insert(index, interval)
        self._starts.insert(index, interval.start)

    def _insert(self, start: int, packet: ParsedPacket, ref: PacketReference) -> None:
        data = packet.payload
        end = start + len(data)
        signature = _signature(start, data)
        prior_frames = self._signatures.get(signature)
        is_exact_repeat = prior_frames is not None
        is_frame_repeat = bool(prior_frames and packet.frame_digest in prior_frames)
        self._signatures.setdefault(signature, []).append(packet.frame_digest)

        overlaps = self._overlapping(start, end)
        covered_matching = 0
        covered_conflicting = 0
        touched: list[_Interval] = []

        cursor = start
        new_ranges: list[tuple[int, bytes]] = []
        for index in overlaps:
            interval = self._intervals[index]
            if interval.start > cursor:
                new_ranges.append((cursor, data[cursor - start : interval.start - start]))
                cursor = interval.start
            overlap_start = max(cursor, interval.start)
            overlap_end = min(end, interval.end)
            if overlap_end > overlap_start:
                incoming = data[overlap_start - start : overlap_end - start]
                stored = interval.data[
                    overlap_start - interval.start : overlap_end - interval.start
                ]
                if incoming == stored:
                    covered_matching += overlap_end - overlap_start
                    touched.append(interval)
                else:
                    covered_conflicting += overlap_end - overlap_start
                    self._record_conflict(
                        overlap_start, stored, incoming, interval.packet, ref
                    )
                cursor = overlap_end
        if cursor < end:
            new_ranges.append((cursor, data[cursor - start :]))

        new_byte_count = sum(len(chunk) for _, chunk in new_ranges)
        granted_total = self._grant(new_byte_count, ref)

        stored_new = 0
        accepted_ranges: list[tuple[int, bytes]] = []
        for range_start, chunk in new_ranges:
            if granted_total <= 0:
                self._limit_dropped.append((range_start, range_start + len(chunk)))
                continue
            if len(chunk) > granted_total:
                accepted_ranges.append((range_start, chunk[:granted_total]))
                self._limit_dropped.append(
                    (range_start + granted_total, range_start + len(chunk))
                )
                stored_new += granted_total
                granted_total = 0
            else:
                accepted_ranges.append((range_start, chunk))
                stored_new += len(chunk)
                granted_total -= len(chunk)

        if len(self._intervals) + len(accepted_ranges) > self._config.max_segments_per_direction:
            self.truncated_by_limit = True
            self.dropped_by_limit_count += 1
            self._sink.add(
                WarningCode.LIMIT_SEGMENTS_PER_DIRECTION,
                f"Direction {self.direction.value} reached the "
                f"{self._config.max_segments_per_direction}-segment limit; further segments "
                "are not reconstructed.",
                severity=Severity.ERROR,
                session_id=self._session_id,
                packet_refs=(ref,),
                limit=self._config.max_segments_per_direction,
            )
            for range_start, chunk in accepted_ranges:
                self._limit_dropped.append((range_start, range_start + len(chunk)))
            accepted_ranges = []
            stored_new = 0

        # Out-of-order means the segment arrived *behind* the high-water mark
        # and stayed behind it -- it backfilled a hole. A segment that starts
        # behind the mark but pushes past it is an overlapping resend, not
        # reordering, and is classified by its overlap disposition instead.
        out_of_order = (
            self._max_end_ext is not None
            and start < self._max_end_ext
            and end <= self._max_end_ext
            and stored_new > 0
        )
        if self._max_end_ext is None or end > self._max_end_ext:
            self._max_end_ext = end

        disposition = self._classify(
            new_byte_count=new_byte_count,
            stored_new=stored_new,
            covered_matching=covered_matching,
            covered_conflicting=covered_conflicting,
            is_exact_repeat=is_exact_repeat,
            is_frame_repeat=is_frame_repeat,
        )

        if disposition is SegmentDisposition.DUPLICATE:
            self.duplicate_count += 1
        elif disposition is SegmentDisposition.RETRANSMISSION:
            self.retransmission_count += 1
        if disposition in (SegmentDisposition.DUPLICATE, SegmentDisposition.RETRANSMISSION):
            for interval in touched:
                interval.duplicates.append(ref)
        if out_of_order:
            self.out_of_order_count += 1
        if disposition is SegmentDisposition.DROPPED_LIMIT:
            self.dropped_by_limit_count += 1

        for range_start, chunk in accepted_ranges:
            interval = _Interval(start=range_start, data=chunk, packet=ref)
            self._insert_interval(interval)
            self._segments.append(
                (
                    range_start,
                    ReassembledSegment(
                        # Offsets are unknown until finalize() fixes the base.
                        stream_offset=0,
                        length=len(chunk),
                        sequence_number=(
                            self._space.to_sequence(range_start) if self._space else 0
                        ),
                        source=ref,
                        disposition=disposition,
                    ),
                )
            )

    @staticmethod
    def _classify(
        *,
        new_byte_count: int,
        stored_new: int,
        covered_matching: int,
        covered_conflicting: int,
        is_exact_repeat: bool,
        is_frame_repeat: bool,
    ) -> SegmentDisposition:
        if covered_conflicting:
            return SegmentDisposition.OVERLAP_CONFLICT
        if new_byte_count == 0:
            if is_frame_repeat:
                return SegmentDisposition.DUPLICATE
            if is_exact_repeat or covered_matching:
                return SegmentDisposition.RETRANSMISSION
            return SegmentDisposition.RETRANSMISSION
        if stored_new == 0:
            return SegmentDisposition.DROPPED_LIMIT
        if covered_matching:
            return SegmentDisposition.PARTIAL_OVERLAP
        return SegmentDisposition.ACCEPTED

    def _grant(self, amount: int, ref: PacketReference) -> int:
        if amount <= 0:
            return 0
        granted = min(self._session_budget.remaining, self._global_budget.remaining, amount)
        if granted > 0:
            self._session_budget.take(granted)
            self._global_budget.take(granted)
        if granted < amount:
            self.truncated_by_limit = True
            code = (
                WarningCode.LIMIT_SESSION_PAYLOAD_BYTES
                if self._session_budget.remaining == 0
                else WarningCode.LIMIT_TOTAL_PAYLOAD_BYTES
            )
            self._sink.add(
                code,
                f"Payload budget exhausted while reconstructing {self.direction.value}; "
                f"{amount - granted} bytes from packet {ref.packet_number} were not stored.",
                severity=Severity.ERROR,
                session_id=self._session_id,
                packet_refs=(ref,),
                dropped_bytes=amount - granted,
            )
        return granted

    def _record_conflict(
        self,
        offset_ext: int,
        stored: bytes,
        incoming: bytes,
        accepted_packet: PacketReference,
        conflicting_packet: PacketReference,
    ) -> None:
        self._conflicts.append(
            OverlapConflict(
                stream_offset=offset_ext,  # rebased in finalize()
                length=len(stored),
                accepted_packet=accepted_packet,
                conflicting_packet=conflicting_packet,
                accepted_sha256=_digest(stored),
                conflicting_sha256=_digest(incoming),
            )
        )
        self._sink.add(
            WarningCode.OVERLAP_CONFLICT,
            f"Packets {accepted_packet.packet_number} and "
            f"{conflicting_packet.packet_number} deliver different bytes for the same "
            f"{len(stored)}-byte range of the {self.direction.value} stream. The first "
            "observation was kept (FIRST_OBSERVED_WINS); the disagreement is reported.",
            severity=Severity.ERROR,
            session_id=self._session_id,
            packet_refs=(accepted_packet, conflicting_packet),
            conflict_length=len(stored),
        )

    # -- results -----------------------------------------------------------
    def _base_ext(self) -> int | None:
        """Extended sequence that maps to stream offset 0."""
        candidates: list[int] = []
        if self._syn_ext is not None:
            candidates.append(self._syn_ext + 1)
        if self._intervals:
            candidates.append(self._intervals[0].start)
        if not candidates:
            return None
        return min(candidates)

    def payload_runs(self) -> list[tuple[int, bytes]]:
        """Contiguous ``(stream_offset, bytes)`` runs, ordered by offset.

        More than one run means the stream has holes.  Callers must treat each
        run independently; concatenating across a gap would invent data.
        """
        base = self._base_ext()
        if base is None or not self._intervals:
            return []
        runs: list[tuple[int, bytearray]] = []
        for interval in self._intervals:
            offset = interval.start - base
            if runs and runs[-1][0] + len(runs[-1][1]) == offset:
                runs[-1][1].extend(interval.data)
            else:
                runs.append((offset, bytearray(interval.data)))
        return [(offset, bytes(buffer)) for offset, buffer in runs]

    def _build_gaps(self, base: int) -> list[ReassemblyGap]:
        """Every byte range we have reason to believe existed but do not hold.

        Three sources are unified into one ordered walk so that a range is
        never reported twice: holes between stored intervals, tails a packet
        declared but the snapshot length cut off, and ranges dropped because a
        payload or segment limit was reached.  The reason recorded for each
        gap names the most specific cause that applies to it.
        """
        if not self._intervals:
            return []

        claimed_end = self._intervals[-1].end
        for _, end in self._not_captured:
            claimed_end = max(claimed_end, end)
        for _, end in self._limit_dropped:
            claimed_end = max(claimed_end, end)

        gaps: list[ReassemblyGap] = []
        cursor = self._intervals[0].start
        previous: _Interval | None = None
        for interval in self._intervals:
            if interval.start > cursor:
                gaps.append(self._gap(cursor, interval.start, base, previous, interval))
            cursor = max(cursor, interval.end)
            previous = interval
            if len(gaps) >= self._config.max_gaps_per_direction:
                return gaps
        if claimed_end > cursor and len(gaps) < self._config.max_gaps_per_direction:
            gaps.append(self._gap(cursor, claimed_end, base, previous, None))
        return gaps

    @staticmethod
    def _intersects(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
        return any(not (r_end <= start or r_start >= end) for r_start, r_end in ranges)

    def _gap(
        self,
        start: int,
        end: int,
        base: int,
        previous: _Interval | None,
        following: _Interval | None,
    ) -> ReassemblyGap:
        if self._intersects(start, end, self._not_captured):
            reason = GapReason.NOT_CAPTURED
        elif self._intersects(start, end, self._limit_dropped):
            reason = GapReason.LIMIT_EXCEEDED
        else:
            reason = GapReason.MISSING_SEGMENT
        return ReassemblyGap(
            stream_offset=start - base,
            length=end - start,
            reason=reason,
            content_status=EvidenceStatus.UNKNOWN,
            preceding_packet=previous.packet if previous else None,
            following_packet=following.packet if following else None,
        )

    def finalize(self) -> DirectionalStream:
        """Compute stream offsets and produce the immutable result model."""
        base = self._base_ext()
        if base is None or not self._intervals:
            return DirectionalStream(
                direction=self.direction,
                source=self.source,
                destination=self.destination,
                packet_count=self.packet_count,
                payload_packet_count=self.payload_packet_count,
                stream_base_sequence=self._space.to_sequence(base)
                if (self._space is not None and base is not None)
                else None,
                base_status=EvidenceStatus.OBSERVED
                if self._syn_ext is not None
                else EvidenceStatus.UNKNOWN,
                base_basis="TCP_SYN" if self._syn_ext is not None else None,
                truncated_by_limit=self.truncated_by_limit,
                fin_observed=self.fin_observed,
                rst_observed=self.rst_observed,
                highest_ack_observed=self._peer_ack_ext,
                dropped_by_limit_count=self.dropped_by_limit_count,
            )

        gaps = self._build_gaps(base)

        # Group adjacent intervals into maximal contiguous runs. More than one
        # run means the stream has holes and must not be parsed as continuous.
        groups: list[list[_Interval]] = []
        for interval in self._intervals:
            if groups and groups[-1][-1].end == interval.start:
                groups[-1].append(interval)
            else:
                groups.append([interval])

        runs = tuple(
            ByteRun(
                stream_offset=group[0].start - base,
                length=sum(len(item.data) for item in group),
                sha256=_digest(b"".join(item.data for item in group)),
                first_packet=group[0].packet,
                last_packet=group[-1].packet,
            )
            for group in groups
        )

        by_start = {interval.start: interval for interval in self._intervals}
        segments_list = [
            segment.model_copy(
                update={
                    "stream_offset": start_ext - base,
                    "duplicates": tuple(by_start[start_ext].duplicates)
                    if start_ext in by_start
                    else (),
                }
            )
            for start_ext, segment in self._segments
        ]
        segments_list.sort(key=lambda segment: (segment.stream_offset, segment.length))
        segments = tuple(segments_list)
        conflicts = tuple(
            conflict.model_copy(update={"stream_offset": conflict.stream_offset - base})
            for conflict in self._conflicts
        )

        bytes_reconstructed = sum(len(interval.data) for interval in self._intervals)
        highest_end = self._intervals[-1].end - base

        self._emit_gap_warnings(gaps)
        self._emit_acked_not_captured(base)

        return DirectionalStream(
            direction=self.direction,
            source=self.source,
            destination=self.destination,
            packet_count=self.packet_count,
            payload_packet_count=self.payload_packet_count,
            stream_base_sequence=self._space.to_sequence(base) if self._space else None,
            base_status=EvidenceStatus.OBSERVED
            if self._syn_ext is not None
            else EvidenceStatus.INFERRED,
            base_basis="TCP_SYN" if self._syn_ext is not None else "LOWEST_OBSERVED_SEQUENCE",
            bytes_reconstructed=bytes_reconstructed,
            highest_offset_observed=highest_end,
            runs=runs,
            segments=segments,
            gaps=tuple(gaps),
            overlap_conflicts=conflicts,
            retransmission_count=self.retransmission_count,
            duplicate_count=self.duplicate_count,
            out_of_order_count=self.out_of_order_count,
            dropped_by_limit_count=self.dropped_by_limit_count,
            truncated_by_limit=self.truncated_by_limit,
            fin_observed=self.fin_observed,
            rst_observed=self.rst_observed,
            highest_ack_observed=self._peer_ack_ext,
        )

    def _emit_gap_warnings(self, gaps: list[ReassemblyGap]) -> None:
        for gap in gaps:
            self._sink.add(
                WarningCode.SEQUENCE_GAP,
                f"{gap.length} bytes are missing from the {self.direction.value} stream at "
                f"offset {gap.stream_offset}; their contents are UNKNOWN and the surrounding "
                "data must not be treated as contiguous.",
                session_id=self._session_id,
                packet_refs=tuple(
                    ref for ref in (gap.preceding_packet, gap.following_packet) if ref
                ),
                gap_offset=gap.stream_offset,
                gap_length=gap.length,
                reason=gap.reason.value,
            )

    def _emit_acked_not_captured(self, base: int) -> None:
        if self._peer_ack_ext is None or self._max_end_ext is None:
            return
        acked_end = self._peer_ack_ext - (1 if self.fin_observed else 0)
        missing = acked_end - self._max_end_ext
        if missing > 0:
            self._sink.add(
                WarningCode.ACKED_DATA_NOT_CAPTURED,
                f"The peer acknowledged {missing} bytes beyond the furthest byte captured in "
                f"the {self.direction.value} stream, so data was sent that this capture does "
                "not contain.",
                session_id=self._session_id,
                missing_bytes=int(missing),
                stream_end_offset=int(self._max_end_ext - base),
            )
