"""Unit tests for the gap-safe line reader, redaction filters and TLS framing."""

from __future__ import annotations

import pytest

from securemailscope.config import AnalysisConfig
from securemailscope.diagnostics import WarningSink
from securemailscope.models.evidence import PacketReference, WarningCode
from securemailscope.models.protocol import TLSContentType, TLSFramingEvidence
from securemailscope.models.tcp import (
    Direction,
    DirectionalStream,
    Endpoint,
    OverlapConflict,
    ReassembledSegment,
)
from securemailscope.protocols.framing import probe_tls_records
from securemailscope.protocols.reader import (
    DialogueDriver,
    DirectionalBuffer,
    StreamCursor,
    merge_span,
)
from securemailscope.protocols.redaction import (
    IMAP_VERBS,
    POP3_VERBS,
    SMTP_VERBS,
    safe_capability,
    safe_mechanism,
    safe_reply_code,
    safe_tag,
    safe_verb,
)
from securemailscope.testing.tls_blobs import (
    application_data,
    client_hello,
    not_tls_binary,
    server_hello,
    truncated_client_hello,
)

CLIENT = Endpoint(ip="192.0.2.10", port=49152)
SERVER = Endpoint(ip="198.51.100.25", port=25)


def _reference(number: int) -> PacketReference:
    return PacketReference.create(number, 1_704_067_200_000_000_000 + number * 1_000_000)


def _stream(
    runs: list[tuple[int, bytes]],
    *,
    conflicts: tuple[OverlapConflict, ...] = (),
    direction: Direction = Direction.CLIENT_TO_SERVER,
) -> DirectionalStream:
    """A DirectionalStream whose segments map one packet per run."""
    segments = tuple(
        ReassembledSegment(
            stream_offset=offset,
            length=len(data),
            sequence_number=1000 + offset,
            source=_reference(index + 1),
        )
        for index, (offset, data) in enumerate(runs)
    )
    return DirectionalStream(
        direction=direction,
        source=CLIENT if direction is Direction.CLIENT_TO_SERVER else SERVER,
        destination=SERVER if direction is Direction.CLIENT_TO_SERVER else CLIENT,
        segments=segments,
        overlap_conflicts=conflicts,
    )


def _cursor(
    runs: list[tuple[int, bytes]],
    *,
    config: AnalysisConfig | None = None,
    conflicts: tuple[OverlapConflict, ...] = (),
) -> tuple[StreamCursor, WarningSink]:
    sink = WarningSink(capture_id="sha256:test")
    buffer = DirectionalBuffer.build(
        Direction.CLIENT_TO_SERVER, runs, _stream(runs, conflicts=conflicts)
    )
    return (
        StreamCursor(buffer, config or AnalysisConfig(), sink, "sess-test"),
        sink,
    )


def _drain(cursor: StreamCursor) -> list[tuple[int, int, bytes, bool]]:
    lines = []
    while (line := cursor.advance()) is not None:
        lines.append((line.start_offset, line.end_offset, line.content, line.complete))
    return lines


# -- line splitting ----------------------------------------------------------
def test_multiple_commands_in_one_segment_are_separate_lines() -> None:
    cursor, _ = _cursor([(0, b"EHLO a\r\nSTARTTLS\r\nQUIT\r\n")])
    assert _drain(cursor) == [
        (0, 8, b"EHLO a", True),
        (8, 18, b"STARTTLS", True),
        (18, 24, b"QUIT", True),
    ]


def test_bare_lf_is_accepted_and_recorded() -> None:
    cursor, _ = _cursor([(0, b"NOOP\nQUIT\r\n")])
    cursor_lines = []
    while (line := cursor.advance()) is not None:
        cursor_lines.append((line.content, line.terminator))
    assert cursor_lines == [(b"NOOP", b"\n"), (b"QUIT", b"\r\n")]


def test_crlf_split_across_segments_is_joined_by_reassembly() -> None:
    """Segments inside one run are contiguous, so a split CRLF is not a gap."""
    cursor, _ = _cursor([(0, b"STARTTLS\r" + b"\n")])
    lines = _drain(cursor)
    assert lines == [(0, 10, b"STARTTLS", True)]


def test_offsets_are_absolute_not_run_relative() -> None:
    cursor, _ = _cursor([(100, b"QUIT\r\n")])
    assert _drain(cursor) == [(100, 106, b"QUIT", True)]


# -- gaps --------------------------------------------------------------------
def test_line_is_never_assembled_across_a_gap() -> None:
    cursor, sink = _cursor([(0, b"STAR"), (10, b"TTLS\r\n")])
    first = cursor.advance()
    second = cursor.advance()
    assert first is not None and second is not None
    assert first.content == b"STAR"
    assert first.complete is False, "the run ended mid-line"
    assert second.content == b"TTLS"
    assert second.preceded_by_gap is True
    assert second.gap_length == 6
    assert WarningCode.PROTOCOL_GAP_IN_DIALOGUE in {w.code for w in sink.collect()}


def test_unterminated_tail_at_end_of_capture_is_not_a_gap() -> None:
    cursor, sink = _cursor([(0, b"EHLO client.example")])
    line = cursor.advance()
    assert line is not None
    assert line.complete is False
    assert line.preceded_by_gap is False
    assert WarningCode.PROTOCOL_GAP_IN_DIALOGUE not in {w.code for w in sink.collect()}


# -- bounds ------------------------------------------------------------------
def test_oversized_line_is_truncated_and_resynchronises() -> None:
    config = AnalysisConfig(max_line_bytes=16)
    payload = b"A" * 40 + b"\r\n" + b"QUIT\r\n"
    cursor, sink = _cursor([(0, payload)], config=config)

    first = cursor.advance()
    assert first is not None
    assert first.truncated is True
    assert first.complete is False
    assert len(first.content) == 16
    assert first.usable is False

    # Parsing resumes at the next terminator rather than mid-line.
    second = cursor.advance()
    assert second is not None
    assert second.content == b"QUIT"
    assert second.complete is True
    assert WarningCode.LIMIT_LINE_BYTES in {w.code for w in sink.collect()}


def test_line_limit_bounds_memory_on_a_stream_with_no_terminator() -> None:
    config = AnalysisConfig(max_line_bytes=32)
    cursor, _ = _cursor([(0, b"X" * 100_000)], config=config)
    line = cursor.advance()
    assert line is not None
    assert len(line.content) == 32
    assert cursor.advance() is None, "the rest is skipped, not buffered"


# -- literals ----------------------------------------------------------------
def test_skip_bytes_consumes_exactly_the_declared_length() -> None:
    cursor, _ = _cursor([(0, b"a001 APPEND {5+}\r\nHELLO\r\na002 NOOP\r\n")])
    first = cursor.advance()
    assert first is not None and first.content.endswith(b"{5+}")
    outcome = cursor.skip_bytes(5)
    assert outcome.complete is True
    assert outcome.skipped == 5
    assert outcome.start_offset == 18
    assert outcome.end_offset == 23
    remaining = _drain(cursor)
    assert remaining[-1][2] == b"a002 NOOP"


def test_skip_bytes_stops_at_a_gap_and_says_so() -> None:
    cursor, _ = _cursor([(0, b"a001 APPEND {40+}\r\nSHORT"), (200, b"a002 NOOP\r\n")])
    cursor.advance()
    outcome = cursor.skip_bytes(40)
    assert outcome.complete is False
    assert outcome.stopped_at_gap is True
    assert outcome.skipped == 5


def test_skip_bytes_stops_at_end_of_capture() -> None:
    cursor, _ = _cursor([(0, b"a001 APPEND {40+}\r\nSHORT")])
    cursor.advance()
    outcome = cursor.skip_bytes(40)
    assert outcome.complete is False
    assert outcome.stopped_at_end is True
    assert outcome.stopped_at_gap is False


# -- ambiguity ---------------------------------------------------------------
def test_bytes_from_an_overlap_conflict_are_flagged_ambiguous() -> None:
    conflict = OverlapConflict(
        stream_offset=2,
        length=4,
        accepted_packet=_reference(1),
        conflicting_packet=_reference(2),
        accepted_sha256="a" * 64,
        conflicting_sha256="b" * 64,
    )
    cursor, sink = _cursor([(0, b"STARTTLS\r\n")], conflicts=(conflict,))
    line = cursor.advance()
    assert line is not None
    assert line.ambiguous is True
    assert line.usable is False, "ambiguous bytes are not usable protocol evidence"
    assert WarningCode.PROTOCOL_AMBIGUOUS_BYTES in {w.code for w in sink.collect()}


# -- ordering ----------------------------------------------------------------
def test_driver_interleaves_by_capture_order() -> None:
    client_runs = [(0, b"EHLO a\r\nSTARTTLS\r\n")]
    server_runs = [(0, b"220 ready\r\n")]
    sink = WarningSink(capture_id="sha256:test")
    config = AnalysisConfig()

    client_stream = _stream(client_runs, direction=Direction.CLIENT_TO_SERVER)
    server_stream = _stream(server_runs, direction=Direction.SERVER_TO_CLIENT)
    client = StreamCursor(
        DirectionalBuffer.build(Direction.CLIENT_TO_SERVER, client_runs, client_stream),
        config,
        sink,
        "sess-test",
    )
    server = StreamCursor(
        DirectionalBuffer.build(Direction.SERVER_TO_CLIENT, server_runs, server_stream),
        config,
        sink,
        "sess-test",
    )
    driver = DialogueDriver(client, server)
    order = []
    while (item := driver.next()) is not None:
        order.append((item.direction.value, item.line.content))
    # Both streams' first line is packet 1; the client wins the tie, then the
    # client's second line (also packet 1, higher offset) precedes the server's.
    assert order[0][0] == "CLIENT_TO_SERVER"
    assert {entry[1] for entry in order} == {b"EHLO a", b"STARTTLS", b"220 ready"}


def test_merge_span_covers_the_whole_multiline_record() -> None:
    cursor, _ = _cursor([(0, b"220-one\r\n220-two\r\n220 three\r\n")])
    lines = [cursor.advance(), cursor.advance(), cursor.advance()]
    assert all(line is not None for line in lines)
    span = merge_span([line for line in lines if line is not None])
    assert span.start_offset == 0
    assert span.end_offset == 29, "the span must end after the FINAL line"
    assert len(span.packet_refs) >= 1


# -- redaction ---------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "allowed", "expected"),
    [
        (b"EHLO", SMTP_VERBS, "EHLO"),
        (b"starttls", SMTP_VERBS, "STARTTLS"),
        (b"PASS", POP3_VERBS, "PASS"),
        (b"LOGIN", IMAP_VERBS, "LOGIN"),
        # A base64 credential blob is alphanumeric and short. It must not pass.
        (b"dXNlcgBteXBhc3N3b3Jk", SMTP_VERBS, None),
        (b"aGVsbG8", POP3_VERBS, None),
        (b"NotARealPassword123", POP3_VERBS, None),
        (b"", SMTP_VERBS, None),
        (b"\xff\xfe", SMTP_VERBS, None),
    ],
)
def test_safe_verb_only_accepts_known_protocol_keywords(
    raw: bytes, allowed: frozenset[str], expected: str | None
) -> None:
    assert safe_verb(raw, allowed) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"PLAIN", "PLAIN"),
        (b"cram-md5", "CRAM-MD5"),
        (b"XOAUTH2", "XOAUTH2"),
        (b"dXNlcgBwdw==", None),
        (b"NotARealPassword123", None),
    ],
)
def test_safe_mechanism_only_accepts_known_sasl_names(
    raw: bytes, expected: str | None
) -> None:
    assert safe_mechanism(raw) == expected


def test_safe_tag_and_capability_and_reply_code() -> None:
    assert safe_tag(b"a001") == "a001"
    assert safe_tag(b"tag with space") is None
    assert safe_capability(b"AUTH=PLAIN") == "AUTH=PLAIN"
    assert safe_capability(b"has space") is None
    assert safe_reply_code(b"220") == "220"
    assert safe_reply_code(b"22") is None
    assert safe_reply_code(b"2x0") is None


# -- TLS framing -------------------------------------------------------------
def _probe(data: bytes, max_records: int = 8):
    runs = [(0, data)]
    buffer = DirectionalBuffer.build(Direction.CLIENT_TO_SERVER, runs, _stream(runs))
    return probe_tls_records(
        buffer, 0, direction=Direction.CLIENT_TO_SERVER, max_records=max_records
    )


def test_client_hello_is_recognised_as_strong_evidence() -> None:
    records = _probe(client_hello())
    assert len(records) == 1
    record = records[0]
    assert record.evidence is TLSFramingEvidence.HANDSHAKE_CLIENT_HELLO
    assert record.status.value == "OBSERVED"
    assert record.content_type_name is TLSContentType.HANDSHAKE
    assert record.handshake_type_name == "CLIENT_HELLO"
    assert record.complete is True
    assert record.limitations, "framing evidence must state what it does not prove"


def test_server_hello_is_recognised() -> None:
    records = _probe(server_hello())
    assert records[0].evidence is TLSFramingEvidence.HANDSHAKE_SERVER_HELLO


def test_truncated_record_is_reported_incomplete_not_dropped() -> None:
    records = _probe(truncated_client_hello(40))
    assert len(records) == 1
    assert records[0].complete is False
    assert records[0].bytes_available < records[0].declared_length
    assert any("declared record bytes" in text for text in records[0].limitations)


def test_a_lone_application_data_header_is_weak_evidence() -> None:
    records = _probe(application_data(16))
    assert len(records) == 1
    assert records[0].evidence is TLSFramingEvidence.SINGLE_RECORD_HEADER
    assert records[0].status.value == "INFERRED"


def test_two_chained_records_upgrade_the_evidence() -> None:
    records = _probe(application_data(16) + application_data(16))
    assert len(records) == 2
    assert records[0].evidence is TLSFramingEvidence.RECORD_CHAIN
    assert records[0].status.value == "OBSERVED"


def test_non_tls_binary_is_rejected() -> None:
    assert _probe(not_tls_binary()) == ()


def test_plaintext_is_never_mistaken_for_tls() -> None:
    assert _probe(b"220 mail.example ESMTP ready\r\n") == ()
    assert _probe(b"+OK POP3 server ready\r\n") == ()
    assert _probe(b"* OK IMAP4rev1 Service Ready\r\n") == ()


def test_record_probe_is_bounded() -> None:
    records = _probe(application_data(8) * 20, max_records=3)
    assert len(records) == 3
