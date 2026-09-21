# Requirements matrix — SIH26159

Maps every requirement to the module that implements it, the milestone that
owns it, its acceptance criterion, the test that verifies it, and its **actual**
status.

> **Provenance of this list.** The requirements below are derived from the
> SecureMailScope product definition and the M0/M1 implementation directive.
> The canonical SIH26159 problem statement text is not reproduced here; when it
> is attached to the repository, this table must be reconciled against it line
> by line and any requirement missing from this list added with status
> `NOT IMPLEMENTED`.

## Status vocabulary

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Built, tested against hand-derived expectations, and working |
| **PARTIAL** | Something real exists but the requirement is not met in full; the gap is stated |
| **NOT IMPLEMENTED** | No code exists. Not started. |

Nothing in this table is marked complete on the strength of a placeholder
module. Five packages (`tls/`, `certificates/`, `assessment/`,
`intelligence/`, `ml/`) still contain no code at all -- only a docstring
stating their status and the milestone that owns them.

---

## F1 — Capture ingestion

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F1.1 | Read PCAP files | `ingestion/pcap_reader.py` | M1 | All four libpcap magic variants parsed; packets and timestamps exact | `test_ingestion.py::test_packet_numbering_and_timestamps_are_exact` | **IMPLEMENTED** |
| F1.2 | Read PCAPNG files | `ingestion/pcapng_reader.py` | M1 | SHB/IDB/EPB/SPB, multi-section, per-interface `if_tsresol` | `test_ingestion.py::test_pcapng_preserves_nanosecond_precision` | **IMPLEMENTED** |
| F1.3 | Detect format from contents, not extension | `ingestion/formats.py` | M1 | A pcapng named `.pcap` is detected as pcapng and vice versa | `test_formats.py::test_extension_is_irrelevant` | **IMPLEMENTED** |
| F1.4 | Validate input before parsing | `ingestion/reader.py` | M1 | Missing / directory / empty / oversized / non-capture each raise a distinct error | `test_ingestion.py` (5 rejection tests) | **IMPLEMENTED** |
| F1.5 | Stream packets; do not load the capture into memory | `ingestion/reader.py` | M1 | One packet record resident at a time | Design; `CaptureSource.frames()` is a generator | **IMPLEMENTED** |
| F1.6 | Reject malformed files gracefully | `ingestion/*` | M1 | Truncated file yields partial results plus a diagnostic, never an exception | `test_ingestion.py::test_truncated_capture_yields_partial_results_not_an_exception` | **IMPLEMENTED** |
| F1.7 | Stable packet numbers in capture order | `ingestion/frames.py` | M1 | 1-based, contiguous, matches Wireshark frame numbers | `test_ingestion.py::test_packet_numbering_and_timestamps_are_exact` | **IMPLEMENTED** |
| F1.8 | Preserve original timestamps with sufficient precision | `models/evidence.py` | M1 | Nanosecond values survive; `timestamp` is timezone-aware UTC | `test_ingestion.py::test_pcapng_preserves_nanosecond_precision`, `::test_timestamps_are_timezone_aware` | **IMPLEMENTED** |
| F1.9 | Capture identifier from SHA-256 of original bytes | `ingestion/reader.py` | M1 | `capture_id == "sha256:" + sha256(file)` | `test_ingestion.py::test_capture_id_is_the_sha256_of_the_file` | **IMPLEMENTED** |
| F1.10 | Store capture metadata (format, size, counts, time range, warnings) | `models/capture.py` | M1 | All fields present in the report | `test_cli.py::test_analyze_writes_a_json_report` | **IMPLEMENTED** |
| F1.11 | Support Ethernet and IPv4/IPv6 TCP | `ingestion/dissect.py` | M1 | Both address families reconstructed | `test_sessions.py::test_ipv6_sessions_are_reconstructed` | **IMPLEMENTED** |
| F1.12 | Unsupported link types produce diagnostics, not fabricated sessions | `ingestion/linktypes.py` | M1 | Link type 105 → diagnostic, zero sessions | `test_ingestion.py::test_unsupported_link_type_produces_a_diagnostic_not_a_session` | **IMPLEMENTED** |
| F1.13 | Do not store or display payloads by default | `reporting/json_report.py` | M1 | Fixture payload text never appears in a report | `test_report.py::test_report_never_contains_payload_bytes` | **IMPLEMENTED** |
| F1.14 | Additional encapsulations (VLAN, SLL, loopback) | `ingestion/dissect.py` | M1 | Headers walked correctly | Implemented; **no dedicated fixture** — see `test-strategy.md` | **PARTIAL** |
| F1.15 | IP fragment reassembly | — | deferred | — | — | **NOT IMPLEMENTED** (detected and reported, not reassembled) |

## F2 — Resource limits

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F2.1 | Maximum capture size | `config.py` | M1 | Rejected before parsing | `test_ingestion.py::test_oversized_capture_is_rejected_before_parsing` | **IMPLEMENTED** |
| F2.2 | Maximum packet count | `ingestion/reader.py` | M1 | Stops at the limit, marks truncated | `test_ingestion.py::test_packet_count_limit_stops_parsing` | **IMPLEMENTED** |
| F2.3 | Maximum individual packet size | `ingestion/pcap_reader.py` | M1 | Refused on the header, before the read | `test_ingestion.py::test_packet_size_limit_stops_parsing`, `::test_absurd_declared_packet_length_does_not_allocate` | **IMPLEMENTED** |
| F2.4 | Maximum total reconstructed payload | `network/budget.py` | M1 | Enforced across all sessions | `test_ingestion.py::test_total_payload_limit_is_enforced_across_sessions` | **IMPLEMENTED** |
| F2.5 | Maximum per-session payload | `network/budget.py` | M1 | Prefix retained, session marked `TRUNCATED` | `test_ingestion.py::test_session_payload_limit_truncates_rather_than_dropping` | **IMPLEMENTED** |
| F2.6 | Maximum concurrent sessions | `network/sessions.py` | M1 | New connections refused with a diagnostic | `test_ingestion.py::test_concurrent_session_limit_refuses_new_connections` | **IMPLEMENTED** |
| F2.7 | Documented defaults | `.env.example`, `threat-model.md` | M0 | Every limit documented with rationale | Doc review | **IMPLEMENTED** |
| F2.8 | Bounded segment provenance | `network/reassembly.py` | M1 | Segment records capped per direction | `test_ingestion.py::test_segment_limit_is_enforced` | **IMPLEMENTED** |

## F3 — TCP session reconstruction

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F3.1 | Identify flows by 5-tuple | `network/flows.py` | M1 | Order-independent normalisation, direction preserved | `test_sessions.py::test_normalisation_is_order_independent`, `::test_direction_is_preserved_after_normalisation` | **IMPLEMENTED** |
| F3.2 | Do not merge connections reusing a tuple | `network/sessions.py` | M1 | Two sessions, one flow id, distinct ISNs | `test_sessions.py::test_tuple_reuse_produces_two_sessions_on_one_flow` (fixture J) | **IMPLEMENTED** |
| F3.3 | Use connection lifecycle where available | `network/sessions.py` | M1 | Handshake and termination recorded with packet refs | `test_sessions.py::test_roles_are_observed_when_a_syn_is_present` | **IMPLEMENTED** |
| F3.4 | Record when the start was not observed | `network/sessions.py` | M1 | `MIDSTREAM` completeness, `INFERRED` roles and base | `test_sessions.py::test_midstream_capture_is_labelled_inferred` (fixture M) | **IMPLEMENTED** |
| F3.5 | In-order segments | `network/reassembly.py` | M1 | Byte-exact reconstruction | `test_reassembly.py` (fixtures A, B) | **IMPLEMENTED** |
| F3.6 | Out-of-order segments | `network/reassembly.py` | M1 | Contiguous stream; provenance in offset order | `test_reassembly.py` (fixture C) | **IMPLEMENTED** |
| F3.7 | Retransmissions | `network/reassembly.py` | M1 | Bytes not duplicated; counted as retransmission | `test_reassembly.py::test_retransmission_and_duplicate_are_distinguished` (fixture E) | **IMPLEMENTED** |
| F3.8 | Duplicate segments | `network/reassembly.py` | M1 | Byte-identical frame classified `DUPLICATE` | `test_reassembly.py::test_retransmission_and_duplicate_are_distinguished` (fixture D) | **IMPLEMENTED** |
| F3.9 | Segmentation across packet boundaries | `network/reassembly.py` | M1 | Three segments → identical stream to one | `test_reassembly.py::test_segmented_and_whole_payload_reconstruct_identically` (fixture B) | **IMPLEMENTED** |
| F3.10 | Overlapping segments | `network/reassembly.py` | M1 | Clipped; only novel bytes stored | `test_reassembly.py` (fixture H) | **IMPLEMENTED** |
| F3.11 | Conflicting overlapping bytes | `network/reassembly.py` | M1 | `OverlapConflict` with both digests and packet numbers; policy documented | `test_reassembly.py::test_overlap_conflict_keeps_the_first_observation` (fixture H) | **IMPLEMENTED** |
| F3.12 | Missing segments represented explicitly | `network/reassembly.py` | M1 | Two runs, one gap, contents `UNKNOWN` | `test_reassembly.py::test_gaps_are_not_concatenated` (fixture F) | **IMPLEMENTED** |
| F3.13 | Partial captures | `network/sessions.py` | M1 | Damage reported; intact prefix analysed | `test_ingestion.py::test_truncated_capture_yields_partial_results_not_an_exception` (fixture I1) | **IMPLEMENTED** |
| F3.14 | Termination and tuple reuse | `network/sessions.py` | M1 | FIN/FIN, RST and reuse all distinguished | `test_sessions.py` (fixture J) | **IMPLEMENTED** |
| F3.15 | SYN sequence consumption | `network/reassembly.py` | M1 | Stream offset 0 is ISN+1 | `test_reassembly.py` (`stream_base_sequence` asserted per fixture) | **IMPLEMENTED** |
| F3.16 | Sequence wraparound | `network/seqspace.py` | M1 | Continuous projection across 2³² | `test_seqspace.py::test_wraparound_is_projected_continuously` | **IMPLEMENTED** (unit-tested; no end-to-end fixture) |
| F3.17 | Documented overlap policy | `reassembly.py` docstring, `architecture.md` | M0/M1 | `FIRST_OBSERVED_WINS` stated and emitted in every conflict record | `test_reassembly.py` asserts `policy` field | **IMPLEMENTED** |
| F3.18 | Never silently concatenate across a gap | `network/reassembly.py` | M1 | No API joins runs; report exposes runs separately | `test_reassembly.py::test_gaps_are_not_concatenated` | **IMPLEMENTED** |
| F3.19 | Preserve provenance of reconstructed ranges | `models/tcp.py` | M1 | Exact packet numbers and timestamps per segment | `test_reassembly.py::test_sessions_match_manifest` (`segment_packets`) | **IMPLEMENTED** |
| F3.20 | Bound all buffering | `network/budget.py`, `reassembly.py` | M1 | Payload and segment ceilings enforced | `test_ingestion.py` limit tests | **IMPLEMENTED** |
| F3.21 | Explicit session completeness states | `models/tcp.py` | M1 | Four states plus a note per contributing reason | `test_reassembly.py` asserts `completeness` per fixture | **IMPLEMENTED** |
| F3.22 | Per-OS reassembly policy emulation | — | deferred | — | — | **NOT IMPLEMENTED** |
| F3.23 | TCP option interpretation (SACK, window scale, timestamps) | — | deferred | — | — | **NOT IMPLEMENTED** |

## F4 — Data contracts

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F4.1 | `CaptureMetadata` | `models/capture.py` | M1 | Typed, frozen, serialises | `test_report.py` | **IMPLEMENTED** |
| F4.2 | `PacketReference` | `models/evidence.py` | M1 | Packet number + aware timestamp + ns precision | `test_report.py::test_report_carries_packet_provenance` | **IMPLEMENTED** |
| F4.3 | `TCPFlow` | `models/tcp.py` | M1 | Endpoints, family, role status and basis | `test_sessions.py` | **IMPLEMENTED** |
| F4.4 | `TCPSession` | `models/tcp.py` | M1 | Handshake, termination, completeness, both directions | `test_reassembly.py` | **IMPLEMENTED** |
| F4.5 | `ReassembledSegment` | `models/tcp.py` | M1 | Offset, length, sequence, source packet, duplicates | `test_reassembly.py` | **IMPLEMENTED** |
| F4.6 | `ReassemblyGap` | `models/tcp.py` | M1 | Offset, length, reason, boundary packets, `UNKNOWN` contents | `test_reassembly.py` | **IMPLEMENTED** |
| F4.7 | `AnalysisWarning` | `models/evidence.py` | M1 | Stable code, severity, packet refs, typed details | `test_reassembly.py::test_warning_codes_match_manifest` | **IMPLEMENTED** |
| F4.8 | `Observation` | `models/evidence.py` | M1 | Value, status, capture/session id, refs, basis, limitations | `test_sessions.py::test_protocol_hints_are_labelled_as_hints` | **IMPLEMENTED** |
| F4.9 | Structured fields, not nested dictionaries | `models/*` | M1 | `extra="forbid"` on every model | Pydantic validation | **IMPLEMENTED** |
| F4.10 | Model supports later SMTP/IMAP/POP3/TLS work without breaking TCP | `network/sessions.py::payload_runs` | M1 | Runs handed out per direction with offsets | `test_reassembly.py::test_reconstructed_bytes_equal_expected_bytes` | **IMPLEMENTED** |
| F4.11 | Timezone-aware timestamps in public output | `models/evidence.py` | M1 | UTC `tzinfo` on every emitted datetime | `test_ingestion.py::test_timestamps_are_timezone_aware` | **IMPLEMENTED** |
| F4.12 | No sensitive payload in persistent reports | `reporting/json_report.py` | M1 | Payload text absent from serialised output | `test_report.py::test_report_never_contains_payload_bytes` | **IMPLEMENTED** |

## F5 — Analysis pipeline and CLI

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F5.1 | PCAP → sessions → JSON end to end | `pipeline.py` | M1 | Single call produces a complete report | `test_cli.py::test_analyze_writes_a_json_report` | **IMPLEMENTED** |
| F5.2 | `securemailscope analyze <capture> --output result.json` | `cli.py` | M1 | Exact command works; exit code 0 | `test_cli.py` | **IMPLEMENTED** |
| F5.3 | JSON includes metadata, ids, endpoints, packet refs, byte counts, status, gaps, warnings | `reporting/` | M1 | All present | `test_cli.py::test_analyze_reports_gaps_and_conflicts` | **IMPLEMENTED** |
| F5.4 | No fictitious TLS findings | whole engine | M1 | No TLS/certificate key appears in any report | `test_report.py::test_report_declares_stage_status_honestly` | **IMPLEMENTED** |
| F5.5 | Port-based protocol hints, clearly labelled | `protocols/hints.py` | M1 | `INFERRED`, `HINT:` prefix, explicit limitations. Retained on `TCPSession` for M1 compatibility; superseded by F6 detection | `test_sessions.py::test_protocol_hints_are_labelled_as_hints` | **IMPLEMENTED** |
| F5.6 | Output distinguishes facts, hints and unknowns | `models/evidence.py` | M1 | Four statuses used correctly throughout | `test_sessions.py`, `test_report.py` | **IMPLEMENTED** |
| F5.7 | Works with no LLM, server, database or frontend | package deps | M0/M1 | Only `scapy` and `pydantic` installed | `pyproject.toml`; suite runs standalone | **IMPLEMENTED** |
| F5.8 | Functional CLI entry point named `securemailscope` | `pyproject.toml` | M0 | Installed console script | `test_cli.py` (runs `python -m securemailscope`) | **IMPLEMENTED** |

## F6 — Email protocol analysis (M2)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F6.1 | Identify SMTP from payload | `protocols/smtp.py` | M2 | Greeting + command grammar + matched response ⇒ CONFIRMED | `test_protocols.py::test_detection_matches_manifest` (P_A, P_H) | **IMPLEMENTED** |
| F6.2 | Identify IMAP from payload | `protocols/imap.py` | M2 | Untagged greeting + tagged command/completion ⇒ CONFIRMED | `test_protocols.py` (P_D, P_Q) | **IMPLEMENTED** |
| F6.3 | Identify POP3 from payload | `protocols/pop3.py` | M2 | `+OK` greeting + matched command/response ⇒ CONFIRMED | `test_protocols.py` (P_F, P_R) | **IMPLEMENTED** |
| F6.4 | Identify on non-standard ports | `protocols/analyzer.py` | M2 | SMTP on 8025 CONFIRMED with no port hint | `test_protocols.py` (P_H) | **IMPLEMENTED** |
| F6.5 | Port disagreement resolved toward payload | `protocols/analyzer.py` | M2 | POP3 on 143 ⇒ POP3, `port_hint_agrees=false` | `test_protocols.py` (P_I) | **IMPLEMENTED** |
| F6.6 | Four-level detection status | `models/protocol.py` | M2 | CONFIRMED / PROBABLE / PORT_HINT / UNKNOWN with basis and evidence | `test_protocols.py::test_detection_matches_manifest` | **IMPLEMENTED** |
| F6.7 | A port never yields CONFIRMED | `protocols/analyzer.py` | M2 | Binary payload on 25/143/110 never CONFIRMED | `test_protocol_behaviour.py::test_a_conventional_port_alone_never_confirms` | **IMPLEMENTED** |
| F6.8 | Detect STARTTLS (SMTP) | `protocols/smtp.py` | M2 | Advertisement, command and 220 matched to the pending command | `test_protocols.py` (P_A, P_B, P_C) | **IMPLEMENTED** |
| F6.9 | Detect STARTTLS (IMAP) with tag matching | `protocols/imap.py` | M2 | Only a matching tagged OK accepts | `test_protocols.py` (P_D, P_E) | **IMPLEMENTED** |
| F6.10 | Detect STLS (POP3) | `protocols/pop3.py` | M2 | `+OK`/`-ERR` matched to the pending STLS | `test_protocols.py` (P_F, P_G) | **IMPLEMENTED** |
| F6.11 | Multiline SMTP replies | `protocols/smtp.py` | M2 | A reply completes only at its final line | `test_protocols.py` (P_C) | **IMPLEMENTED** |
| F6.12 | Intermediate replies do not complete a command | `protocols/smtp.py` | M2 | 354 and 334 keep the command outstanding | `test_protocol_behaviour.py::test_smtp_354_does_not_complete_the_data_command` | **IMPLEMENTED** |
| F6.13 | Reply matched to the right outstanding command | `protocols/base.py` | M2 | A 220 answering EHLO does not accept STARTTLS | `test_protocol_behaviour.py::test_a_220_answering_an_earlier_command_does_not_accept_starttls` | **IMPLEMENTED** |
| F6.14 | SMTP DATA body skipped, dot-stuffing handled | `protocols/smtp.py` | M2 | A body containing "STARTTLS" produces no upgrade | `test_protocols.py` (P_P) | **IMPLEMENTED** |
| F6.15 | IMAP literals skipped by declared length | `protocols/imap.py` | M2 | A literal containing a fake STARTTLS exchange produces no upgrade | `test_protocols.py` (P_Q) | **IMPLEMENTED** |
| F6.16 | POP3 multiline responses skipped | `protocols/pop3.py` | M2 | A retrieved message containing "STLS" produces no upgrade | `test_protocols.py` (P_R) | **IMPLEMENTED** |
| F6.17 | Detect implicit TLS (465/993/995) | `protocols/framing.py` | M2 | Record framing from the first byte; identity stays PORT_HINT | `test_protocol_behaviour.py::test_implicit_tls_on_993_is_a_port_hint_not_confirmed_imap` | **IMPLEMENTED** |
| F6.18 | Capability advertisement recorded separately from use | `protocols/*` | M2 | `UPGRADE_ADVERTISED` distinct from `UPGRADE_REQUESTED` | `test_protocols.py` (P_B) | **IMPLEMENTED** |
| F6.19 | Detect offered-but-unused STARTTLS as a *finding* | `intelligence/` | M5 | — | — | **NOT IMPLEMENTED** (the observations exist; the finding does not) |

## F9 — Gap-safe stream reading and protocol bounds (M2)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F9.1 | Commands split across TCP segments | `protocols/reader.py` | M2 | Reassembled run yields one line | `test_protocols.py` (P_S) | **IMPLEMENTED** |
| F9.2 | Multiple commands in one segment | `protocols/reader.py` | M2 | Three lines from one payload | `test_protocol_reader.py::test_multiple_commands_in_one_segment_are_separate_lines` | **IMPLEMENTED** |
| F9.3 | CRLF split across segments | `protocols/reader.py` | M2 | Line still complete | `test_protocol_reader.py::test_crlf_split_across_segments_is_joined_by_reassembly` | **IMPLEMENTED** |
| F9.4 | Original stream offsets preserved | `protocols/reader.py` | M2 | Absolute, not run-relative | `test_protocol_reader.py::test_offsets_are_absolute_not_run_relative` | **IMPLEMENTED** |
| F9.5 | Packet provenance and timestamps preserved | `protocols/reader.py` | M2 | Every event carries packet refs and aware timestamps | `test_protocols.py::test_key_events_present_with_exact_offsets_and_provenance` | **IMPLEMENTED** |
| F9.6 | Maximum line size enforced | `protocols/reader.py` | M2 | Truncated, reported, resynchronised at next terminator | `test_protocol_reader.py::test_oversized_line_is_truncated_and_resynchronises` | **IMPLEMENTED** |
| F9.7 | Buffered data bounded | `protocols/reader.py` | M2 | 100 KB with no terminator does not buffer | `test_protocol_reader.py::test_line_limit_bounds_memory_on_a_stream_with_no_terminator` | **IMPLEMENTED** |
| F9.8 | Incomplete final lines supported | `protocols/reader.py` | M2 | Reported `complete=False`, not a gap | `test_protocol_reader.py::test_unterminated_tail_at_end_of_capture_is_not_a_gap` | **IMPLEMENTED** |
| F9.9 | Never concatenate across missing bytes | `protocols/reader.py` | M2 | Two lines, `preceded_by_gap`, gap length reported | `test_protocol_reader.py::test_line_is_never_assembled_across_a_gap` | **IMPLEMENTED** |
| F9.10 | Gap marks the record incomplete and invalidates state | `protocols/base.py` | M2 | Pending commands cleared, parse state INCOMPLETE | `test_protocols.py` (P_K) | **IMPLEMENTED** |
| F9.11 | Gap during negotiation prevents claiming success | `protocols/base.py` | M2 | State forced to `INCOMPLETE` even with TLS bytes present | `test_protocols.py` (P_K) | **IMPLEMENTED** |
| F9.12 | Ambiguous overlap bytes not used as evidence | `protocols/reader.py` | M2 | `ambiguous=True`, `usable=False`, diagnostic emitted | `test_protocol_reader.py::test_bytes_from_an_overlap_conflict_are_flagged_ambiguous` | **IMPLEMENTED** |
| F9.13 | IMAP literal bound enforced | `protocols/imap.py` | M2 | Oversized literal ⇒ INDETERMINATE, parsing stops | `test_protocol_behaviour.py::test_oversized_imap_literal_stops_parsing` | **IMPLEMENTED** |
| F9.14 | Message body bound enforced | `protocols/smtp.py`, `pop3.py` | M2 | Oversized body ⇒ INDETERMINATE | `test_protocol_behaviour.py::test_oversized_data_body_stops_parsing` | **IMPLEMENTED** |
| F9.15 | Malformed records reported, never crash | `protocols/*` | M2 | `PARSE_DESYNCHRONISED` events | `test_protocol_behaviour.py::test_malformed_server_reply_is_reported_not_crashed` | **IMPLEMENTED** |

## F10 — TLS transition model (M2)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F10.1 | Explicit upgrade state model | `models/protocol.py` | M2 | 8 states, each distinguishable | `test_protocols.py::test_upgrade_state_and_boundaries_match_manifest` | **IMPLEMENTED** |
| F10.2 | Advertisement / request / response tracked separately | `models/protocol.py` | M2 | Three independent event fields | `test_protocols.py` | **IMPLEMENTED** |
| F10.3 | Server boundary = end of success reply | `protocols/base.py` | M2 | Multiline 220 ⇒ end of FINAL line | `test_protocols.py` (P_C) | **IMPLEMENTED** |
| F10.4 | Client boundary determined independently | `protocols/base.py` | M2 | `FIRST_TLS_RECORD`, or `NOT_OBSERVED` when nothing validates | `test_protocol_behaviour.py::test_client_boundary_is_not_assumed_to_be_the_command_end` | **IMPLEMENTED** |
| F10.5 | TLS bytes in the acceptance payload preserved | `protocols/base.py` | M2 | Boundary mid-payload; records forwarded | `test_protocols.py` (P_L) | **IMPLEMENTED** |
| F10.6 | Accepted-but-no-TLS-bytes distinguished | `protocols/base.py` | M2 | `UPGRADE_ACCEPTED` + diagnostic | `test_protocol_behaviour.py::test_no_plaintext_parsing_resumes_after_acceptance` | **IMPLEMENTED** |
| F10.7 | Truncated/malformed TLS bytes preserve uncertainty | `protocols/framing.py` | M2 | `complete=False`, limitation recorded | `test_protocol_reader.py::test_truncated_record_is_reported_incomplete_not_dropped` | **IMPLEMENTED** |
| F10.8 | No plaintext parsing after acceptance | `protocols/*` | M2 | Fake plaintext AUTH after the boundary is never parsed | `test_protocols.py` (P_N), `test_protocol_behaviour.py` | **IMPLEMENTED** |
| F10.9 | Rejected upgrade continues plaintext parsing | `protocols/*` | M2 | Session parsed to COMPLETE after 454/-ERR | `test_protocols.py` (P_B, P_G) | **IMPLEMENTED** |
| F10.10 | Handshake analysis explicitly not claimed | `models/protocol.py` | M2 | `handshake_analyzed=False` everywhere | `test_protocols.py`, `test_report.py` | **IMPLEMENTED** |
| F10.11 | Record framing validated and bounded | `protocols/framing.py` | M2 | Header + length checks; weak single headers marked INFERRED | `test_protocol_reader.py` (7 framing tests) | **IMPLEMENTED** |

## F11 — Authentication privacy (M2)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F11.1 | SMTP AUTH and continuations recognised | `protocols/smtp.py` | M2 | Verb, mechanism and continuation count recorded | `test_protocols.py` (P_M) | **IMPLEMENTED** |
| F11.2 | IMAP LOGIN and AUTHENTICATE recognised | `protocols/imap.py` | M2 | Observation produced | `test_protocols.py` (P_Q) | **IMPLEMENTED** |
| F11.3 | POP3 USER / PASS / APOP / AUTH recognised | `protocols/pop3.py` | M2 | Observations produced | `test_protocols.py` (P_R) | **IMPLEMENTED** |
| F11.4 | No credential material persisted anywhere | `protocols/redaction.py` | M2 | Dummy credentials absent from report, warnings and event details | `test_protocols.py::test_no_credential_material_reaches_the_report`, `test_cli.py::test_analyze_never_emits_credentials` | **IMPLEMENTED** |
| F11.5 | Unrecognised command tokens never echoed | `protocols/redaction.py` | M2 | Base64 blob in command position is not reported | `test_protocol_behaviour.py::test_unrecognised_command_token_is_not_echoed` | **IMPLEMENTED** |
| F11.6 | Pre-upgrade flag recorded | `models/protocol.py` | M2 | `occurred_before_tls_upgrade` + state at attempt | `test_protocols.py::test_authentication_observations_match_manifest` | **IMPLEMENTED** |
| F11.7 | Plaintext auth scored as a finding | `assessment/` | M4 | — | — | **NOT IMPLEMENTED** (observation only, by design) |

## F7 — TLS record and handshake analysis (M3)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F7.1 | TLS record framing over reconstructed streams | `tls/records.py` | M3 | Records framed with provenance; bounded | `test_tls.py::test_records_carry_provenance` | **IMPLEMENTED** |
| F7.2 | Records split across TCP segments | `tls/records.py` | M3 | Framed normally; all packets recorded | `test_tls.py` (T_I) | **IMPLEMENTED** |
| F7.3 | Multiple records in one segment | `tls/records.py` | M3 | Each framed separately | `test_tls.py` (T_A, T_K) | **IMPLEMENTED** |
| F7.4 | Partial record header / body | `tls/records.py` | M3 | `TRUNCATED_RECORD` with declared vs available | `test_tls.py` (T_L) | **IMPLEMENTED** |
| F7.5 | Do not parse through a TCP gap | `tls/records.py` | M3 | `ALIGNMENT_LOST_AT_GAP`; framing stops | `test_tls.py` (T_M) | **IMPLEMENTED** |
| F7.6 | Conflicting bytes not treated as evidence | `tls/records.py`, `analyzer.py` | M3 | `AMBIGUOUS_BYTES`; body never parsed | `test_tls.py` (T_N) | **IMPLEMENTED** |
| F7.7 | Malformed content type / invalid length | `tls/records.py` | M3 | `MALFORMED_RECORD`; framing stops | `test_tls.py` (T_Y) | **IMPLEMENTED** |
| F7.8 | Configurable record and buffer bounds | `config.py`, `tls/records.py` | M3 | Limits enforced with diagnostics | `test_tls_validation.py::test_record_count_limit_is_enforced` | **IMPLEMENTED** |
| F7.9 | Separate directional record streams | `tls/records.py` | M3 | Per-direction parse state and indices | `test_tls.py::test_session_shape_matches_manifest` | **IMPLEMENTED** |
| F7.10 | All four content types handled | `tls/analyzer.py` | M3 | handshake, alert, CCS, application_data | `test_tls.py` (T_A, T_Z, T_HRR) | **IMPLEMENTED** |
| F7.11 | TLS 1.3 compatibility CCS not read as TLS 1.2 | `tls/analyzer.py` | M3 | Recognised as compatibility; no TLS 1.2 inference | `test_tls.py` (T_HRR) | **IMPLEMENTED** |
| F7.12 | Encrypted TLS 1.3 application_data never parsed | `tls/analyzer.py` | M3 | Records framed, `body_interpreted` false | `test_tls.py::test_records_carry_provenance` | **IMPLEMENTED** |
| F7.13 | Handshake message spanning records | `tls/handshake.py` | M3 | Reassembled; contributing records recorded | `test_tls.py` (T_J) | **IMPLEMENTED** |
| F7.14 | Multiple messages in one record | `tls/handshake.py` | M3 | All reported separately | `test_tls.py` (T_K) | **IMPLEMENTED** |
| F7.15 | Message completeness tracked | `tls/handshake.py` | M3 | `complete=False`; not interpreted | `test_tls.py` (T_L, T_M) | **IMPLEMENTED** |
| F7.16 | TLS 1.2 encryption boundary at CCS | `tls/analyzer.py` | M3 | Direction goes dark at its own CCS | `test_tls.py` (T_A boundaries) | **IMPLEMENTED** |
| F7.17 | TLS 1.3 encryption boundary after ServerHello | `tls/analyzer.py` | M3 | Both directions; nothing after parsed | `test_tls.py` (T_D boundaries) | **IMPLEMENTED** |
| F7.18 | Unknown handshake types handled gracefully | `tls/handshake.py` | M3 | Numeric type reported with a limitation | Code path; `HANDSHAKE_TYPE_NAMES` fallback | **IMPLEMENTED** |
| F7.19 | No decryption; no key logs loaded | whole engine | M3 | No key material is read or accepted | `test_tls_validation.py::test_tls_analysis_opens_no_socket` | **IMPLEMENTED** |

## F12 — Version, cipher and key-exchange identification (M3)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F12.1 | Client-offered versions | `tls/analyzer.py` | M3 | From `supported_versions`, else legacy | `test_tls.py::test_version_negotiation_matches_manifest` | **IMPLEMENTED** |
| F12.2 | Server-selected version | `tls/analyzer.py` | M3 | Recorded with `selected_source` | same | **IMPLEMENTED** |
| F12.3 | TLS 1.3 from `supported_versions` only | `tls/analyzer.py` | M3 | Never from legacy or record-layer version | `test_tls_validation.py::test_tls13_version_comes_from_the_extension_not_legacy_version` | **IMPLEMENTED** |
| F12.4 | Offered ≠ selected | `models/tls.py` | M3 | Separate fields; UNKNOWN without ServerHello | `test_tls_validation.py::test_client_hello_alone_never_yields_a_negotiated_version` | **IMPLEMENTED** |
| F12.5 | GREASE and malformed extensions handled safely | `tls/extensions.py` | M3 | GREASE marked; malformed recorded and skipped | `test_tls_wire.py` | **IMPLEMENTED** |
| F12.6 | Offered and selected cipher suites | `tls/analyzer.py` | M3 | Exact numeric id plus registered name | `test_tls.py::test_cipher_suite_matches_manifest` | **IMPLEMENTED** |
| F12.7 | Unknown suite ids do not crash | `tls/registry.py` | M3 | Reported numerically, `known=false` | `test_tls_wire.py` | **IMPLEMENTED** |
| F12.8 | Documented, versioned suite registry | `tls/registry.py` | M3 | Source and revision emitted in every report | `test_tls.py::test_cipher_suite_matches_manifest` | **IMPLEMENTED** |
| F12.9 | TLS 1.2 suite decomposition | `tls/registry.py` | M3 | kx, auth, cipher, MAC from the suite | `test_tls.py` (T_A, T_C) | **IMPLEMENTED** |
| F12.10 | TLS 1.3 suites do not encode kx/auth | `tls/analyzer.py` | M3 | `decomposition_applicable=false`; fields empty | `test_tls_validation.py::test_tls13_cipher_suite_does_not_encode_key_exchange` | **IMPLEMENTED** |
| F12.11 | TLS 1.2 key exchange family identified | `tls/keyexchange.py` | M3 | RSA / DHE / ECDHE recognised | `test_tls.py` (T_A, T_C) | **IMPLEMENTED** |
| F12.12 | Ephemeral parameters extracted where safe | `tls/keyexchange.py` | M3 | Curve and public-key length from ServerKeyExchange | `test_tls.py` (T_A selected group) | **IMPLEMENTED** |
| F12.13 | Curve not inferred when unexposed | `tls/keyexchange.py` | M3 | `selected_group` absent with a limitation | `test_tls.py` (T_H) | **IMPLEMENTED** |
| F12.14 | TLS 1.3 groups, key_share, PSK modes | `tls/extensions.py`, `keyexchange.py` | M3 | Server key_share group extracted | `test_tls.py` (T_D) | **IMPLEMENTED** |
| F12.15 | HelloRetryRequest handled | `tls/handshake.py` | M3 | Distinguished by its special random; not a negotiation | `test_tls.py` (T_HRR) | **IMPLEMENTED** |
| F12.16 | PSK-only vs PSK+DHE distinguished | `tls/keyexchange.py` | M3 | `PSK` vs `PSK_EPHEMERAL` | `test_tls.py` (T_F) | **IMPLEMENTED** |
| F12.17 | TLS 1.3 not automatically forward secret | `tls/forward_secrecy.py` | M3 | PSK-only ⇒ `PSK_ONLY` | Code path + criteria text | **IMPLEMENTED** |
| F12.18 | ServerHello ≠ completed handshake | `tls/forward_secrecy.py` | M3 | `handshake_completion_observable` false always | `test_tls.py::test_no_handshake_is_ever_claimed_verified` | **IMPLEMENTED** |

## F13 — Forward secrecy (M3)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F13.1 | Dedicated forward-secrecy module | `tls/forward_secrecy.py` | M3 | Structured result with stated criteria | `test_tls.py::test_key_exchange_and_forward_secrecy_match_manifest` | **IMPLEMENTED** |
| F13.2 | Ephemeral observed vs capable | `tls/forward_secrecy.py` | M3 | Two distinct statuses | `test_tls.py` (T_A vs T_H) | **IMPLEMENTED** |
| F13.3 | Static RSA identified | `tls/forward_secrecy.py` | M3 | `STATIC_RSA_KEY_EXCHANGE` with RFC citation | `test_tls.py` (T_C) | **IMPLEMENTED** |
| F13.4 | PSK-only identified | `tls/forward_secrecy.py` | M3 | `PSK_ONLY` | Code path + T_F | **IMPLEMENTED** |
| F13.5 | Unknown on incomplete evidence | `tls/forward_secrecy.py` | M3 | `UNKNOWN_INCOMPLETE_EVIDENCE` | `test_tls.py` (T_G, T_Z) | **IMPLEMENTED** |
| F13.6 | Criteria documented per result | `models/tls.py` | M3 | `criteria` names the rule and the evidence | `test_tls.py` asserts non-empty | **IMPLEMENTED** |
| F13.7 | Scoring | `assessment/` | M4 | — | — | **NOT IMPLEMENTED** (by design) |

## F14 — Certificate extraction and validation (M3)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F14.1 | Extract from plaintext Certificate messages | `tls/analyzer.py` | M3 | TLS ≤ 1.2 chains decoded | `test_tls.py::test_certificates_match_manifest` | **IMPLEMENTED** |
| F14.2 | TLS 1.3 certificate reported unavailable | `tls/analyzer.py` | M3 | `ENCRYPTED_TLS13` with explanation, never a failure | `test_tls_validation.py::test_tls13_certificate_is_unavailable_not_missing` | **IMPLEMENTED** |
| F14.3 | Certificate-list and DER decoding | `tls/handshake.py`, `certificates/parse.py` | M3 | Both TLS 1.2 and 1.3 framings | `test_tls.py` | **IMPLEMENTED** |
| F14.4 | Fingerprint, subject, issuer, serial, dates | `certificates/parse.py` | M3 | All present and asserted | `test_tls.py::test_certificates_match_manifest` | **IMPLEMENTED** |
| F14.5 | Public key algorithm and size | `certificates/parse.py` | M3 | RSA/EC/Ed25519/Ed448/DSA; no invented bit length | `test_tls.py`, `test_tls_wire.py` | **IMPLEMENTED** |
| F14.6 | Signature algorithm and hash | `certificates/parse.py` | M3 | Both recorded | `test_tls.py` | **IMPLEMENTED** |
| F14.7 | SANs, BasicConstraints, KeyUsage, EKU, position | `certificates/parse.py` | M3 | All extracted | `test_tls.py` | **IMPLEMENTED** |
| F14.8 | Unsupported algorithms handled explicitly | `certificates/parse.py` | M3 | `supported=false` with a note | Code path | **IMPLEMENTED** |
| F14.9 | Bounded certificate count and size | `config.py`, `tls/handshake.py` | M3 | Limits enforced with notes | `test_tls_validation.py` (2 tests) | **IMPLEMENTED** |
| F14.10 | No raw DER/PEM in default reports | `models/certificates.py` | M3 | Fingerprint and size instead | `test_tls_validation.py::test_reports_never_contain_raw_certificate_bytes` | **IMPLEMENTED** |
| F14.11 | Five independent validation fields | `certificates/validate.py` | M3 | Separate statuses and explanations | `test_tls.py::test_validation_checks_are_independent_and_match_manifest` | **IMPLEMENTED** |
| F14.12 | Validity at capture timestamp | `certificates/validate.py` | M3 | `CAPTURE_TIME` mode; aware timestamps | `test_tls_validation.py` (4 date tests) | **IMPLEMENTED** |
| F14.13 | Optional current-time assessment, labelled | `certificates/validate.py` | M3 | Additive, separately identified | `test_tls_validation.py::test_current_time_assessment_is_additive_and_labelled` | **IMPLEMENTED** |
| F14.14 | Explicit trust store; no auto-fetch | `certificates/truststore.py` | M3 | `NOT_AVAILABLE` without one; no network | `test_tls_validation.py` (5 chain tests) | **IMPLEMENTED** |
| F14.15 | Established verification API used | `certificates/validate.py` | M3 | `cryptography.x509.verification` | same | **IMPLEMENTED** |
| F14.16 | Missing intermediate distinguished | `certificates/validate.py` | M3 | "chain appears incomplete" | `test_tls_validation.py::test_incomplete_chain_is_distinguished_from_an_invalid_one` | **IMPLEMENTED** |
| F14.17 | Trust store identified without paths | `models/certificates.py` | M3 | Anchor-set digest, count, policy | `test_tls_validation.py::test_chain_verifies_against_a_configured_trust_store` | **IMPLEMENTED** |
| F14.18 | Hostname needs an explicit identity | `certificates/validate.py` | M3 | Destination IP never used | `test_tls_validation.py::test_hostname_is_not_available_without_a_reference_identity` | **IMPLEMENTED** |
| F14.19 | SNI is evidence, not an expectation | `certificates/validate.py` | M3 | Opt-in only | `test_tls_validation.py::test_observed_sni_is_evidence_not_an_expectation` | **IMPLEMENTED** |
| F14.20 | Hostname outcomes distinguished | `certificates/validate.py` | M3 | Match / mismatch / no identity / unavailable / error | `test_tls_validation.py` (4 hostname tests) | **IMPLEMENTED** |
| F14.21 | Revocation never claimed | `certificates/validate.py` | M3 | Always `NOT_AVAILABLE` with explanation | `test_tls.py::test_validation_checks_are_independent_and_match_manifest` | **IMPLEMENTED** |
| F14.22 | Chain success ≠ non-revocation | `certificates/validate.py` | M3 | Stated in the chain check's limitations | same | **IMPLEMENTED** |
| F14.23 | Documented algorithm policy | `certificates/policy.py` | M3 | RFC-cited factual notes, no scores | `policy_notes` field | **IMPLEMENTED** |
| F14.24 | Certificate posture scoring | `assessment/` | M4 | — | — | **NOT IMPLEMENTED** (by design) |
| F14.25 | Revocation checking (OCSP/CRL) | — | never | — | — | **NOT IMPLEMENTED** (out of scope: no network) |

## F15 — TLS session lifecycle (M3)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F15.1 | Complete observable handshake sequences | `tls/analyzer.py` | M3 | `SERVER_FLIGHT_COMPLETE` | `test_tls.py` (T_A) | **IMPLEMENTED** |
| F15.2 | Partial captures | `tls/analyzer.py` | M3 | `CLIENT_HELLO_ONLY`, `SERVER_HELLO_WITHOUT_CLIENT_HELLO` | `test_tls.py` (T_G, T_H, T_X) | **IMPLEMENTED** |
| F15.3 | Aborted handshakes and alerts | `tls/analyzer.py` | M3 | `ABORTED_BY_ALERT` with decoded alert | `test_tls.py` (T_Z) | **IMPLEMENTED** |
| F15.4 | Encrypted alerts | `tls/analyzer.py` | M3 | Framing only, `encrypted=true` | Code path | **IMPLEMENTED** |
| F15.5 | TLS 1.2 resumption indicators | `tls/analyzer.py` | M3 | Session-id echo compared, ids not stored | `test_tls.py` (T_A resumption) | **IMPLEMENTED** |
| F15.6 | TLS 1.3 PSK resumption indicators | `tls/analyzer.py` | M3 | `likely_resumed` from offer + selection | `test_tls.py` (T_F) | **IMPLEMENTED** |
| F15.7 | No certificate is not a failure | `tls/analyzer.py` | M3 | `CertificateVisibility` states the cause | `test_tls.py::test_certificates_match_manifest` | **IMPLEMENTED** |
| F15.8 | Negotiation progress ≠ verified completion | `models/tls.py` | M3 | Constants asserted across every fixture | `test_tls.py::test_no_handshake_is_ever_claimed_verified` | **IMPLEMENTED** |

## F8 — Assessment, correlation, ML, reporting, UI

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F8.1 | Explainable security findings | `assessment/` | M4 | Every finding cites its observations and their statuses | — | **NOT IMPLEMENTED** |
| F8.2 | Posture scoring | `assessment/` | M4 | Score auditable back to packets | — | **NOT IMPLEMENTED** |
| F8.3 | Evidence-based correlation | `intelligence/` | M5 | Multi-session findings retain all contributing refs | — | **NOT IMPLEMENTED** |
| F8.4 | ML-assisted analysis | `ml/` | M6 | Local scikit-learn; output always `INFERRED` | — | **NOT IMPLEMENTED** |
| F8.5 | Forensic reports | `reporting/` | M1 / M4 | JSON implemented (schema 1.1.0, protocol layer included); narrative forensic report is M4 | `test_report.py` | **PARTIAL** |
| F8.6 | Local SQLite persistence | `backend/` | M7 | — | — | **NOT IMPLEMENTED** |
| F8.7 | FastAPI backend | `backend/` | M7 | — | — | **NOT IMPLEMENTED** |
| F8.8 | React + TypeScript + Vite frontend | `frontend/` | M8 | — | — | **NOT IMPLEMENTED** |

## NF — Non-functional

| ID | Requirement | Where | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| NF1 | Entirely passive; never contact captured hosts | `scapy_guard.py` | M1 | Neighbour resolution raises; no socket during analysis | `test_passive.py` | **IMPLEMENTED** |
| NF2 | No live domain scanning | whole engine | M1 | No DNS or HTTP client exists | `test_passive.py::test_analysis_opens_no_socket` | **IMPLEMENTED** |
| NF3 | No capture data sent to any external service | whole engine | M1 | No outbound client imported | `test_passive.py` | **IMPLEMENTED** |
| NF4 | Engine functions independently of any LLM | `pyproject.toml`, ADR 0001 | M0 | No model dependency; deterministic output | Whole suite | **IMPLEMENTED** |
| NF5 | No shell command built from a user-controlled filename | whole engine | M1 | No subprocess anywhere | `test_passive.py::test_shell_metacharacters_in_filename_are_harmless` | **IMPLEMENTED** |
| NF6 | No telemetry | whole engine | M1 | None exists | `test_passive.py` | **IMPLEMENTED** |
| NF7 | Type hints throughout | whole package | M1 | `mypy --disallow-untyped-defs` clean over 41 files | `make typecheck` | **IMPLEMENTED** |
| NF8 | Lint clean | whole package | M1 | `ruff` clean (E, F, W, I, UP, B, C4, SIM, RUF, S) | `make lint` | **IMPLEMENTED** |
| NF9 | Deterministic, reproducible fixtures | `testing/` | M1 | Captures byte-identical across runs; manifests record SHA-256 | `test_cli.py::test_fixture_generation_is_reproducible` | **IMPLEMENTED** |
| NF10 | No broad exception swallowing | whole package | M1 | No bare `except Exception` in the analysis path | Code review; `ruff` `B` rules | **IMPLEMENTED** |
| NF11 | Captures and secrets never committed | `.gitignore`, `scripts/check_staged.sh` | M0 | Both controls present and exercised | `make secrets-check` | **IMPLEMENTED** |
| NF12 | Reproducible execution commands | `Makefile`, `README.md` | M0 | Documented and working | Manual | **IMPLEMENTED** |
| NF13 | Pinned dependencies | `pyproject.toml` | M0 | Exact versions | — | **PARTIAL** (versions pinned; no hash-pinned lock file) |
| NF14 | Performance characterisation | — | deferred | — | — | **NOT IMPLEMENTED** (no benchmark has been run; no throughput figure is claimed anywhere) |

---

## Summary

| Status | Count | Change since M2 |
|---|---|---|
| IMPLEMENTED | 198 | +74 |
| PARTIAL | 3 | -1 |
| NOT IMPLEMENTED | 16 | -2 |
| **Total requirements tracked** | **217** | +71 |

As of M3 the implemented set covers capture ingestion, TCP reconstruction,
the email protocol layer, and the TLS layer: record framing, handshake
reassembly, version and cipher-suite identification, key-exchange analysis,
forward-secrecy observation, X.509 extraction and five independent validation
checks.

**Still not claimed anywhere:** security findings and scoring (F8.1–F8.2,
F13.7, F14.24), correlation (F8.3), ML (F8.4), backend and frontend
(F8.6–F8.8), and revocation checking (F14.25, permanently out of scope).

**Constants in every report M3 produces:**
`handshake_analyzed = false`, `handshakes_cryptographically_verified = 0`,
`revocation_checks_performed = 0`.
