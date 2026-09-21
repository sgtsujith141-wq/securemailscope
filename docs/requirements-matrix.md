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
| **NOT VERIFIED** | Code exists and may well work, but nothing in this repository proves it. Added in M8 to stop "the module exists" being read as "the requirement is met". |

Nothing in this table is marked complete on the strength of a placeholder
module, and nothing is marked complete merely because the relevant module
exists. Where the evidence is a module rather than a passing test, the status
is **NOT VERIFIED**.

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

## F16 — Security rule evaluation (M4)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F16.1 | Versioned, named policy | `assessment/policy.py` | M4 | `policy_id`, version, published date and fingerprint in every report | `test_assessment.py::test_the_policy_is_reported_with_its_own_caveats` | **IMPLEMENTED** |
| F16.2 | Four distinct rule outcomes | `assessment/rules.py` | M4 | `FAIL`/`PASS`/`UNKNOWN`/`NOT_APPLICABLE` all reachable and distinguished | `test_assessment.py::test_rule_outcomes_match_the_manifest` | **IMPLEMENTED** |
| F16.3 | `UNKNOWN` never becomes `PASS` | `assessment/rules.py` | M4 | Missing evidence yields `UNKNOWN`; only `FAIL` becomes a finding | `test_assessment.py::test_only_failures_become_findings` | **IMPLEMENTED** |
| F16.4 | Rule category A — TLS protocol version | `assessment/rules.py` | M4 | `TLS-PROTO-001..003` | `test_assessment.py` (manifest matrix) | **IMPLEMENTED** |
| F16.5 | Rule category B — cipher suite | `assessment/rules.py` | M4 | `TLS-CIPHER-001..006` | `test_assessment.py` (manifest matrix) | **IMPLEMENTED** |
| F16.6 | Rule category C — key exchange and forward secrecy | `assessment/rules.py` | M4 | `TLS-KEX-001..002` | `test_assessment.py` (manifest matrix) | **IMPLEMENTED** |
| F16.7 | Rule category D — certificate | `assessment/rules.py` | M4 | `CERT-001..007` | `test_assessment.py` (manifest matrix) | **IMPLEMENTED** |
| F16.8 | Rule category E — email transport | `assessment/rules.py` | M4 | `MAIL-001..007` | `test_assessment.py` (manifest matrix) | **IMPLEMENTED** |
| F16.9 | Every rule cites a standard, typed by kind | `assessment/catalog.py` | M4 | `PROTOCOL_REQUIREMENT` / `STANDARDS_RECOMMENDATION` / `PROJECT_POLICY` / `ENVIRONMENT_CHOICE` | `test_assessment.py::test_every_rule_result_is_explained` | **IMPLEMENTED** |
| F16.10 | Stable, deterministic finding identifiers | `assessment/evaluator.py` | M4 | Same inputs and policy give the same id; different policy criteria give a different one | `test_assessment.py::test_finding_ids_are_stable_and_distinct`, `::test_finding_id_changes_with_the_policy_version` | **IMPLEMENTED** |
| F16.11 | One weakness counted once | `assessment/evaluator.py` | M4 | De-duplication groups charge the most severe member only | `test_assessment.py::test_one_weakness_is_counted_once` | **IMPLEMENTED** |
| F16.12 | No fabricated packet references | `assessment/rules.py` | M4 | Every reference is in range and carries the capture's recorded timestamp | `test_assessment.py::test_every_finding_cites_a_real_packet` | **IMPLEMENTED** |
| F16.13 | Rules never re-parse captures or scan JSON with regexes | `assessment/` | M4 | Operates on typed models only | Code review; module imports | **IMPLEMENTED** |
| F16.14 | Operates without an LLM | `assessment/` | M4 | No model dependency anywhere in the package | `test_passive.py` | **IMPLEMENTED** |

## F17 — Explainable posture scoring (M4)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F17.1 | Published, checkable formula | `assessment/scoring.py` | M4 | `score = 100 * (W(E) - W(F)) / W(E)`, recomputable from the report | `test_assessment.py::test_score_follows_the_published_formula` | **IMPLEMENTED** |
| F17.2 | Missing observations cannot improve the score | `assessment/scoring.py` | M4 | `UNKNOWN` is excluded from both sides of the fraction | `test_assessment.py::test_unknown_evidence_cannot_improve_the_score` | **IMPLEMENTED** |
| F17.3 | `SCORE_UNAVAILABLE` below the coverage floor | `assessment/scoring.py` | M4 | Default floor 0.50; status and `null` score reported | `test_assessment.py::test_insufficient_evidence_produces_no_score` | **IMPLEMENTED** |
| F17.4 | Coverage reported separately from posture | `assessment/scoring.py` | M4 | `W(E)/W(A)` with the same denominator the score used | `test_assessment.py::test_coverage_arithmetic_is_consistent` | **IMPLEMENTED** |
| F17.5 | No double counting | `assessment/scoring.py` | M4 | At most one deduction per de-duplication group | `test_assessment.py::test_each_dedup_group_contributes_at_most_one_deduction` | **IMPLEMENTED** |
| F17.6 | Monotonicity in failures | `assessment/scoring.py` | M4 | A more heavily weighted failure never scores higher | `test_assessment.py::test_more_failures_never_raise_the_score` | **IMPLEMENTED** |
| F17.7 | Every deduction itemised | `assessment/scoring.py` | M4 | `deduction_detail` names group, weight and rule, and sums to the total | `test_assessment.py::test_severity_weights_are_reported_not_hidden` | **IMPLEMENTED** |
| F17.8 | Score never clamped into range | `assessment/scoring.py` | M4 | `F ⊆ E` makes `[0,100]` structural | `test_assessment.py::test_deductions_never_exceed_the_evaluated_weight` | **IMPLEMENTED** |
| F17.9 | Score presented as a project-defined metric | `docs/scoring-methodology.md` | M4 | Limitations carried in the report itself, not only in prose | `test_assessment.py::test_the_policy_is_reported_with_its_own_caveats` | **IMPLEMENTED** |
| F17.10 | Disabling a rule removes it from the population | `assessment/policy.py` | M4 | Not counted as a pass | `test_assessment.py::test_disabling_a_rule_removes_it_from_both_sides` | **IMPLEMENTED** |

## F18 — Threat prioritisation (M4)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F18.1 | Deterministic total order | `assessment/prioritization.py` | M4 | Dense ranks from 1; identical across runs | `test_assessment.py::test_prioritisation_is_a_total_order`, `::test_prioritisation_is_stable_across_runs` | **IMPLEMENTED** |
| F18.2 | Priority from a matrix, never a product | `assessment/prioritization.py` | M4 | Severity and confidence looked up, not multiplied | `test_assessment.py::test_priority_comes_from_the_matrix_not_a_product` | **IMPLEMENTED** |
| F18.3 | Severity order never violated | `assessment/prioritization.py` | M4 | A more severe finding is never ranked lower | `test_assessment.py::test_more_severe_findings_are_never_ranked_lower` | **IMPLEMENTED** |
| F18.4 | Asset criticality never inferred | `assessment/policy.py` | M4 | Operator-supplied only; unlabelled assets sort last within a band | `test_assessment.py::test_asset_criticality_is_never_invented` | **IMPLEMENTED** |
| F18.5 | Attack intent never inferred from configuration | `assessment/catalog.py` | M4 | A refused upgrade is described as configuration, with the alternative stated | `test_assessment.py::test_rejected_starttls_is_reported_as_configuration_not_attack` | **IMPLEMENTED** |

## F19 — Remediation guidance (M4)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F19.1 | Advice only for findings that were raised | `assessment/remediation.py` | M4 | Exactly the remediations the raised findings reference | `test_assessment.py::test_remediations_answer_findings_that_exist` | **IMPLEMENTED** |
| F19.2 | No dangling catalogue references | `assessment/catalog.py` | M4 | Every rule's remediation exists; every remediation is reachable | `test_assessment.py::test_the_catalogue_has_no_dangling_references` | **IMPLEMENTED** |
| F19.3 | Vendor-neutral, with validation steps | `assessment/catalog.py` | M4 | No product named; each entry states how to verify the fix | `test_assessment.py::test_remediations_answer_findings_that_exist` | **IMPLEMENTED** |
| F19.4 | No active remediation | whole engine | M4 | Nothing is applied; no connection is made | `test_passive.py` | **IMPLEMENTED** |
| F19.5 | No fictitious before-and-after scores | `assessment/` | M4 | No projected score exists in any model | Code review; `models/assessment.py` | **IMPLEMENTED** |
| F19.6 | Generated policy documents cannot drift | `scripts/generate_policy_docs.py` | M4 | Committed files match the generator | `test_assessment.py::test_the_generated_policy_documents_are_current` | **IMPLEMENTED** |

## F20 — Multi-capture analysis (M5)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F20.1 | Analyse several captures together | `intelligence/engine.py` | M5 | `analyze-batch` reuses the single-capture pipeline | `test_intelligence.py::test_cli_batch_analysis_end_to_end` | **IMPLEMENTED** |
| F20.2 | Capture identity and evidence preserved | `intelligence/engine.py` | M5 | Batched results identical to standalone ones | `test_intelligence.py::test_capture_evidence_survives_the_batch` | **IMPLEMENTED** |
| F20.3 | Duplicate captures detected by content hash | `intelligence/engine.py` | M5 | Same bytes under two names analysed once | `test_intelligence.py::test_a_duplicate_capture_is_analysed_once` | **IMPLEMENTED** |
| F20.4 | Failed captures never disappear | `intelligence/engine.py` | M5 | Recorded as `FAILED` with a reason and a warning | `test_intelligence.py::test_a_failed_capture_stays_in_the_inventory` | **IMPLEMENTED** |
| F20.5 | Empty captures handled explicitly | `intelligence/engine.py` | M5 | Recorded as `EMPTY` with a warning | Fixture manifests | **IMPLEMENTED** |
| F20.6 | Deterministic, order-independent output | `intelligence/engine.py` | M5 | Reversing the arguments changes nothing | `test_intelligence.py::test_results_do_not_depend_on_argument_order` | **IMPLEMENTED** |
| F20.7 | Stable investigation identifiers | `intelligence/engine.py` | M5 | Derived from the set of capture hashes | `test_intelligence.py::test_results_do_not_depend_on_argument_order` | **IMPLEMENTED** |
| F20.8 | Configurable batch resource limits | `config.py` | M5 | Captures, sessions, fingerprints, correlations, timeline events | `test_intelligence.py::test_the_capture_limit_warns_rather_than_dropping_silently` | **IMPLEMENTED** |
| F20.9 | Limits warn rather than truncate silently | `intelligence/engine.py` | M5 | Every limit emits an `IntelligenceWarning` | `test_intelligence.py::test_the_timeline_limit_warns_rather_than_truncating_silently` | **IMPLEMENTED** |
| F20.10 | No database server required | whole engine | M5 | Files in, JSON out | Whole suite | **IMPLEMENTED** |

## F21 — Cryptographic fingerprints (M5)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F21.1 | Versioned fingerprint algorithm | `intelligence/fingerprints.py` | M5 | `smsfp/1` in the canonical form and the id | `test_intelligence.py::test_canonical_form_is_ordered_and_versioned` | **IMPLEMENTED** |
| F21.2 | Deterministic canonicalisation | `intelligence/fingerprints.py` | M5 | Fixed component order; digest recomputable from the report | `test_intelligence.py::test_canonical_form_is_recomputable_from_the_report` | **IMPLEMENTED** |
| F21.3 | Component-level explanation stored with the hash | `intelligence/fingerprints.py` | M5 | Every component carries source, presence and explanation | `test_intelligence.py::test_a_missing_server_hello_cannot_produce_a_usable_fingerprint` | **IMPLEMENTED** |
| F21.4 | Client offers never become server components | `intelligence/fingerprints.py` | M5 | No component is `CLIENT_OFFERED` | `test_intelligence.py::test_client_offers_never_become_server_components` | **IMPLEMENTED** |
| F21.5 | Incidental material excluded | `intelligence/fingerprints.py` | M5 | No port, timestamp or session id contributes | `test_intelligence.py::test_fingerprints_exclude_incidental_session_material` | **IMPLEMENTED** |
| F21.6 | Explicit completeness metadata | `intelligence/fingerprints.py` | M5 | `COMPLETE` / `PARTIAL` / `INSUFFICIENT` plus missing components | `test_intelligence.py::test_absent_components_are_written_explicitly` | **IMPLEMENTED** |
| F21.7 | Missing information cannot fabricate completeness | `intelligence/fingerprints.py` | M5 | Absences written as `<ABSENT>`; TLS 1.3 never `COMPLETE` | `test_intelligence.py::test_two_tls13_sessions_never_reach_an_exact_match` | **IMPLEMENTED** |
| F21.8 | Four comparison outcomes | `intelligence/fingerprints.py` | M5 | Exact, partial, conflicting, insufficient | `test_intelligence.py::test_conflicting_components_are_named` | **IMPLEMENTED** |
| F21.9 | Partial agreement is not identity | `intelligence/fingerprints.py` | M5 | Carries the limitation; never `EXACT_MATCH` | `test_intelligence.py::test_two_tls13_sessions_never_reach_an_exact_match` | **IMPLEMENTED** |
| F21.10 | Configuration fingerprint excludes the certificate | `intelligence/fingerprints.py` | M5 | A renewal does not change it | `test_intelligence.py::test_configuration_fingerprint_ignores_the_certificate` | **IMPLEMENTED** |
| F21.11 | SubjectPublicKeyInfo fingerprint | `certificates/parse.py` | M5 | `spki_sha256` over the DER SPKI | `test_intelligence.py::test_a_renewal_is_distinguishable_from_a_rekey` | **IMPLEMENTED** |

## F22 — Server identity resolution (M5)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F22.1 | Entities are observed `(ip, port)` endpoints | `intelligence/identity.py` | M5 | Source ports do not multiply entities | `test_intelligence.py::test_entities_are_endpoints_not_connections` | **IMPLEMENTED** |
| F22.2 | Shared certificate never merges endpoints | `intelligence/identity.py` | M5 | Two entities, one typed relationship | `test_intelligence.py::test_a_shared_certificate_never_merges_endpoints` | **IMPLEMENTED** |
| F22.3 | Same IP is not the same application | `intelligence/identity.py` | M5 | Two ports are two entities | `test_intelligence.py::test_one_address_with_two_services_is_two_entities` | **IMPLEMENTED** |
| F22.4 | Seven typed identity relations | `models/intelligence.py` | M5 | Each names the property matched | `test_intelligence.py::test_identity_relations_match_expectation` | **IMPLEMENTED** |
| F22.5 | Every relationship carries evidence and limitations | `intelligence/identity.py` | M5 | Basis, supporting sessions, limitations | `test_intelligence.py::test_a_shared_certificate_never_merges_endpoints` | **IMPLEMENTED** |
| F22.6 | Weak evidence never merges entities | `intelligence/identity.py` | M5 | Identical config alone yields only `CONFIGURATION_MATCH` | `test_intelligence.py::test_identical_configuration_alone_is_not_a_relation_claim` | **IMPLEMENTED** |
| F22.7 | Stable, order-independent entity ids | `intelligence/identity.py` | M5 | Derived from the endpoint alone | `test_intelligence.py::test_entity_ids_are_stable_and_order_independent` | **IMPLEMENTED** |

## F23 — Cryptographic drift (M5)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F23.1 | Four drift statuses | `models/intelligence.py` | M5 | Observed / unchanged / inconclusive / not comparable | `test_intelligence.py::test_expected_drift_is_classified_correctly` | **IMPLEMENTED** |
| F23.2 | Missing evidence is never drift | `intelligence/drift.py` | M5 | A parameter absent in one capture is `NOT_COMPARABLE` | `test_intelligence.py::test_changes_the_evidence_does_not_support_are_absent` | **IMPLEMENTED** |
| F23.3 | Different client offers handled conservatively | `intelligence/drift.py` | M5 | `INCONCLUSIVE` with the offers recorded | `test_intelligence.py::test_a_different_client_offer_blocks_attribution` | **IMPLEMENTED** |
| F23.4 | Identical offers permit attribution | `intelligence/drift.py` | M5 | `OBSERVED_CHANGE` when the offer is constant | `test_intelligence.py::test_an_identical_client_offer_permits_attribution` | **IMPLEMENTED** |
| F23.5 | Certificate drift ignores the client offer | `intelligence/drift.py` | M5 | `client_offers_comparable` is null there | `test_intelligence.py::test_certificate_drift_does_not_consult_the_client_offer` | **IMPLEMENTED** |
| F23.6 | Renewal distinguishable from rekey | `intelligence/drift.py` | M5 | Certificate changes, public key does not | `test_intelligence.py::test_a_renewal_is_distinguishable_from_a_rekey` | **IMPLEMENTED** |
| F23.7 | Chronology from capture timestamps | `intelligence/drift.py` | M5 | Argument order is irrelevant | `test_intelligence.py::test_drift_follows_capture_time_not_argument_order` | **IMPLEMENTED** |
| F23.8 | Score drift only across compatible policies | `intelligence/drift.py` | M5 | Differing policy fingerprints give `NOT_COMPARABLE` | `test_intelligence.py::test_score_drift_across_different_policies_is_not_comparable` | **IMPLEMENTED** |
| F23.9 | A withheld score is reported as incomparable | `intelligence/drift.py` | M5 | Not silently omitted | `test_intelligence.py::test_a_withheld_score_is_reported_as_incomparable` | **IMPLEMENTED** |
| F23.10 | Score drift kept separate from cryptographic drift | `intelligence/drift.py` | M5 | Distinct kind, with its own limitations | `test_intelligence.py::test_every_drift_event_explains_and_qualifies_itself` | **IMPLEMENTED** |

## F24 — Correlation, timeline and blast radius (M5)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F24.1 | Eight correlation types over shared observations | `intelligence/correlation.py` | M5 | Each names its shared property and value | `test_intelligence.py::test_every_correlation_names_its_basis_and_its_limits` | **IMPLEMENTED** |
| F24.2 | Stable, order-independent correlation ids | `intelligence/correlation.py` | M5 | Derived from type and basis only | `test_intelligence.py::test_correlation_ids_are_stable_and_order_independent` | **IMPLEMENTED** |
| F24.3 | Evidence de-duplicated within a correlation | `intelligence/correlation.py` | M5 | Unique by packet number and timestamp | `test_intelligence.py::test_evidence_is_deduplicated_within_a_correlation` | **IMPLEMENTED** |
| F24.4 | No intent, ownership or topology inferred | `intelligence/correlation.py` | M5 | No accusatory language anywhere | `test_intelligence.py::test_correlations_never_claim_intent_or_ownership` | **IMPLEMENTED** |
| F24.5 | Mixed policy versions disclosed | `intelligence/correlation.py` | M5 | `policy_versions` plus an extra limitation | `test_intelligence.py::test_mixed_policy_versions_are_disclosed` | **IMPLEMENTED** |
| F24.6 | Bounded algorithms, no all-pairs comparison | `intelligence/correlation.py` | M5 | Grouping by index on the shared value | Code review; `correlation.py` | **IMPLEMENTED** |
| F24.7 | Deterministic timeline ordering | `intelligence/timeline.py` | M5 | Dense indices; stable for equal timestamps | `test_intelligence.py::test_timeline_ordering_is_stable_for_equal_timestamps` | **IMPLEMENTED** |
| F24.8 | Timeline events carry packet provenance | `intelligence/timeline.py` | M5 | Every reference in range with a real timestamp | `test_intelligence.py::test_timeline_events_carry_real_packet_provenance` | **IMPLEMENTED** |
| F24.9 | Derived events name their sources | `intelligence/engine.py` | M5 | `derived_from` populated; marked `INFERRED` | `test_intelligence.py::test_derived_timeline_events_name_their_sources` | **IMPLEMENTED** |
| F24.10 | No invented timestamps | `intelligence/timeline.py` | M5 | Unknown timing yields null, sorted last | `test_intelligence.py::test_no_timestamp_is_invented` | **IMPLEMENTED** |
| F24.11 | Clock limitations documented in the report | `intelligence/timeline.py` | M5 | Carried in `Investigation.limitations` | `test_intelligence.py::test_clock_limitations_are_stated` | **IMPLEMENTED** |
| F24.12 | Blast radius counts endpoints conservatively | `intelligence/blast_radius.py` | M5 | By `(ip, port)`, not by connection | `test_intelligence.py::test_blast_radius_counts_one_endpoint_per_service` | **IMPLEMENTED** |
| F24.13 | Duplicate captures do not inflate counts | `intelligence/blast_radius.py` | M5 | Counted by content hash | `test_intelligence.py::test_blast_radius_never_double_counts_a_duplicate_capture` | **IMPLEMENTED** |
| F24.14 | Counting method and scope stated | `intelligence/blast_radius.py` | M5 | Verbatim scope statement on every result | `test_intelligence.py::test_blast_radius_states_its_scope_and_method` | **IMPLEMENTED** |
| F24.15 | No enterprise-wide claim | `intelligence/blast_radius.py` | M5 | No such language anywhere | `test_intelligence.py::test_blast_radius_claims_nothing_about_the_wider_estate` | **IMPLEMENTED** |
| F24.16 | Business criticality never invented | `intelligence/blast_radius.py` | M5 | Not represented at all | `test_intelligence.py::test_blast_radius_states_its_scope_and_method` | **IMPLEMENTED** |
| F24.17 | Additive investigation output contract | `reporting/json_report.py` | M5 | Nine required blocks; capture reports unchanged | `test_intelligence.py::test_individual_capture_reports_are_preserved_unchanged` | **IMPLEMENTED** |
| F24.18 | No credential material in an investigation | whole engine | M5 | M2 redaction holds through the new layer | `test_intelligence.py::test_no_credential_material_reaches_an_investigation` | **IMPLEMENTED** |
| F24.19 | The intelligence layer opens no socket | whole engine | M5 | Passive, like every layer beneath it | `test_intelligence.py::test_the_engine_opens_no_socket` | **IMPLEMENTED** |

## F25 — ML dataset and ground truth (M6)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F25.1 | Reproducible dataset from fixed seeds | `ml/dataset.py` | M6 | Same seeds give the same servers, negotiations and labels | `test_ml.py::test_dataset_generation_is_reproducible` | **IMPLEMENTED** |
| F25.2 | Versioned dataset manifest with real counts | `docs/ml-dataset.md` | M6 | 608 sessions, 152 groups, actual class distribution | `test_ml.py::test_population_is_reproducible_and_spans_families` | **IMPLEMENTED** |
| F25.3 | Samples are real captures through the real pipeline | `ml/preprocessing.py` | M6 | Generator writes pcap; M1–M5 reconstructs it | `test_ml.py::test_feature_extraction_is_deterministic` | **IMPLEMENTED** |
| F25.4 | Controlled configuration families | `ml/dataset.py` | M6 | Seven families spanning TLS 1.2/1.3, suites, certificates, clients | `test_ml.py::test_population_is_reproducible_and_spans_families` | **IMPLEMENTED** |
| F25.5 | The class is not encoded by family or fixture name | `ml/dataset.py` | M6 | Families span several posture classes | `test_ml.py::test_no_family_is_a_proxy_for_the_label` | **IMPLEMENTED** |
| F25.6 | Forensic truth, policy label and ML label kept separate | `ml/dataset.py` | M6 | Three distinct concepts, documented | `test_ml.py::test_labels_are_not_derived_from_the_assessment_engine` | **IMPLEMENTED** |
| F25.7 | ML labels never derived from the M4 engine | `ml/preprocessing.py` | M6 | Assessment disabled while building; latent target | `test_ml.py::test_the_dataset_is_built_with_the_assessment_layer_off` | **IMPLEMENTED** |
| F25.8 | Held-out anomaly scenarios declared before training | `ml/dataset.py` | M6 | Injected-anomaly family and negative control fixed in code | `test_ml.py::test_rare_but_legitimate_configurations_are_not_flagged` | **IMPLEMENTED** |
| F25.9 | Realistic negative controls | `ml/dataset.py` | M6 | `hardened_uncommon`: rare, legitimate, labelled not anomalous | `test_ml.py::test_rare_but_legitimate_configurations_are_not_flagged` | **IMPLEMENTED** |
| F25.10 | No downloaded, private or confidential data | `ml/dataset.py` | M6 | Generated locally; no network in generation | `test_ml.py::test_inference_opens_no_socket` | **IMPLEMENTED** |
| F25.11 | Byte-level reproducibility limits disclosed | `ml/dataset.py` | M6 | Content digest plus a measured size profile | `test_ml.py::test_dataset_generation_is_reproducible` | **IMPLEMENTED** |

## F26 — Feature engineering (M6)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F26.1 | Versioned feature schema | `ml/features.py` | M6 | `smsfeat/1`, 93 columns, fixed order | `test_ml.py::test_every_feature_vector_has_the_schema_width` | **IMPLEMENTED** |
| F26.2 | Features derived from M1–M5 observations | `ml/features.py` | M6 | Every feature carries a provenance string | `test_ml.py::test_every_explanation_is_traceable_to_an_observation` | **IMPLEMENTED** |
| F26.3 | Categorical encoding; no raw code points as magnitudes | `ml/features.py` | M6 | One-hot against frozen vocabularies | `test_ml.py::test_feature_extraction_is_deterministic` | **IMPLEMENTED** |
| F26.4 | Missing values are not numeric zero | `ml/features.py` | M6 | Explicit `*_missing` indicator per numeric | `test_ml.py::test_missing_values_carry_an_indicator_not_a_zero` | **IMPLEMENTED** |
| F26.5 | UNKNOWN, NOT_AVAILABLE and NOT_APPLICABLE distinguished | `ml/features.py` | M6 | `AbsenceReason` as a feature | `test_ml.py::test_tls13_absent_certificate_is_not_the_same_as_a_missing_one` | **IMPLEMENTED** |
| F26.6 | No invented certificate properties for TLS 1.3 | `ml/features.py` | M6 | All certificate features MISSING, absence `NOT_AVAILABLE` | `test_ml.py::test_no_certificate_property_is_invented_for_tls13` | **IMPLEMENTED** |
| F26.7 | Minimum-evidence eligibility rule | `ml/features.py` | M6 | `ML_NOT_EVALUABLE` without version and suite | `test_ml.py::test_insufficient_evidence_is_not_evaluated` | **IMPLEMENTED** |
| F26.8 | Incomplete captures are not automatically anomalous | `ml/features.py` | M6 | Excluded by the gate, never scored | `test_ml.py::test_incomplete_captures_are_not_treated_as_anomalies` | **IMPLEMENTED** |
| F26.9 | Prohibited leakage features excluded | `ml/features.py` | M6 | No ids, hashes, scores, severities, names or addresses | `test_ml.py::test_prohibited_identifiers_are_absent_from_features` | **IMPLEMENTED** |
| F26.10 | Fingerprint digests never used as magnitudes | `ml/features.py` | M6 | Structure used; digest excluded | `test_ml.py::test_prohibited_identifiers_are_absent_from_features` | **IMPLEMENTED** |

## F27 — Training, splitting and leakage prevention (M6)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F27.1 | Split before fitting preprocessing | `ml/preprocessing.py` | M6 | Split first; scales are hand-set constants | `test_ml.py::test_splitting_is_group_aware` | **IMPLEMENTED** |
| F27.2 | Group-aware splitting by server instance | `ml/preprocessing.py` | M6 | No group in two partitions | `test_ml.py::test_splitting_is_group_aware` | **IMPLEMENTED** |
| F27.3 | Certificates never span partitions | `ml/preprocessing.py` | M6 | Grouping by server carries the certificate | `test_ml.py::test_no_certificate_spans_two_partitions` | **IMPLEMENTED** |
| F27.4 | Sessions from one configuration stay together | `ml/preprocessing.py` | M6 | All four sessions of a server on one side | `test_ml.py::test_duplicate_sessions_of_one_server_stay_together` | **IMPLEMENTED** |
| F27.5 | Held-out configuration-family test | `ml/preprocessing.py` | M6 | Two families withheld entirely | `test_ml.py::test_family_holdout_withholds_whole_families` | **IMPLEMENTED** |
| F27.6 | Train/validation/test partitions used correctly | `ml/training.py` | M6 | Selection on validation; test touched once | `test_ml.py::test_threshold_selection_uses_only_the_split_it_is_given` | **IMPLEMENTED** |
| F27.7 | Fixed, documented seeds | `ml/dataset.py`, `ml/preprocessing.py` | M6 | Population, session, split and model seeds | `test_ml.py::test_the_split_is_reproducible` | **IMPLEMENTED** |
| F27.8 | Training is reproducible | `ml/anomaly.py` | M6 | Same data and seed, identical scores | `test_ml.py::test_training_is_reproducible` | **IMPLEMENTED** |
| F27.9 | Small-sample limitations reported | `docs/ml-evaluation.md` | M6 | 31 test groups stated; no narrow intervals claimed | Documentation review | **IMPLEMENTED** |

## F28 — Models and evaluation (M6)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F28.1 | A genuine anomaly model is trained | `ml/anomaly.py` | M6 | Isolation Forest and a rarity baseline, both fitted | `test_ml.py::test_the_anomaly_detector_finds_the_injected_anomalies` | **IMPLEMENTED** |
| F28.2 | Algorithm choice justified by measurement | `docs/ml-methodology.md` | M6 | Baseline won on validation and ships | `test_ml.py::test_a_baseline_is_always_compared` | **IMPLEMENTED** |
| F28.3 | Threshold selected on validation and frozen | `ml/anomaly.py` | M6 | One rule, applied identically to both candidates | `test_ml.py::test_threshold_selection_respects_the_false_positive_cap` | **IMPLEMENTED** |
| F28.4 | Reference population recorded with the model | `ml/registry.py` | M6 | In every manifest and every report | `test_ml.py::test_manifests_record_reproducibility_metadata` | **IMPLEMENTED** |
| F28.5 | Four anomaly statuses | `models/ml.py` | M6 | ANOMALOUS / NOT_ANOMALOUS / NOT_EVALUABLE / MODEL_UNAVAILABLE | `test_ml.py::test_inference_abstains_on_insufficient_evidence` | **IMPLEMENTED** |
| F28.6 | Legitimate rare configurations not flagged | `ml/anomaly.py` | M6 | Zero false positives on the negative control | `test_ml.py::test_rare_but_legitimate_configurations_are_not_flagged` | **IMPLEMENTED** |
| F28.7 | Supervised classifier trained and compared | `ml/classification.py` | M6 | Baseline, logistic regression, random forest | `test_ml.py::test_classification_is_reported_as_not_validated` | **IMPLEMENTED** |
| F28.8 | Classification reported as NOT_VALIDATED | `ml/inference.py` | M6 | Status on every prediction, with reasons | `test_ml.py::test_classification_is_reported_as_not_validated` | **PARTIAL** (implemented and measured; not independently validated — by design, see model card) |
| F28.9 | No calibrated-probability claim | `ml/classification.py` | M6 | Relative scores; stated in the model card | `test_ml.py::test_classification_is_reported_as_not_validated` | **IMPLEMENTED** |
| F28.10 | Class imbalance documented and handled | `ml/classification.py` | M6 | Balanced weights; macro-averaged metrics | Documentation; `docs/ml-evaluation.md` | **IMPLEMENTED** |
| F28.11 | Metrics with real denominators | `ml/evaluation.py` | M6 | Support and confusion matrices reported | `test_ml.py::test_binary_metrics_match_a_hand_worked_matrix` | **IMPLEMENTED** |
| F28.12 | Undefined metrics reported as undefined | `ml/evaluation.py` | M6 | `None` with a reason, never zero | `test_ml.py::test_undefined_metrics_are_reported_as_undefined_not_zero` | **IMPLEMENTED** |
| F28.13 | Trivial baselines included | `ml/classification.py` | M6 | `DummyClassifier` reported alongside | `test_ml.py::test_a_baseline_is_always_compared` | **IMPLEMENTED** |
| F28.14 | Metrics labelled as synthetic | `ml/evaluation.py` | M6 | Measurement context on every result | `test_ml.py::test_every_metric_result_states_it_is_synthetic` | **IMPLEMENTED** |
| F28.15 | Failure cases reported | `docs/ml-evaluation.md` | M6 | Nine false positives and HIGH recall analysed | Documentation review | **IMPLEMENTED** |

## F29 — Persistence, inference and output (M6)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F29.1 | Reproducibility metadata in every manifest | `ml/registry.py` | M6 | Versions, digest, hyperparameters, libraries | `test_ml.py::test_manifests_record_reproducibility_metadata` | **IMPLEMENTED** |
| F29.2 | Artifacts loaded only from a controlled path | `ml/registry.py` | M6 | Resolved and confined; a manifest cannot redirect | `test_ml.py::test_an_artifact_outside_the_model_directory_is_refused` | **IMPLEMENTED** |
| F29.3 | Integrity verified before deserialisation | `ml/registry.py` | M6 | SHA-256 checked before joblib opens the file | `test_ml.py::test_a_tampered_artifact_is_never_deserialised` | **IMPLEMENTED** |
| F29.4 | Incompatible feature schemas refused | `ml/registry.py` | M6 | Mismatch raises, never loads | `test_ml.py::test_a_feature_schema_mismatch_is_refused` | **IMPLEMENTED** |
| F29.5 | Unsupported model versions refused | `ml/registry.py` | M6 | Version allowlist | `test_ml.py::test_an_unsupported_model_version_is_refused` | **IMPLEMENTED** |
| F29.6 | No model is ever downloaded | `ml/registry.py` | M6 | No URL or network path exists | `test_ml.py::test_inference_opens_no_socket` | **IMPLEMENTED** |
| F29.7 | The analyzer works with no model | `ml/inference.py` | M6 | Status reported; analysis unaffected | `test_ml.py::test_a_missing_model_is_reported_not_raised_into_the_analysis` | **IMPLEMENTED** |
| F29.8 | A rejected model does not fail the analysis | `ml/inference.py` | M6 | `MODEL_REJECTED` warning; assessment survives | `test_ml.py::test_a_rejected_model_does_not_fail_the_analysis` | **IMPLEMENTED** |
| F29.9 | ML never modifies a deterministic result | `pipeline.py` | M6 | Identical analysis with and without | `test_ml.py::test_ml_never_modifies_a_deterministic_result` | **IMPLEMENTED** |
| F29.10 | No ML output in a SecurityFinding | `models/ml.py` | M6 | Separate block; asserted absent from the assessment | `test_ml.py::test_no_ml_prediction_enters_a_security_finding` | **IMPLEMENTED** |
| F29.11 | Inference is deterministic | `ml/inference.py` | M6 | Repeated runs byte-identical | `test_ml.py::test_repeated_inference_is_identical` | **IMPLEMENTED** |
| F29.12 | Explanations are evidence-linked | `ml/explanations.py` | M6 | Provenance and packet references on every result | `test_ml.py::test_every_explanation_is_traceable_to_an_observation` | **IMPLEMENTED** |
| F29.13 | Output discloses that ML produced it | `models/ml.py` | M6 | Disclosure on the block and in each explanation | `test_ml.py::test_ml_output_discloses_that_a_model_produced_it` | **IMPLEMENTED** |
| F29.14 | No credential material in the ML block | `ml/features.py` | M6 | M2 redaction holds through the layer | `test_ml.py::test_no_credential_material_reaches_the_ml_block` | **IMPLEMENTED** |
| F29.15 | No identity in the ML block | `ml/features.py` | M6 | No address, host name, SNI or subject | `test_ml.py::test_no_identity_reaches_the_ml_block` | **IMPLEMENTED** |
| F29.16 | Additive JSON contract | `models/analysis.py` | M6 | Schema 1.4.0; `ml` block removable | `test_ml.py::test_cli_reports_ml_end_to_end` | **IMPLEMENTED** |
| F29.17 | End-to-end CLI inference | `cli.py` | M6 | `analyze` reports ML; `--no-ml` disables it | `test_ml.py::test_cli_reports_ml_end_to_end` | **IMPLEMENTED** |
| F29.18 | Bounded, local, no GPU | `ml/inference.py` | M6 | 0.43 ms/session, one cached model, `n_jobs=1` | `docs/ml-evaluation.md` | **IMPLEMENTED** |
| F29.19 | Measured training and inference performance | `docs/ml-evaluation.md` | M6 | Real hardware, timings and artifact sizes | Documentation review | **IMPLEMENTED** |

## F8 — Assessment, correlation, ML, reporting, UI

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F8.1 | Explainable security findings | `assessment/` | M4 | Every finding cites its observations and their statuses | `test_assessment.py::test_every_finding_cites_a_real_packet` | **IMPLEMENTED** |
| F8.2 | Posture scoring | `assessment/` | M4 | Score auditable back to packets | `test_assessment.py::test_score_follows_the_published_formula` | **IMPLEMENTED** |
| F8.3 | Evidence-based correlation | `intelligence/` | M5 | Multi-session findings retain all contributing refs | `test_intelligence.py::test_every_correlation_names_its_basis_and_its_limits` | **IMPLEMENTED** |
| F8.4 | ML-assisted analysis | `ml/` | M6 | Local scikit-learn; output always `INFERRED` | `test_ml.py::test_ml_output_discloses_that_a_model_produced_it` | **IMPLEMENTED** |
| F8.5 | Forensic reports | `reporting/` | M1 / M7 | JSON, HTML and PDF, all from one canonical model | `test_backend.py::test_all_three_formats_agree_on_the_facts` | **IMPLEMENTED** |
| F8.6 | Local SQLite persistence | `backend/` | M7 | Investigations survive a restart | `test_backend.py::test_results_survive_a_restart` | **IMPLEMENTED** |
| F8.7 | FastAPI backend | `backend/` | M7 | Serves the real engine; no second analyzer | `test_backend.py::test_analysis_runs_the_real_engine_and_persists` | **IMPLEMENTED** |
| F8.8 | React + TypeScript + Vite frontend | `frontend/` | M7 | Nine areas, real data throughout | `frontend/e2e/workflow.spec.ts` | **IMPLEMENTED** |

## F30 — Local API and execution (M7)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F30.1 | FastAPI serves the real forensic engine | `backend/app.py` | M7 | No second analyzer; endpoints read persisted engine output | `test_backend.py::test_analysis_runs_the_real_engine_and_persists` | **IMPLEMENTED** |
| F30.2 | PCAP and PCAPNG upload | `backend/storage.py` | M7 | Both formats accepted, identified by magic bytes | `test_backend.py::test_a_pcapng_capture_uploads` | **IMPLEMENTED** |
| F30.3 | The file extension is not trusted | `backend/storage.py` | M7 | A non-capture named `.pcap` is rejected | `test_backend.py::test_a_file_that_is_not_a_capture_is_rejected` | **IMPLEMENTED** |
| F30.4 | Limits enforced during upload, not after | `backend/storage.py` | M7 | Abandoned mid-stream; the partial file is removed | `test_backend.py::test_the_upload_limit_is_enforced_while_streaming` | **IMPLEMENTED** |
| F30.5 | Server-generated storage ids; no path traversal | `backend/storage.py` | M7 | A traversing filename cannot escape the store | `test_backend.py::test_a_traversing_filename_cannot_escape_storage` | **IMPLEMENTED** |
| F30.6 | Captures stored outside the repository | `backend/storage.py` | M7 | Storage root is not under the repository | `test_backend.py::test_storage_is_outside_the_repository` | **IMPLEMENTED** |
| F30.7 | Analysis does not block the interface | `backend/service.py` | M7 | Bounded worker pool; status polled | `frontend/e2e/workflow.spec.ts` | **IMPLEMENTED** |
| F30.8 | Real analysis progress | `intelligence/engine.py`, `backend/service.py` | M7 | Captures done out of total, reported by the engine | `test_backend.py::test_job_progress_is_real` | **IMPLEMENTED** |
| F30.9 | Job states persisted | `backend/database.py` | M7 | QUEUED, RUNNING, COMPLETED, FAILED | `test_backend.py::test_job_progress_is_real` | **IMPLEMENTED** |
| F30.10 | An interrupted job never looks completed | `backend/database.py` | M7 | Marked FAILED on restart, with the reason | `test_backend.py::test_an_interrupted_job_is_never_reported_as_completed` | **IMPLEMENTED** |
| F30.11 | Duplicate analysis jobs refused | `backend/service.py` | M7 | 409 rather than two workers on one investigation | `test_backend.py::test_a_duplicate_analysis_is_refused` | **IMPLEMENTED** |
| F30.12 | A failed capture stays visible | `backend/service.py` | M7 | Present in the inventory with its reason | `test_backend.py::test_a_failed_capture_stays_visible` | **IMPLEMENTED** |
| F30.13 | Typed, paginated responses | `backend/schemas.py` | M7 | Every collection reports its true total | `test_backend.py::test_sessions_can_be_filtered_and_paginated` | **IMPLEMENTED** |
| F30.14 | Filtering and sorting on an allowlist | `backend/app.py` | M7 | An unknown sort key is 422, never interpolated | `test_backend.py::test_an_invalid_sort_key_is_rejected` | **IMPLEMENTED** |
| F30.15 | Cancellation | — | M7 | Not implemented; no CANCELLED status is produced | — | **NOT IMPLEMENTED** (documented in limitations.md) |

## F31 — Persistence (M7)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F31.1 | Records for captures, investigations, jobs, sessions, findings, intelligence, ML and exports | `backend/database.py` | M7 | Eight tables | `test_backend.py::test_results_survive_a_restart` | **IMPLEMENTED** |
| F31.2 | Canonical identifiers preserved | `backend/service.py` | M7 | Engine ids stored; packet references stay meaningful | `test_backend.py::test_findings_link_to_real_packet_evidence` | **IMPLEMENTED** |
| F31.3 | Transactional writes | `backend/database.py` | M7 | An investigation's results commit together or not at all | `test_backend.py::test_results_survive_a_restart` | **IMPLEMENTED** |
| F31.4 | Schema migrations | `backend/database.py` | M7 | `PRAGMA user_version` with ordered steps | `test_backend.py::test_health_reports_real_versions` | **IMPLEMENTED** |
| F31.5 | No sensitive payload persisted | `backend/service.py` | M7 | Stream records carry counts and offsets only | `test_backend.py::test_session_detail_contains_no_payload_or_credential` | **IMPLEMENTED** |
| F31.6 | Previous investigations never silently discarded | `backend/app.py` | M7 | Deleting a capture keeps its results | `test_backend.py::test_deleting_a_capture_removes_the_file_but_keeps_results` | **IMPLEMENTED** |

## F32 — Interface (M7)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F32.1 | Nine primary areas, all functional | `frontend/src/pages` | M7 | Every navigation entry reaches a working page | `app.test.tsx::renders every primary area` | **IMPLEMENTED** |
| F32.2 | Direct navigation, refresh and invalid routes | `frontend/src/App.tsx` | M7 | Deep links work; unknown routes show a real page | `workflow.spec.ts` | **IMPLEMENTED** |
| F32.3 | Overview shows authentic data | `pages/Overview.tsx` | M7 | Every number comes from the API | `app.test.tsx` (Overview suite) | **IMPLEMENTED** |
| F32.4 | NO FINDINGS, NOT ANALYSED and INSUFFICIENT EVIDENCE distinguished | `pages/Overview.tsx` | M7 | Never a zero where the answer is unknown | `app.test.tsx::distinguishes NO FINDINGS from a count of zero` | **IMPLEMENTED** |
| F32.5 | A high-severity finding is never hidden by the score | `pages/Overview.tsx`, `pages/Findings.tsx` | M7 | Stated beside the aggregate | `app.test.tsx::keeps a high-severity finding prominent` | **IMPLEMENTED** |
| F32.6 | Session explorer with search, sort, filter, pagination | `pages/Sessions.tsx` | M7 | All server-side | `app.test.tsx::passes a filter to the backend` | **IMPLEMENTED** |
| F32.7 | UNKNOWN and NOT AVAILABLE shown explicitly | `components/ui.tsx` | M7 | A TLS 1.3 certificate is NOT AVAILABLE, not blank | `app.test.tsx::shows NOT AVAILABLE for a TLS 1.3 certificate` | **IMPLEMENTED** |
| F32.8 | Reusable evidence component | `components/EvidenceLink.tsx` | M7 | Renders only when evidence exists | `app.test.tsx::navigates from a finding to its packet evidence` | **IMPLEMENTED** |
| F32.9 | Real progress only | `pages/Investigations.tsx` | M7 | Determinate when a proportion exists, indeterminate otherwise | `app.test.tsx::shows determinate progress only when...` | **IMPLEMENTED** |
| F32.10 | Loading, empty, failure and partial states | `components/ui.tsx` | M7 | Each distinct and tested | `app.test.tsx` (multiple) | **IMPLEMENTED** |
| F32.11 | Cryptographic intelligence views with caveats | `pages/Intelligence.tsx` | M7 | Fingerprint, drift, correlation and blast-radius caveats in the interface | `workflow.spec.ts` | **IMPLEMENTED** |
| F32.12 | Timeline with clock disclosure | `pages/Timeline.tsx` | M7 | Multi-capture clock limitation stated | `app.test.tsx::discloses clock limitations` | **IMPLEMENTED** |
| F32.13 | ML sections kept separate and honest | `pages/MLAnalysis.tsx` | M7 | Rarity baseline never called ML; Isolation Forest marked not in use; classifier NOT_VALIDATED | `app.test.tsx` (ML suite) | **IMPLEMENTED** |
| F32.14 | Benchmarks loaded from versioned metadata | `pages/MLAnalysis.tsx` | M7 | No metric hardcoded in the frontend | `app.test.tsx::reads benchmark numbers from the evaluation record` | **IMPLEMENTED** |
| F32.15 | Settings expose only real functionality | `pages/Settings.tsx` | M7 | Validated; reanalysis requirement stated | `test_backend.py::test_settings_are_validated` | **IMPLEMENTED** |
| F32.16 | A rendering failure is visible, not blank | `components/ErrorBoundary.tsx` | M7 | Error boundary states the evidence is intact | Code review; added after a real blank-page defect | **IMPLEMENTED** |

## F33 — Reporting and local security (M7)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F33.1 | One canonical report model | `reporting/report_model.py` | M7 | Selection and structuring only; nothing recomputed | `test_backend.py::test_all_three_formats_agree_on_the_facts` | **IMPLEMENTED** |
| F33.2 | JSON export | `backend/app.py` | M7 | Canonical model, deterministic serialisation | `test_backend.py::test_all_three_formats_export` | **IMPLEMENTED** |
| F33.3 | Standalone HTML export | `reporting/html_report.py` | M7 | No external font, script, stylesheet or image | `test_backend.py::test_the_html_report_is_standalone` | **IMPLEMENTED** |
| F33.4 | Untrusted text escaped | `reporting/html_report.py` | M7 | Autoescaping on; nothing marked safe | `test_backend.py::test_the_html_report_escapes_untrusted_text` | **IMPLEMENTED** |
| F33.5 | PDF export, offline renderer | `reporting/pdf_report.py` | M7 | ReportLab Platypus; no URL resolver exists | `test_backend.py::test_the_pdf_renders_correctly` | **IMPLEMENTED** |
| F33.6 | PDF renders correctly, verified visually | `reporting/pdf_report.py` | M7 | A4, paginated, no blank pages, no margin bleed | `test_backend.py::test_the_pdf_renders_correctly` | **IMPLEMENTED** |
| F33.7 | Long values wrap rather than clip | `reporting/pdf_report.py` | M7 | Every 71-character capture id survives in full | `test_backend.py::test_long_values_wrap_rather_than_clipping` | **IMPLEMENTED** |
| F33.8 | Report parity across formats | `reporting/` | M7 | Ids, counts, severities, policy, score, remediations, ML status | `test_backend.py::test_all_three_formats_agree_on_the_facts` | **IMPLEMENTED** |
| F33.9 | No credentials or payload in any report | `reporting/` | M7 | Checked in JSON, HTML and extracted PDF text | `test_backend.py::test_reports_contain_no_payload_or_credentials` | **IMPLEMENTED** |
| F33.10 | Bound to 127.0.0.1 by default | `backend/server.py` | M7 | Refuses a non-loopback bind | Code review; `server.py` | **IMPLEMENTED** |
| F33.11 | Host validation against DNS rebinding | `backend/app.py` | M7 | A foreign Host header is 400 | `test_backend.py::test_a_foreign_host_header_is_refused` | **IMPLEMENTED** |
| F33.12 | Explicit CORS origins, never permissive | `backend/security.py` | M7 | No wildcard; credentials off | `test_backend.py::test_cors_is_not_permissive` | **IMPLEMENTED** |
| F33.13 | Local token, never in committed source | `backend/security.py` | M7 | Generated at startup, stored outside the repository | `test_backend.py::test_requests_without_a_token_are_refused` | **IMPLEMENTED** |
| F33.14 | Error bodies leak nothing | `backend/app.py` | M7 | No traceback, path or database error | `test_backend.py::test_an_error_body_does_not_leak_internals` | **IMPLEMENTED** |
| F33.15 | Response hardening headers | `backend/app.py` | M7 | nosniff, DENY, CSP, no-referrer | `test_backend.py::test_responses_carry_hardening_headers` | **IMPLEMENTED** |
| F33.16 | No telemetry, no outbound request | whole application | M7 | None exists | `test_passive.py`, `test_intelligence.py::test_the_engine_opens_no_socket` | **IMPLEMENTED** |

## NF-V — Verification, performance and release readiness (M8)

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| NFV1 | Reproducible benchmark harness | `benchmarks/harness.py`, `corpus.py` | M8 | Fixed-seed corpus with ground truth; repeated runs; median, min and max reported | `scripts/run_benchmarks.py` | **IMPLEMENTED** |
| NFV2 | Acceptance thresholds defined before measurement | `benchmarks/thresholds.json` | M8 | Seven thresholds, each justified by the deployment target, committed before the results | `scripts/check_benchmarks.py`; git history | **IMPLEMENTED** |
| NFV3 | Correctness does not degrade under load | `benchmarks/harness.py` | M8 | Session and TLS counts match ground truth at every profile | `benchmarks/results.json` (25/25, 200/200, 1000/1000, 4000/4000) | **IMPLEMENTED** |
| NFV4 | Stage-level timing reported honestly | `benchmarks/harness.py` | M8 | An increment smaller than run-to-run spread is flagged, never presented as a measurement | `scripts/run_benchmarks.py` output | **IMPLEMENTED** |
| NFV47 | Fixtures reproducible across platforms | `testing/live_tls.py` | M8 | A TLS 1.3 capture is the same handshake on macOS and on an Ubuntu runner | CI Engine job; `test_tls.py::test_key_exchange_and_forward_secrecy_match_manifest` | **IMPLEMENTED** (the key-exchange group is pinned; before M8 each OpenSSL build chose its own and the committed manifest matched one platform only) |
| NFV5 | Malformed capture containers handled | `ingestion/` | M8 | Stated rejection or empty result; never a crash, never invented evidence | `test_robustness.py` (7 tests, 4 property-based) | **IMPLEMENTED** |
| NFV6 | Malformed TLS records handled | `tls/` | M8 | Lying lengths, truncated handshakes and arbitrary payloads yield no invented negotiation or certificate | `test_robustness.py` (4 tests, 3 property-based) | **IMPLEMENTED** |
| NFV7 | Malformed protocol data handled | `protocols/` | M8 | Arbitrary bytes never produce a CONFIRMED credential finding; oversized lines bounded | `test_robustness.py` (2 tests) | **IMPLEMENTED** |
| NFV8 | Resource limits engage visibly | `config.py`, `engine.py` | M8 | Session limit warns; packet limit marks the result truncated; evidence preserved | `test_robustness.py` (4 tests) | **IMPLEMENTED** |
| NFV9 | Passive operation proven, not asserted | whole engine | M8 | Socket constructors replaced with raising stubs across analysis, batch and all three renderers; no outbound client library imported | `test_robustness.py` (7 tests) | **IMPLEMENTED** |
| NFV10 | Token required on every data endpoint | `backend/app.py`, `security.py` | M8 | 13 endpoints answer 401 without a valid token | `test_security_audit.py` (13 parametrised + 3) | **IMPLEMENTED** |
| NFV11 | DNS rebinding refused | `backend/app.py` | M8 | Non-local `Host` answers 400 before the body is read | `test_security_audit.py` (2 tests) | **IMPLEMENTED** |
| NFV12 | CORS never permissive | `backend/security.py` | M8 | Fixed origin list, no wildcard, credentials off | `test_security_audit.py` (2 tests) | **IMPLEMENTED** |
| NFV13 | CSRF structurally impossible | `backend/app.py` | M8 | No cookies; four state-changing endpoints refused from a token-less cross-origin client | `test_security_audit.py::test_there_are_no_cookies_so_there_is_no_cookie_csrf` | **IMPLEMENTED** |
| NFV14 | Hostile identifiers refused without leaking | `backend/app.py` | M8 | 12 hostile strings × 5 endpoint templates: never 200, never a traceback, path or SQL error | `test_security_audit.py` (12 parametrised) | **IMPLEMENTED** |
| NFV15 | No SQL injection via sort or search | `backend/app.py` | M8 | Sort looked up in a fixed dict (422 otherwise); search bound; row count unchanged afterwards | `test_security_audit.py` (12 parametrised) | **IMPLEMENTED** |
| NFV16 | Collection responses bounded | `backend/app.py` | M8 | Every collection has a `le=` ceiling; over-limit, zero, negative and negative offset all refused | `test_security_audit.py::test_collection_responses_are_bounded` | **IMPLEMENTED** |
| NFV17 | Upload validation and limits | `backend/storage.py` | M8 | Magic bytes not extension; server-generated paths; oversized answers 413 and is not stored | `test_security_audit.py` (4 tests) | **IMPLEMENTED** |
| NFV18 | No information disclosure in errors | `backend/app.py` | M8 | An exception carrying the data path and the token leaks neither | `test_security_audit.py` (3 tests) | **IMPLEMENTED** |
| NFV19 | Reports execute nothing | `reporting/` | M8 | 13 hostile titles escaped but not discarded; PDF catalogue free of actions | `test_report_hardening.py` (16 tests) | **IMPLEMENTED** |
| NFV20 | Reports fetch nothing | `reporting/html_report.py` | M8 | `find_external_references` raises rather than shipping a report that loads a resource | `test_report_hardening.py` (3 tests) | **IMPLEMENTED** |
| NFV21 | No finding hidden by an aggregate score | `reporting/` | M8 | Every CRITICAL/HIGH finding in the JSON export present in HTML and PDF, by `finding_id` | `test_report_hardening.py` (2 tests) | **IMPLEMENTED** |
| NFV22 | Reports survive Unicode and long identifiers | `reporting/` | M8 | Round trip through all three formats; identifiers printed in full | `test_report_hardening.py` (16 tests) | **IMPLEMENTED** |
| NFV23 | SQLite integrity and foreign keys enforced | `backend/database.py` | M8 | `integrity_check` ok, `foreign_key_check` empty, `foreign_keys` on, violation raises | `test_reliability.py` (3 tests) | **IMPLEMENTED** |
| NFV24 | Persistence is atomic | `backend/service.py` | M8 | A failure mid-transaction restores the previous results exactly; a first failure stores nothing | `test_reliability.py` (4 tests) | **IMPLEMENTED** |
| NFV25 | Restart never fabricates success | `backend/database.py` | M8 | Interrupted jobs marked FAILED with a reason; completed investigations survive byte-for-byte | `test_reliability.py` (3 tests) | **IMPLEMENTED** |
| NFV26 | Concurrency safe | `backend/service.py` | M8 | Simultaneous uploads, duplicate uploads, reads during analysis, concurrent exports, duplicate analyses | `test_reliability.py` (6 tests) | **IMPLEMENTED** |
| NFV27 | Worker model documented truthfully | `backend/service.py` | M8 | `ThreadPoolExecutor(max_workers=2)`, asserted by test so docs cannot drift | `test_reliability.py::test_the_worker_model_is_a_bounded_thread_pool` | **IMPLEMENTED** |
| NFV28 | Frontend landmarks and headings | `frontend/src/App.tsx` | M8 | One `<h1>`; `navigation` and `main` landmarks | `accessibility.test.tsx` (3 tests) | **IMPLEMENTED** |
| NFV29 | Every control has an accessible name | `frontend/src/pages/` | M8 | All controls on 8 pages; 6 placeholder-only controls fixed | `accessibility.test.tsx` (16 tests) | **IMPLEMENTED** |
| NFV30 | Keyboard operable | `frontend/src/` | M8 | Navigation reachable by tab; no enabled control out of the tab order; no focus trap | `accessibility.test.tsx` (4 tests) | **IMPLEMENTED** |
| NFV31 | Failure announced, never shown as zero | `frontend/src/pages/` | M8 | 7 pages announce `role="alert"` on error and claim nothing while loading | `accessibility.test.tsx` (14 tests) | **IMPLEMENTED** |
| NFV32 | Usable at narrow widths | `frontend/src/` | M8 | Navigation intact at 320, 480, 768 and 1024 px | `accessibility.test.tsx` (4 tests) | **IMPLEMENTED** |
| NFV33 | Colour contrast meets WCAG 2.1 AA | `frontend/tailwind.config.js` | M8 | 9 token pairs computed with the relative-luminance formula | `accessibility.test.tsx` (10 tests) | **PARTIAL** (token-level check; rendered pixels are not sampled, so a colour changed without updating the test would not be caught) |
| NFV34 | Every third-party import declared | `pyproject.toml` | M8 | AST scan of `src/`, `tests/`, `scripts/` against declared extras | `test_dependencies.py` (5 tests) | **IMPLEMENTED** |
| NFV35 | Engine dependency floor enforced | `src/securemailscope/` | M8 | No engine module imports the web or ML stack; importing the pipeline loads neither | `test_dependencies.py` (2 tests) | **IMPLEMENTED** |
| NFV36 | Production frontend free of known advisories | `frontend/package.json` | M8 | `npm audit --omit=dev` reports zero | CI job `frontend` | **IMPLEMENTED** |
| NFV37 | Development frontend advisories recorded | `docs/dependency-audit.md` | M8 | Five remaining advisories listed with severity, scope and reason for deferral | — | **PARTIAL** (recorded and scoped, not remediated; needs a vite 5→8 and vitest 2→5 migration) |
| NFV38 | Clean installation from a bare checkout | `pyproject.toml` | M8 | Engine-only and full installs from `git archive`, in fresh venvs, on Python 3.12 | Executed 2026-09-21: 1346 passed, 25 skipped; ruff and mypy clean | **IMPLEMENTED** |
| NFV39 | Continuous integration | `.github/workflows/ci.yml` | M8 | Five jobs; read-only permissions; no secrets; no capture data uploaded | GitHub Actions run 35627938267 on `74ee1f1` | **IMPLEMENTED** (all five jobs green in an observed run; the first run failed two jobs and both failures were real defects, now fixed) |
| NFV40 | Complete browser-to-backend acceptance test | `frontend/e2e/acceptance.spec.ts` | M8 | 22 steps against the real stack, including a backend restart and reopen | `npm run e2e` | **IMPLEMENTED** |
| NFV41 | Analysis cancellation absent, not faked | `backend/app.py` | M8 | No route, no CANCELLED status, no button | `test_reliability.py::test_cancellation_is_not_offered_because_it_is_not_implemented` | **NOT IMPLEMENTED** (deliberately; the absence is tested) |
| NFV42 | Hash-pinned dependency lock | — | M8 | `pip install --require-hashes` | — | **NOT IMPLEMENTED** |
| NFV43 | Python advisory scanning | — | M8 | `pip-audit` or Dependabot in CI | — | **NOT IMPLEMENTED** |
| NFV44 | SBOM generation | — | M8 | A machine-readable bill of materials | — | **NOT IMPLEMENTED** |
| NFV45 | Type checking of tests and scripts | `pyproject.toml` | M8 | `mypy` covers `src/` only (116 files); `tests/` and `scripts/` are outside its scope | — | **NOT IMPLEMENTED** (a widened run reports 161 errors in 13 files, all in test and script code) |
| NFV46 | Benchmarks on the assumed minimum hardware | — | M8 | A run on 4 cores / 8 GB | — | **NOT VERIFIED** (thresholds are derived for that machine; the recorded run used 16 logical CPUs) |

---

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
| NF13 | Pinned dependencies | `pyproject.toml`, `requirements-lock.txt` | M0/M8 | Exact versions; fully-resolved lock file | `test_dependencies.py::test_every_declared_dependency_is_pinned_exactly`, `::test_the_lock_file_matches_what_is_declared` | **PARTIAL** (45 packages pinned and locked, zero drift on a clean install; hashes still not pinned) |
| NF14 | Performance characterisation | `benchmarks/`, `scripts/run_benchmarks.py` | M8 | Reproducible harness, ground-truth corpus, repeated runs, variation reported | `scripts/run_benchmarks.py`; `benchmarks/results.json` | **IMPLEMENTED** (four profiles, 3 repeats each, measured on one machine only — see `docs/performance-benchmarks.md` for what the figures do not establish) |

---

## Summary

| Status | Count | Change since M7 |
|---|---|---|
| IMPLEMENTED | 453 | +40 |
| PARTIAL | 5 | +2 |
| NOT IMPLEMENTED | 14 | +4 |
| NOT VERIFIED | 1 | new in M8 |
| **Total requirements tracked** | **473** | +47 |

The implemented set covers the whole product: capture ingestion, TCP
reconstruction, the email protocol layer, the TLS and certificate layer, the
assessment layer, the forensic intelligence layer, the machine-learning layer,
a local application around them, and — since M8 — a verified account of how all
of it behaves under adverse conditions.

The count rose by 47 in M8 without a single new product feature. Every new row
is a verification requirement, and five of them are recorded as gaps rather
than achievements.

**Reported PARTIAL (5):** certificate extraction (TLS ≤ 1.2 only — TLS 1.3
encrypts the Certificate message, permanently); supervised risk classification
(F28.8, implemented and measured, reported `NOT_VALIDATED`); pinned
dependencies (NF13 — 45 packages pinned and locked with zero drift on a clean
install, but bytes are not hash-pinned); colour contrast (NFV33 — computed from
design tokens, not sampled from rendered pixels); and the five remaining
development-only npm advisories (NFV37 — recorded and scoped, not remediated).

**Reported NOT IMPLEMENTED (14):** analysis cancellation (F30.15, NFV41 — a
running analysis finishes or fails, and the absence is tested rather than
disguised); revocation checking (F14.25, permanently out of scope); hash-pinned
dependencies (NFV42); Python advisory scanning (NFV43); SBOM generation
(NFV44); type checking of tests and scripts (NFV45 — `mypy` covers `src/` only;
a widened run reports 161 errors in 13 files); and eight earlier items.

**Reported NOT VERIFIED (1), a status introduced in M8:** benchmarks on the
assumed minimum hardware (NFV46). The thresholds are derived for a 4-core, 8 GB
machine; the recorded run used one with 16 logical CPUs, so a pass there does
not demonstrate a pass on the minimum.

Continuous integration (NFV39) was NOT VERIFIED for most of M8 and is now
IMPLEMENTED, because a run was watched to completion rather than inferred from
local passes. That run mattered: its first attempt failed two of five jobs, and
both failures were real defects that every local check had missed.

This status exists because "the module is there" is not evidence that the
requirement is met. Where the only thing supporting a row would be the
existence of code, the row says NOT VERIFIED.

**Constants in every report:** `handshake_analyzed = false`,
`handshakes_cryptographically_verified = 0`,
`revocation_checks_performed = 0`.
