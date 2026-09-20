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
`intelligence/`, `ml/`) contain only a docstring stating their status.

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
| F5.5 | Port-based protocol hints, clearly labelled | `protocols/hints.py` | M1 | `INFERRED`, `HINT:` prefix, explicit limitations | `test_sessions.py::test_protocol_hints_are_labelled_as_hints` | **IMPLEMENTED** |
| F5.6 | Output distinguishes facts, hints and unknowns | `models/evidence.py` | M1 | Four statuses used correctly throughout | `test_sessions.py`, `test_report.py` | **IMPLEMENTED** |
| F5.7 | Works with no LLM, server, database or frontend | package deps | M0/M1 | Only `scapy` and `pydantic` installed | `pyproject.toml`; suite runs standalone | **IMPLEMENTED** |
| F5.8 | Functional CLI entry point named `securemailscope` | `pyproject.toml` | M0 | Installed console script | `test_cli.py` (runs `python -m securemailscope`) | **IMPLEMENTED** |

## F6 — Email protocol analysis

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F6.1 | Identify SMTP | `protocols/` | M2 | Banner and command grammar confirmed from payload | — | **NOT IMPLEMENTED** |
| F6.2 | Identify IMAP | `protocols/` | M2 | Tagged command/response grammar confirmed | — | **NOT IMPLEMENTED** |
| F6.3 | Identify POP3 | `protocols/` | M2 | `+OK`/`-ERR` grammar confirmed | — | **NOT IMPLEMENTED** |
| F6.4 | Detect STARTTLS / STLS | `protocols/` | M2 | Command and server acceptance both observed | — | **NOT IMPLEMENTED** |
| F6.5 | Detect implicit TLS (465/993/995) | `tls/` | M3 | TLS record on the first byte of the stream | — | **NOT IMPLEMENTED** |
| F6.6 | Detect offered-but-unused STARTTLS | `intelligence/` | M5 | Capability advertised, upgrade never issued | — | **NOT IMPLEMENTED** |

## F7 — TLS and certificate analysis

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F7.1 | TLS record framing over reconstructed streams | `tls/` | M3 | Records framed; stops at a gap | — | **NOT IMPLEMENTED** |
| F7.2 | Reconstruct handshakes | `tls/` | M3 | ClientHello/ServerHello parsed | — | **NOT IMPLEMENTED** |
| F7.3 | Extract observable crypto properties | `tls/` | M3 | Version, cipher suite, groups, signature algorithms, ALPN, SNI | — | **NOT IMPLEMENTED** |
| F7.4 | Certificate extraction | `certificates/` | M3 | TLS ≤ 1.2 only; TLS 1.3 → `NOT_AVAILABLE` | — | **NOT IMPLEMENTED** |
| F7.5 | Certificate security assessment | `certificates/` | M4 | Key size, algorithm, validity, chain shape | — | **NOT IMPLEMENTED** |
| F7.6 | Correctly report TLS 1.3 certificate unavailability | `tls/`, docs | M3 | `NOT_AVAILABLE`, never `UNKNOWN`, never omitted | — | **NOT IMPLEMENTED** (documented in `limitations.md`) |

## F8 — Assessment, correlation, ML, reporting, UI

| ID | Requirement | Module | Milestone | Acceptance criterion | Test | Status |
|---|---|---|---|---|---|---|
| F8.1 | Explainable security findings | `assessment/` | M4 | Every finding cites its observations and their statuses | — | **NOT IMPLEMENTED** |
| F8.2 | Posture scoring | `assessment/` | M4 | Score auditable back to packets | — | **NOT IMPLEMENTED** |
| F8.3 | Evidence-based correlation | `intelligence/` | M5 | Multi-session findings retain all contributing refs | — | **NOT IMPLEMENTED** |
| F8.4 | ML-assisted analysis | `ml/` | M6 | Local scikit-learn; output always `INFERRED` | — | **NOT IMPLEMENTED** |
| F8.5 | Forensic reports | `reporting/` | M1 / M4 | JSON implemented; narrative forensic report is M4 | `test_report.py` | **PARTIAL** |
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

| Status | Count |
|---|---|
| IMPLEMENTED | 74 |
| PARTIAL | 3 |
| NOT IMPLEMENTED | 23 |
| **Total requirements tracked** | **100** |

The implemented set is, deliberately, entirely within capture ingestion, TCP
reconstruction, data contracts, the CLI and the non-functional guarantees.
**No requirement in F6, F7 or F8 is claimed.**
