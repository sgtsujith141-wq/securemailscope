# M7 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M7 — Production-oriented forensic dashboard, local API, persistence and JSON/PDF/HTML reporting
- **Baseline (M6):** `e29d0400051939bf3bb3b1a8c1e41af716b70c80`
- **Result:** **COMPLETE** — all 18 acceptance gates pass.

---

## 1. Baseline verification

| Claim | Actual |
|---|---|
| Local HEAD == remote HEAD | both `e29d0400051939bf3bb3b1a8c1e41af716b70c80` |
| Working tree | clean |
| `pytest -q` | `1163 passed, 25 skipped` — **matches the directive** |
| `SECUREMAILSCOPE_TSHARK=1 pytest -q` | `1173 passed, 15 skipped` — **matches** |
| `backend/`, `frontend/` | did not exist; F8.6–F8.8 were correctly marked NOT IMPLEMENTED |

### Discrepancy found and corrected

`README.md` stated *"This repository is at the end of **M0 + M1**"* and listed
M4, M5, M6 and M7 as NOT IMPLEMENTED — six milestones out of date. The
requirements matrix and every milestone report were accurate; only the README
had been left behind. It has been rewritten with the true stage table and a
quick-start section.

No other reported functionality differed from the code.

---

## 2. Files changed

**64 files, +16,527/−52** (55 new).

### Backend

| File | Lines | Purpose |
|---|---|---|
| `backend/app.py` | 1,015 | Routes, middleware, security guards |
| `backend/service.py` | 470 | Bounded worker pool, transactional persistence |
| `backend/database.py` | 396 | SQLite schema, migrations, restart recovery |
| `backend/schemas.py` | 279 | Typed API contracts |
| `backend/storage.py` | 197 | Private capture storage |
| `backend/security.py` | 104 | Host allowlist, CORS origins, local token |
| `backend/server.py` | 90 | Entry point |

### Reporting

| File | Lines | Purpose |
|---|---|---|
| `reporting/report_model.py` | 725 | The canonical model all three formats render |
| `reporting/pdf_report.py` | 535 | A4 PDF via ReportLab Platypus |
| `reporting/html_report.py` | 87 | Standalone HTML with an external-reference guard |
| `reporting/templates/report.html.j2` | 330 | Autoescaped template |

### Frontend

**4,129 lines** of TypeScript and TSX across 9 pages, 4 shared components,
the API client, hooks and context, plus 32 component tests and 4 Playwright
end-to-end tests.

### Tests and documentation

`tests/test_backend.py` (628 lines, 38 tests); six new documents
(`application-architecture.md`, `api-reference.md`, `database.md`,
`dashboard.md`, `reporting.md`, `deployment.md`); five updated.

### One engine change

`intelligence/engine.py` gained an optional `on_capture` progress callback, so
the service can report **real** progress rather than animating a timer. No
analytical behaviour changed.

---

## 3. Backend functionality

FastAPI over the **existing** engine — there is no second analyzer. Endpoints
schedule `analyze_batch` and read persisted rows; none recomputes a score,
re-derives a severity or counts anything the engine already counted.

Health and version · capture upload and listing · investigation creation,
analysis, listing and detail · job status · session listing with search,
sorting, filtering and pagination · session detail · findings with filters ·
finding detail with evidence · fingerprints, entities, drift, correlations and
blast radius · timeline with filters · ML results with the versioned evaluation
record · JSON, HTML and PDF export · export history · settings · capture
deletion.

Every collection is paginated and reports its true total.

---

## 4. Database schema

Eight tables in one SQLite file at `~/.securemailscope/securemailscope.sqlite3`
— outside the repository by construction.

`captures` · `investigations` · `jobs` · `sessions` · `findings` ·
`intelligence` · `ml_results` · `report_exports`

Normalised where the interface queries (filters, sorts, paginates); JSON
columns where a document is always read whole. Canonical engine identifiers are
stored, so a packet reference persisted here means what it meant during
analysis. Migrations use `PRAGMA user_version` with ordered steps. Foreign keys
are enabled; SQLite disables them by default, which would let the schema drift
into orphaned rows silently.

**`posture_score` is nullable and means it.** A missing score is `NULL`, never
`0` — the two say opposite things.

---

## 5. Frontend pages

Nine areas, all functional: Overview, Investigations (+ workspace), Sessions
(+ detail), Security findings, Cryptographic intelligence, Evidence timeline,
ML analysis, Reports, Settings. Direct navigation, refresh-safe context and a
real not-found page.

Genuine screenshots of the running application were captured into
`local-evidence/screenshots/` — **gitignored**, so real application state is
never committed. Thirteen views: upload, investigation, overview, sessions,
session detail, finding evidence, fingerprints, drift, blast radius, timeline,
ML analysis, reports, settings.

---

## 6. Upload and analysis example

Real run, from the end-to-end test:

```
POST /api/captures         aa_tls10_static_rsa.pcap (990 bytes)
                        →  200  sha256:a78557eb039e84fcb12e06f4a61587f460d48f5f22be6f2550a7559977a6bcf1
                           file_format PCAP, validated from magic bytes
POST /api/investigations   → inv-9553233189365735
POST …/analyze             → job-… QUEUED → RUNNING → COMPLETED
                             captures_done 2 / captures_total 2
                             stage "analysed 2/2: t_a_tls12_complete_handshake.pcap"
```

Result: 2 captures analysed, 2 sessions, 4 findings, score **59/100 (WEAK)**,
coverage **76%** — the engine's own numbers, unchanged.

A file that is not a capture is rejected with `422` and a stated reason,
whatever its extension. An oversized upload is abandoned mid-stream and its
partial file removed.

---

## 7. Session investigation example

`sess-efe8cce0daf09e49` — `192.0.2.10:49152 → 198.51.100.25:993`

| Field | Value |
|---|---|
| Protocol | IMAP (`PORT_HINT` — a port is a hint, not an identification) |
| TLS version | TLS 1.0 |
| Cipher suite | `TLS_RSA_WITH_AES_128_CBC_SHA` |
| Key exchange | RSA — `STATIC_RSA_KEY_EXCHANGE` |
| Certificate | OBSERVED, `CN=mail.example.invalid` |
| Findings | 4 |

The detail page shows connection metadata, TCP reconstruction (packets, bytes,
segments, gaps, retransmissions — **counts only**), protocol observations, the
STARTTLS transition, TLS negotiation, certificate intelligence with the five
independent validation checks, findings and ML observations.

A TLS 1.3 session shows `NOT AVAILABLE` for its certificate with the reason
stated, not a blank.

---

## 8. Finding-to-evidence navigation

Clicking `TLS-KEX-001` expands its detail, and the evidence control reveals:

| Packet | Capture timestamp | Stream offset | Source observation | Status |
|---|---|---|---|---|
| #4 | 2026-06-01 12:00:00.003000 UTC | NOT APPLICABLE | assessment rule TLS-KEX-001 | INFERRED |
| #5 | 2026-06-01 12:00:00.004000 UTC | NOT APPLICABLE | assessment rule TLS-KEX-001 | INFERRED |

With the capture id in full, a link through to the session, and the statement
that packet metadata only is shown.

The component renders a control **only when there is evidence**. A packet
reference that leads nowhere is worse than no link: it implies inspectable
evidence that does not exist.

---

## 9. Cryptographic drift visualisation

The drift tab shows both sides of every comparison with its status:

| Property | Status | Before | After | Offers comparable |
|---|---|---|---|---|
| `NEGOTIATED_VERSION` | `INCONCLUSIVE` | TLS 1.2 | TLS 1.0 | false |
| `CERTIFICATE_FINGERPRINT` | `OBSERVED_CHANGE` | 9e77b09d… | d80b80d7… | — |
| `CERTIFICATE_PUBLIC_KEY` | `UNCHANGED_WITH_EVIDENCE` | 97be88ee… | 97be88ee… | — |
| `KEY_EXCHANGE_GROUP` | `NOT_COMPARABLE` | x25519 | not observed | false |

The page states in the interface that a different negotiated parameter is not
automatically a server configuration change, and shows `client_offers_comparable`
so a reader can see why a comparison was inconclusive.

---

## 10. Timeline

Events in capture-timestamp order with their packet references:

```
0  12:00:00.000  SESSION FIRST PACKET   OBSERVED  sess-efe8cce0daf09e49  Packets 1
1  12:00:00.000  PROTOCOL IDENTIFIED    INFERRED  sess-efe8cce0daf09e49  Packets 1
2  12:00:00.003  CLIENT HELLO           OBSERVED  sess-efe8cce0daf09e49  Packets 4
3  12:00:00.003  SECURITY FINDING       INFERRED  sess-efe8cce0daf09e49  Packets 4, 5
```

Filterable by event type, session and capture. Same-timestamp ordering is the
engine's documented one. For a multi-capture investigation the page states that
clocks are independent and uncorrected, so cross-capture ordering may not
reflect real chronology.

---

## 11. ML interface

Three clearly separated sections, preserving M6's findings exactly:

1. **Deterministic rarity analysis — the detector in use.** Stated as *"a
   deterministic frequency table, **not** a machine-learning model"*, with its
   held-out metrics (P 1.0000, R 1.0000, F1 1.0000, FPR 0.0000).
2. **Experimental anomaly model — not in use.** *"Isolation Forest was trained
   and evaluated, and was not selected."* Both candidates' metrics side by side
   (IF: P 0.4706, F1 0.6400, FPR 0.0968).
3. **Supervised risk classifier.** `NOT_VALIDATED`, *"not confirmed threats"*,
   *"not calibrated probabilities"*, with real per-class metrics.

**No benchmark number is written into the frontend.** All are read from the
versioned evaluation artifact the backend serves, and a test supplies a
distinctive value to prove it reaches the page.

---

## 12. JSON export verification

The canonical model with sorted keys. Verified to carry forensic observations,
findings with evidence references, policy version, score and coverage,
cryptographic intelligence, ML validation status and limitations.

`test_reports_contain_no_payload_or_credentials` runs a capture carrying dummy
credentials through it and asserts none of the marked strings appears.

---

## 13. HTML export verification

Standalone: `find_external_references()` re-checks the rendered output for
scripts, stylesheets, images, `@import` and remote `url()`, and **raises** if
any appear, so a template change cannot quietly reintroduce one. The test
asserts the list is empty.

Autoescaping is on and nothing is marked safe.
`test_the_html_report_escapes_untrusted_text` pushes `<script>alert("xss")</script>`
through the title and asserts it comes out as `&lt;script&gt;`.

---

## 14. PDF export verification

Built from the canonical model with ReportLab Platypus — **not** by converting
the HTML. An HTML-to-PDF renderer resolves what a document references, and
report content derives from untrusted captures; Platypus has no URL resolver at
all, so the guarantee is structural.

Verified, not merely produced:

- **A4 geometry** — 595 × 842 pt, asserted.
- **Text extraction** — Executive summary, Security findings, Limitations,
  "Page 1" and the scope statement all present.
- **Every page rasterised** with pypdfium2 and checked for ink (no blank
  pages) and for margin bleed (which is what clipping looks like).
- **Long values wrap** — every 71-character capture identifier survives in
  full in the extracted text, asserted.
- **No credentials** — the PDF's extracted text is checked alongside JSON and
  HTML.

Visual inspection of the rendered pages confirmed correct typography,
pagination, table layout, wrapped hashes, page numbers and footer metadata.

---

## 15. Report parity

`test_all_three_formats_agree_on_the_facts` compares across JSON, HTML and PDF:

capture ids · session ids and counts · finding rule ids and severities · policy
version · posture score · remediation ids · blast-radius subjects · ML
validation status and anomaly algorithm

Long identifiers wrap across lines in the PDF, so the comparison is made on
whitespace-normalised text.

**A real parity gap was found and fixed.** The HTML template truncated capture
identifiers to 39 characters for display while JSON and PDF printed them in
full. A forensic identifier that cannot be copied is not much use, and the
mismatch broke exactly the guarantee the shared report model exists to provide.

---

## 16. Security tests

| Control | Test |
|---|---|
| Foreign `Host` header refused (DNS rebinding) | `test_a_foreign_host_header_is_refused` |
| Missing token refused; health stays open | `test_requests_without_a_token_are_refused` |
| Wrong token refused | `test_a_wrong_token_is_refused` |
| CORS allowlist, never permissive | `test_cors_is_not_permissive` |
| Hardening headers | `test_responses_carry_hardening_headers` |
| Error bodies carry no path or traceback | `test_an_error_body_does_not_leak_internals` |
| Extension not trusted | `test_a_file_that_is_not_a_capture_is_rejected` |
| Upload limit enforced while streaming | `test_the_upload_limit_is_enforced_while_streaming` |
| Path traversal blocked | `test_a_traversing_filename_cannot_escape_storage` |
| Storage outside the repository | `test_storage_is_outside_the_repository` |
| Sort column allowlisted | `test_an_invalid_sort_key_is_rejected` |
| No payload or credentials in session detail | `test_session_detail_contains_no_payload_or_credential` |
| Report injection prevented | `test_the_html_report_escapes_untrusted_text` |
| No external PDF/HTML resources | `test_the_html_report_is_standalone` |

The server refuses to bind a non-loopback interface rather than pretend its
security model covers one.

---

## 17. End-to-end test results

Four Playwright tests against the **real backend** — no mocking anywhere:

```
✓ upload, analyse, investigate, navigate to evidence and export
✓ ML analysis preserves the M6 distinctions
✓ an unknown route shows a real not-found page
✓ a refresh preserves the selected investigation

4 passed
```

The acceptance test performs the full workflow and verifies every downloaded
file: JSON parsed and its findings counted, HTML checked for its rule ids and
for the absence of external references, PDF checked for its `%PDF` magic.

### What end-to-end testing caught

Two defects no unit test would have found:

1. **A blank page.** The session detail route crashed: certificate validation
   entries are objects, not status strings, and React refuses to render an
   object as a child. Fixed — and an **error boundary** added, because in a
   forensic tool an analyst cannot distinguish a blank page from an empty
   investigation.
2. **The parity gap** in §15.

---

## 18. Regression results

```
$ pytest -q
1201 passed, 25 skipped in 82.04s

$ SECUREMAILSCOPE_TSHARK=1 pytest -q
1211 passed, 15 skipped in 85.04s

$ ruff check src tests scripts
All checks passed!

$ mypy src/securemailscope/
Success: no issues found in 113 source files

$ cd frontend && npm run typecheck && npm run lint && npm run test && npm run build
tsc --noEmit                    → clean
eslint . --max-warnings 0       → clean
vitest run                      → 32 passed (32)
vite build                      → built in 3.62s
```

All M1–M6 tests pass. Five assertions were updated for the schema bump
(1.3.0 → **1.4.0**); no forensic behaviour changed.

---

## 19. Known limitations

- **Localhost security model.** Not a multi-user service; no roles or
  permissions; anyone with the account can read every investigation.
- **Cancellation is not implemented.** A running analysis finishes or fails.
- **Interrupted jobs are failed, not resumed.**
- **Two analysis workers**, and no throughput benchmark is claimed.
- **Progress is per-capture.** Within one capture the engine reports a stage
  but no fraction, so the indicator is indeterminate there.
- **Certificate extraction is still TLS ≤ 1.2 only** — TLS 1.3 encrypts it,
  permanently.
- **Supervised classification remains `NOT_VALIDATED`** from M6.

---

## 20. Local startup commands

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev,backend,ml,reporting-tests]'
cd frontend && npm install && cd ..

# Backend — prints its data directory, private storage path and API token
.venv/bin/python -m securemailscope.backend.server

# Frontend, in a second terminal
cd frontend
SMS_API=http://127.0.0.1:8765 \
SMS_API_TOKEN="$(cd .. && .venv/bin/python -m securemailscope.backend.server --print-token)" \
npm run dev
# open http://127.0.0.1:5173
```

The CLI is unaffected:

```bash
.venv/bin/python -m securemailscope analyze capture.pcap -o report.json
.venv/bin/python -m securemailscope analyze-batch a.pcap b.pcap -o investigation.json
```

Full workflow in [deployment.md](../deployment.md).

---

## 21. Acceptance gates

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | FastAPI serves the real forensic engine | **PASS** | `test_analysis_runs_the_real_engine_and_persists` |
| 2 | PCAP and PCAPNG uploads work | **PASS** | `test_a_real_capture_uploads…`, `test_a_pcapng_capture_uploads` |
| 3 | Analysis does not block the interface | **PASS** | Bounded pool; e2e polls status while the UI responds |
| 4 | Results persist correctly | **PASS** | `test_results_survive_a_restart` |
| 5 | Overview displays authentic data | **PASS** | §5 screenshots; `app.test.tsx` Overview suite |
| 6 | Session explorer functions | **PASS** | `test_sessions_can_be_filtered_and_paginated` |
| 7 | Findings link to evidence | **PASS** | §8; `test_findings_link_to_real_packet_evidence` |
| 8 | Cryptographic intelligence is functional | **PASS** | §9; `test_intelligence_and_timeline_are_served` |
| 9 | Timeline navigation works | **PASS** | §10; e2e |
| 10 | Blast radius shows actual counts | **PASS** | Served from the engine's own counts |
| 11 | ML uncertainty and validation preserved | **PASS** | §11; `test_ml_results_preserve_m6_distinctions` |
| 12 | JSON exports work | **PASS** | §12 |
| 13 | HTML exports work offline | **PASS** | §13 |
| 14 | PDF exports render correctly | **PASS** | §14, verified visually page by page |
| 15 | All formats agree on facts | **PASS** | §15 |
| 16 | Local privacy and API security enforced | **PASS** | §16 |
| 17 | Browser-to-backend workflow passes | **PASS** | §17 |
| 18 | M1–M6 regressions pass | **PASS** | §18 |

---

## 22. Readiness for M8

M8 is hardening. The seams it will work on are visible:

- Every security control has a test, so a change that weakens one fails.
- `SettingsPayload.requires_reanalysis` already distinguishes settings that
  affect future analyses from those that apply immediately.
- The local token, host allowlist and CORS origins are in one module.
- Known gaps are documented rather than hidden: no cancellation, no benchmark,
  no multi-user model.

No M8 work was started.
