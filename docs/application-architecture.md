# Application architecture

M7 wraps the existing forensic engine in a local application. It adds a
persistence layer, an HTTP adapter, a browser interface and two report
renderers — and changes nothing about how evidence is produced.

```
  browser (React + TS + Vite)
        │  fetch /api  (same origin via the dev proxy; token attached)
        ▼
  FastAPI adapter ──────────── SQLite (SQLAlchemy)
        │                            ▲
        │ schedules                  │ persists
        ▼                            │
  AnalysisService (bounded thread pool)
        │
        ▼
  the M1–M6 engine, unchanged
        │
        ▼
  ReportModel ──► JSON  ──► HTML (Jinja2) ──► PDF (ReportLab)
```

## One engine, one report model

Two rules keep the application from growing a second, untested brain.

**No second forensic engine.** The API schedules `analyze_batch` and reads
rows. No endpoint recomputes a score, re-derives a severity or counts anything
the engine already counted.

**One canonical report model.** `reporting/report_model.py` is built by
*selection and structuring only*. JSON, HTML and PDF all render it, so a fact
in two formats comes from one place. A Jinja template that recalculated a score,
or a React component that summed severities in JavaScript, would be a second
engine with no tests — and the first time it disagreed with the real one, the
report would be wrong in a way nobody could see.

`tests/test_backend.py::test_all_three_formats_agree_on_the_facts` compares
capture ids, session counts, finding ids, severities, policy version, score,
remediation ids, blast-radius subjects and ML validation status across all
three.

## Components

| Module | Responsibility |
|---|---|
| `backend/database.py` | SQLite schema, `PRAGMA user_version` migrations, restart recovery |
| `backend/storage.py` | Private capture storage: server-generated ids, streaming limits, magic-byte validation |
| `backend/service.py` | Bounded worker pool, job status, transactional persistence |
| `backend/schemas.py` | Typed API contracts, separate from the engine's evidence models |
| `backend/security.py` | Host allowlist, CORS origins, local token |
| `backend/app.py` | Routes and middleware |
| `backend/server.py` | Entry point; refuses to bind a non-loopback interface |
| `reporting/report_model.py` | The canonical report |
| `reporting/html_report.py` | Standalone HTML, autoescaped, self-contained |
| `reporting/pdf_report.py` | A4 PDF via ReportLab Platypus |
| `frontend/` | React + TypeScript + Vite + Tailwind |

## Why PDF is built from the model, not from the HTML

An HTML-to-PDF renderer resolves what the document references: stylesheets,
fonts, images, and with some engines `file://` URLs. Report content derives from
captures, which are untrusted, so a fetching renderer would turn a malicious
certificate subject into a local file read or an outbound request.

ReportLab's Platypus has no URL resolver at all. The guarantee is structural
rather than a filter that has to be kept correct. Parity with HTML comes from
the shared model, not shared markup.

## Analysis execution

A `ThreadPoolExecutor` with two workers. Analysis is CPU-bound and a local tool
has one user; a large pool would make every job slower and the interface less
responsive.

* **Real progress.** The engine reports each capture as it finishes, so
  `captures_done / captures_total` is a fact. Within one capture there is a
  named stage but no fraction, which is why the interface switches to an
  indeterminate indicator there instead of animating a timer.
* **No duplicate jobs.** Starting the same investigation twice is refused:
  two workers writing the same rows would corrupt them.
* **One transaction.** Sessions, findings, intelligence, ML and the summary
  commit together, so findings can never point at sessions that were not
  stored.
* **Conservative restart.** A job left `QUEUED` or `RUNNING` by a dead process
  is marked `FAILED` with its reason. It produced no results, and a job still
  marked running would either spin for ever or be read as complete.
* **No cancellation.** A running analysis finishes or fails. There is no
  endpoint, no `CANCELLED` status and no button, and
  `tests/test_reliability.py` asserts their absence so the gap cannot be
  mistaken for a broken control.

M8 added tests that hold this description to the code:
`test_the_worker_model_is_a_bounded_thread_pool` asserts the pool type and
`max_workers == 2`, so this section cannot drift away from what runs. Six
concurrency scenarios — simultaneous uploads, identical uploads, reads during
an analysis, concurrent exports in three formats, duplicate analyse requests
and a capture deleted mid-investigation — are exercised in
`tests/test_reliability.py`.

Because both workers share one process, they also share its memory. A single
6,000-packet analysis reaches about 625 MB of resident memory; two of that size
at once approach the 2 GB budget derived for an 8 GB machine. See
[performance-benchmarks.md](performance-benchmarks.md).

## Frontend

React 18, TypeScript in strict mode, Vite, Tailwind and Recharts. Nine primary
areas, client-side routing with direct navigation to investigations and
sessions, and the selected investigation persisted in `sessionStorage` so a
refresh does not lose context.

Three conventions run through it:

**Unknown is rendered as unknown.** The shared `Value` component distinguishes
`UNKNOWN`, `NOT AVAILABLE` and `NOT APPLICABLE`, because a TLS 1.3 certificate
that is encrypted is not the same as one that was missed. A blank cell or a
zero would collapse the distinction the engine worked to preserve.

**No decorative state.** Every spinner corresponds to a request in flight;
progress is determinate only when the backend reports a proportion; there are
no fake terminals, no invented statistics and no controls that do nothing.

**An error boundary, so a bug never blanks the page.** A forensic tool that
renders nothing is worse than one that says it failed: an analyst cannot tell an
empty investigation from a crashed component. (This was not theoretical — a
render bug found during end-to-end testing produced exactly that blank page.)

## What the application does not add

No Docker, Redis, PostgreSQL, Celery or Kubernetes. No telemetry. No cloud
call. No outbound request of any kind. The CLI continues to work on its own,
and the engine remains usable as a library.
