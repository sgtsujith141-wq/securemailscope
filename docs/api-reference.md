# API reference

A local-only HTTP API over the SecureMailScope forensic engine. It binds to
`127.0.0.1`, validates the `Host` header, uses an explicit CORS origin
allowlist and a per-installation token. Interactive documentation is served at
`/docs` while the server is running.

**The API is an adapter, not an engine.** Every analytical value it returns was
computed by M1–M6 and persisted. No endpoint recomputes a score, re-derives a
severity or invents a count.

## Authentication

Every request except `/api/health`, `/docs`, `/openapi.json` and `/redoc`
requires:

```
x-securemailscope-token: <token>
```

The token is generated at first start, written to `~/.securemailscope/api-token`
with owner-only permissions, and never committed. Print it with
`python -m securemailscope.backend.server --print-token`. Comparison is
constant-time.

## Errors

```json
{ "error": "host_not_allowed", "detail": "…", "status_code": 400 }
```

| Status | Meaning |
|---|---|
| 400 | The `Host` header is not a permitted local name |
| 401 | Missing or wrong token |
| 404 | The resource does not exist |
| 409 | The request conflicts with current state — an analysis already running, or an export of an investigation with no analysed captures |
| 422 | The request was understood and rejected: a bad file, an invalid sort key, an out-of-range setting |
| 500 | An unexpected error. The reason goes to the local log; the response says only that it failed |

`detail` is written for a person. Stack traces, absolute paths and database
errors never appear in a response body.

## Pagination

Every collection endpoint returns:

```json
{ "items": [...], "total": 128, "offset": 0, "limit": 50 }
```

`total` is the true count, so a client never has to guess whether it has
everything.

---

## System

### `GET /api/health`

No token required.

```json
{
  "status": "ok",
  "tool_name": "securemailscope",
  "tool_version": "1.0.0",
  "report_schema_version": "1.4.0",
  "database_schema_version": 1,
  "ml_available": true,
  "ml_status": "COMPLETED",
  "analyzer_works_without_ml": true
}
```

### `GET /api/settings` · `POST /api/settings`

Only settings the backend acts on. `POST` validates every field and returns the
resulting state. `requires_reanalysis` lists the keys whose change affects
future analyses only — existing results are never rewritten.

---

## Captures

### `POST /api/captures`

`multipart/form-data` with a `file` field. Validation happens **while the
upload streams**, so an oversized file is abandoned before it is fully written.
The filename is never used to build a path; the container format is decided by
the file's magic bytes.

Uploading identical bytes twice returns the existing capture: the same bytes
are the same evidence.

- `422` — not a capture, empty, or over the limit.

### `GET /api/captures?offset&limit`

### `DELETE /api/captures/{capture_id}`

Removes the stored file. **Analysis results are kept** — deleting evidence does
not retract what was observed. Explicit user action only.

---

## Investigations

### `POST /api/investigations`

```json
{ "name": "Mail gateway review", "capture_ids": ["sha256:…", "sha256:…"] }
```

Several captures make a multi-capture investigation, which is what produces
cross-capture drift and correlation.

### `POST /api/investigations/{id}/analyze`

Queues the analysis and returns the job. `409` if one is already running for
that investigation — two workers writing the same rows would corrupt them.

### `GET /api/investigations` · `GET /api/investigations/{id}`

The detail response carries the investigation, its captures (including failed
ones, with reasons), its jobs, the policy identity, intelligence counts and the
ML summary.

### `GET /api/jobs/{job_id}` · `GET /api/investigations/{id}/jobs`

```json
{
  "status": "RUNNING",
  "stage": "analysed 1/2: capture.pcap",
  "captures_total": 2,
  "captures_done": 1
}
```

`captures_done / captures_total` is **real** progress. Within one capture the
engine reports a named stage but no fraction, which is why a client should show
an indeterminate indicator there rather than inventing one.

---

## Sessions

### `GET /api/investigations/{id}/sessions`

| Parameter | Effect |
|---|---|
| `offset`, `limit` | Pagination (limit ≤ 500) |
| `search` | Substring over session id, endpoints and cipher suite |
| `protocol`, `tls_version`, `capture_id` | Exact-match filters |
| `has_findings` | Sessions with or without findings |
| `sort` | `session_id`, `server`, `protocol`, `tls_version`, `packet_count`, `finding_count`, `posture_score` |
| `direction` | `asc` or `desc` |

An unknown `sort` is `422` rather than silently ignored: the column list is an
allowlist, so no caller-supplied string reaches SQL.

### `GET /api/sessions/{session_id}`

Connection metadata, TCP reconstruction counts, protocol observations, the
STARTTLS transition, TLS negotiation, certificate intelligence, findings and ML
observations. **Stream summaries carry counts and offsets only** — no
reconstructed payload.

---

## Findings

### `GET /api/investigations/{id}/findings`

Filters: `severity`, `category`, `rule_id`, `session_id`, `capture_id`,
`evaluation_status`. Only failed rules are findings; `UNKNOWN` evaluations are
not failures and never appear here.

### `GET /api/findings/{finding_id}`

Includes `evidence`: capture id, session id, packet number, capture timestamp,
stream offset, the source observation and its evidence status. Metadata only.

---

## Intelligence

### `GET /api/investigations/{id}/intelligence?section=`

`fingerprints`, `entities`, `drift`, `correlations`, `blast_radius`,
`warnings`, or omit `section` for the whole document.

### `GET /api/investigations/{id}/timeline`

Paginated, filterable by `event_type`, `session_id` and `capture_id`. Events
keep the engine's documented same-timestamp ordering.

### `GET /api/investigations/{id}/ml`

Returns the summary, the per-session results and the **versioned evaluation
record** read from the model artifact directory. Benchmark numbers come from
there rather than from any client, so they cannot drift from the model that
produced them.

`anomaly_detector_is_ml` is `false` when the selected detector is the
deterministic rarity baseline M6 chose. A client must not label it machine
learning, and this field is how it knows.

---

## Reports

### `GET /api/investigations/{id}/export/{json|html|pdf}`

All three are rendered from one canonical report model, so their facts cannot
disagree. Returns `409` when the investigation has no analysed captures and
`422` for an unknown format.

Reports carry packet references and never payload bytes, credentials, message
bodies or private keys.

### `GET /api/investigations/{id}/exports`

Previously generated reports, newest first.
