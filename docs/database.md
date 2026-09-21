# Database

One local SQLite file, opened by one process. No server, no connection pool to
tune, no migration framework.

```
~/.securemailscope/securemailscope.sqlite3
```

Outside the repository by construction, so it cannot be committed.

## Design choices

**Normalised where it is queried, JSON where it is read whole.** Captures,
investigations, jobs, sessions and findings get real columns because the
interface filters, sorts and paginates on them. Cryptographic intelligence and
ML results are stored as JSON documents because they are always read in full;
normalising them would produce a dozen tables nothing ever joins against.

**Canonical identifiers, not surrogate keys.** `capture_id` is the SHA-256 of
the capture bytes; `session_id` and `finding_id` come from the engine. The
database stores the identity the evidence already has, so a packet reference
persisted here still means what it meant during analysis.

**No payload, ever.** Nothing in this schema holds reconstructed application
data, a credential, an email body or a private key. Stream records carry counts
and offsets.

**`PRAGMA foreign_keys=ON`, WAL journalling.** SQLite disables foreign keys by
default, which would let the schema drift into orphaned rows silently.

## Tables

### `captures`

| Column | Notes |
|---|---|
| `capture_id` | PK. `sha256:<hex>` over the file bytes |
| `storage_id` | Server-generated. The uploaded filename never reaches the filesystem |
| `original_name` | Display only, sanitised, never used to build a path |
| `stored_path` | Absolute path in private storage |
| `status` | `UPLOADED`, `ANALYZED`, `FAILED`, `DUPLICATE`, `EMPTY`, `DELETED` |
| `result_json` | The complete per-capture analysis document |

### `investigations`

Summary columns the overview and list pages read directly: capture and session
counts, finding count, `posture_score`, `score_status`, `score_band`,
`coverage_ratio`, policy identity, and JSON severity and protocol tallies.

`posture_score` is **nullable and means it**. A missing score is `NULL`, never
`0` — the two say opposite things.

### `jobs`

`status` is `QUEUED`, `RUNNING`, `COMPLETED` or `FAILED`. `captures_done` and
`captures_total` are real progress. `stage` names what the engine is doing.

### `sessions`

Denormalised for the session explorer: endpoints, protocol, TLS parameters,
certificate visibility, completeness, counts and per-session score. `detail_json`
holds the full detail the session page renders, assembled once at persist time
rather than re-derived from the analysis document on every page view.

### `findings`

One row per finding **per investigation**, with its severity, confidence,
category, priority, rank, policy version and `evidence_json` — the packet
references, which are metadata only. The primary key is
`(finding_id, investigation_id)`: the id identifies the finding, the pair
identifies the row. `GET /api/findings/{finding_id}` accepts an optional
`investigation_id` to say which investigation's copy is wanted; without it any
copy is returned, which is unambiguous because the rows differ only in the
investigation they belong to.

### `intelligence`, `ml_results`, `report_exports`

The investigation document, the ML metadata with `classification_validation_status`
as a first-class column, and a record of every generated report.

`classification_validation_status` is a column rather than a JSON field so the
interface cannot render a classifier prediction without it.

## Migrations

`PRAGMA user_version` plus an ordered list of steps in `database.py`:

```python
_MIGRATIONS = (_migration_1, _migration_2)
```

Each step applies when `user_version` equals its index and then increments it.
Adding a migration means appending a function and bumping `SCHEMA_VERSION`;
they run automatically on start and are idempotent.

### `_migration_2` — composite keys on `sessions` and `findings`

Added in M8, fixing a defect that made a capture usable in exactly one
investigation. Both `session_id` and `finding_id` are deterministic digests of
their own content — that is the point of them, and it is what makes a finding
citable across a report, a dashboard and a JSON export. But while each was a
single-column primary key, analysing the same capture in a second
investigation produced the same ids again, the insert failed with
`UNIQUE constraint failed: findings.finding_id`, the whole persist transaction
rolled back, and the second investigation was marked FAILED carrying a raw
SQLAlchemy error.

The key on each table is now `(session_id, investigation_id)` and
`(finding_id, investigation_id)`. SQLite cannot alter a primary key, so the
migration rebuilds each table: drop the indexes SQLite carries across a
`RENAME`, create the new shape from the model metadata, copy every row, drop
the old table. Every existing row satisfies the wider key, because the old one
was strictly stricter, so nothing is lost. The step is a no-op on a database
that already has the composite key, which is what a freshly created one gets
from `_migration_1`.

`tests/test_reliability.py` covers both directions: a version-1 database built
by narrowing the real DDL is migrated with its rows intact and no leftover
scaffolding, and re-running the migration on a current database changes
nothing.

Alembic would be the usual answer and would be a great deal of machinery for a
single-file local database.

## Transactions

`Database.session()` is a transactional scope: commit on success, roll back on
any exception. An investigation's results — sessions, findings, intelligence,
ML, summary — are written in **one** transaction, so a partial write cannot
leave findings pointing at sessions that were never stored.

## Restart recovery

On start, any job left `QUEUED` or `RUNNING` is marked `FAILED` with a stated
reason. A process that died mid-analysis produced no results, and a job still
marked `RUNNING` would either spin for ever in the interface or, worse, be read
as complete. Neither is true.

Re-running the analysis is the remedy. The uploaded capture is still in
storage, and previous investigations are never discarded.

## Retention and deletion

There is no automatic expiry. Deleting a capture is explicit, removes the
stored bytes and **keeps** the analysis results: deleting evidence does not
retract what was already observed. The capture row survives with status
`DELETED` so the investigation still names what it analysed.
