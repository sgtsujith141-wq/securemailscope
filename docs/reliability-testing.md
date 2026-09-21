# Reliability testing

How the application behaves when things go wrong: malformed captures,
exhausted limits, interrupted analyses, concurrent work, and a restart in the
middle of everything.

Three test modules cover this, all using isolated temporary databases and
storage directories. None touches a developer's real data, and none is capable
of exhausting the development machine.

| module | tests | subject |
|---|---:|---|
| `tests/test_robustness.py` | 24 | Malformed input, resource limits, passive operation |
| `tests/test_reliability.py` | 24 | Database integrity, migrations, transactions, restart, concurrency |
| `tests/test_report_hardening.py` | 35 | Reports under hostile and awkward input |

## Malformed input

The rule is simple: the parser may reject an input with a stated reason, or it
may parse it and find nothing, but it may never crash, and it may never invent
cryptographic evidence from data that does not contain any.

Tests use a helper that allows a *stated* rejection — a `SecureMailScopeError`
— but treats any other exception as a failure.

### Container level

| input | behaviour |
|---|---|
| Empty file | Rejected with a reason |
| Header only, no packets | Accepted, yields no sessions |
| Truncated pcap header (1–23 bytes, property-based) | Rejected or yields nothing |
| Arbitrary bytes after a valid header (property-based) | Never crashes |
| A packet whose declared length lies (0 to 0xFFFFFFFF, property-based) | Bounded: the reported file size still matches, the packet count stays within the trailer length, and no TLS is reported |
| An unsupported link type | Rejected with a reason |
| A real capture truncated mid-packet | Handled |

### TLS level

| input | behaviour |
|---|---|
| A TLS record whose length field lies (property-based) | No invented handshake |
| A handshake truncated at every offset (property-based) | No invented negotiation |
| Arbitrary bytes in a TLS payload (property-based) | Never yields a certificate |
| A malformed certificate | Reported as unparseable, never as valid |

### Protocol level

| input | behaviour |
|---|---|
| Arbitrary SMTP bytes (property-based) | Never produces a CONFIRMED credential finding |
| A protocol line far over the limit, sent in segments | Bounded; no event reports a line longer than the limit |

The property-based tests use `hypothesis` with 40 examples each and no
deadline. They generate the awkward cases rather than relying on the ones the
author happened to imagine.

## Resource limits

A limit that silently truncates is worse than no limit, because the result
looks complete. Three properties are tested:

- The session limit engages and **emits a warning**, so the output says it was
  applied.
- The packet limit marks the result **truncated** rather than reporting a
  complete analysis of a partial capture.
- A limited analysis still carries its evidence: what was analysed remains
  properly attributed.
- Many small packets stay bounded rather than growing without limit.

`AnalysisConfig` carries `max_capture_bytes`, `max_packets`,
`max_total_sessions` and `max_upload_bytes`, all adjustable from the Settings
page, which also states which of them require a re-analysis to take effect.

## Database integrity

Checked against a populated database after a real analysis:

- `PRAGMA integrity_check` returns `ok`.
- `PRAGMA foreign_key_check` returns no rows.
- `PRAGMA foreign_keys` returns 1 — SQLite disables foreign keys by default,
  and a schema whose constraints are declared but not enforced accumulates
  orphans silently. A separate test inserts a job referencing a non-existent
  investigation and asserts an `IntegrityError`, proving enforcement rather
  than configuration.
- Migrations are idempotent: opening an existing database does not re-run them
  and does not lose data.

## Transactional correctness

Persisting an investigation is one transaction. The demanding case is
**re-analysis**, because persisting begins by deleting the previous run's
sessions and findings. Without a rollback, a failure partway through would
leave the investigation with its old results destroyed and no new ones written.

`test_a_failed_persist_rolls_back_to_the_previous_good_state` analyses
successfully, then injects a failure *inside* the transaction, after the
deletes and capture-row updates have been issued. It asserts the job is FAILED,
the investigation is FAILED, and every original finding id is still present and
in the same order — then re-runs `PRAGMA integrity_check`.

A companion test covers a first analysis that fails to persist: the
investigation ends FAILED with zero findings, zero sessions and no orphaned
rows.

Other invariants:

- No COMPLETED job references results that were not written: the
  investigation's `session_count` and `finding_count` are asserted equal to the
  actual row counts.
- Re-running an analysis replaces its derived rows rather than accumulating
  duplicates beside them.
- A worker thread that raises marks the job FAILED with the error recorded,
  rather than leaving it stuck at RUNNING forever.

## Schema migrations

`PRAGMA user_version` with an ordered list of steps. Two properties are tested
rather than assumed:

- **Forward.** A version-1 database — built by taking the real DDL and
  narrowing the two primary keys back to a single column, so the columns,
  defaults and indexes are the real ones — migrates with its rows intact, with
  `PRAGMA integrity_check` clean and no `_old` scaffolding left behind.
- **Idempotent.** Re-running the migration on a current database leaves
  `sqlite_master` byte-identical: no table rebuilt, no index dropped.

`_migration_2` fixed a defect worth stating plainly. `session_id` and
`finding_id` are deterministic digests of their own content, which is what
makes a finding citable across a report, a dashboard and a JSON export. While
each was also a single-column primary key, analysing the same capture in a
second investigation produced the same ids again and the persist failed with
`UNIQUE constraint failed`, rolling the transaction back and marking the
investigation FAILED. A capture could belong to exactly one investigation.

`test_one_capture_can_be_analysed_in_two_investigations` is the regression: two
investigations over one capture both complete, both carry findings, the finding
ids are identical between them — as a content digest should be — and the
database stays clean.

## Restart and recovery

- **An interrupted job fails visibly.** On startup, `recover_interrupted_jobs`
  marks every RUNNING and QUEUED job as FAILED with "restarted" in the reason
  and a finish time, and marks its investigation FAILED. A restart never turns
  an interrupted job into a successful one.
- **A completed investigation survives intact.** The test analyses two
  captures, shuts the application down, starts a new `AppState` on the same
  directory, and asserts: zero jobs were recovered (a genuinely completed job
  is not touched), the finding count and posture score are unchanged, the
  finding ids are identical and in the same order, the evidence is still
  attached with real packet numbers, and a report still generates from the
  restored state.
- **A database that cannot be written fails loudly.** The file is made
  read-only and a write attempted; the error is raised to the caller, not
  swallowed.
- **A capture file removed behind the application** causes the analysis to
  FAIL with zero sessions, rather than fabricating a result.

## Concurrency

**The execution model, stated plainly:** a `ThreadPoolExecutor` with
`max_workers=2`, inside the API process. It is not a distributed task queue,
not a process pool, and not asynchronous. Two analyses run at once; a third
waits. `test_the_worker_model_is_a_bounded_thread_pool` asserts this, so the
documentation cannot drift away from the code.

| scenario | result |
|---|---|
| Five simultaneous uploads of different captures | Five distinct capture ids, table consistent |
| Six simultaneous uploads of **identical** bytes | One row. Identical bytes are one piece of evidence. |
| Reads polling continuously during an analysis | Every read returns 200; the investigation ends COMPLETED |
| Six simultaneous exports across three formats | All succeed and agree on the finding count |
| Four simultaneous analyse requests for one investigation | Persisted state is one consistent result |
| Deleting a capture that an investigation used | Integrity and foreign keys still clean; capture marked DELETED with its stored path cleared; the investigation's findings are not silently discarded |

### Cancellation is not implemented

There is no cancel endpoint, no CANCELLED status and no Cancel button. A
running analysis runs to completion or fails.
`test_cancellation_is_not_offered_because_it_is_not_implemented` asserts that
`POST .../cancel` and `DELETE /api/jobs/{id}` do not resolve to a route, that
no job ever reports CANCELLED, and that no registered route path contains
"cancel" or "abort". The absence is deliberate and tested, rather than a
control that looks available and does nothing.

## Reports under stress

Covered in detail in `docs/security-audit.md`. In summary: thirteen hostile or
awkward titles — script payloads, template expressions, a right-to-left
override, four thousand characters, emoji and five scripts of non-Latin text —
are rendered through all three formats without crashing, without becoming
markup and without vanishing. Long identifiers are printed in full rather than
truncated. An investigation built from every valid fixture at once (20+
captures) analyses, completes, and exports in all three formats within the
32 MB openability limit.

## Frontend reliability

`frontend/src/test/accessibility.test.tsx` (51 tests) covers:

- One `<h1>` per view; `navigation` and `main` landmarks present.
- Every navigation link has an accessible name and an `href`.
- Every button, link, select, textbox and checkbox on all eight pages has an
  accessible name. This caught six controls whose only label was a
  placeholder — which is not an accessible name and disappears once the analyst
  types. All six now carry an `aria-label`.
- Every table has a header row.
- The navigation is reachable by tabbing; no enabled control is removed from
  the tab order; focus is not trapped in any single control.
- Each of seven pages announces a failure with `role="alert"` rather than
  rendering an empty panel, and none claims a result while still loading.
- The navigation survives at 320, 480, 768 and 1024 pixels wide.
- Nine foreground/background token pairs meet WCAG 2.1 AA contrast, computed
  with the relative-luminance formula rather than judged by eye. The formula
  itself is checked against black-on-white (21:1) and white-on-white (1:1).

This is a token-level contrast check, not a rendered-pixel one: if a colour
changes in `tailwind.config.js` without the test being updated, the test will
not catch it.

## End-to-end

`frontend/e2e/acceptance.spec.ts` drives a real browser against the real
FastAPI application over the real forensic engine — nothing mocked — through
twenty-two numbered steps: upload two captures, have a third refused, analyse,
read the engine's own score, list and filter and search sessions, open a
session, open a finding, reach its packet evidence, inspect intelligence and
the timeline, check the ML page still states its M6 distinctions, read
settings, export all three formats and verify they agree, **restart the backend
process on the same data directory**, reopen the investigation and confirm the
score, session count, finding count and finding ids are unchanged, and export
again from the restored state.

No value is hardcoded from a previous run: each expectation is either a
property that must hold or a number the engine produced earlier in the same
test.

The restart step waits for the API to stop answering *and then* to answer
again. Waiting only for it to come back would sail past the outgoing process,
which keeps serving for up to a second after the restart is requested, and then
hit a server mid-shutdown — an intermittent 500 that looks like a product bug
and is not.
