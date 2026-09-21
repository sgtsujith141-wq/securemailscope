# Milestone 8 — Comprehensive verification, performance benchmarking, security hardening and release readiness

**Status: PARTIAL.** Fifteen of sixteen verification gates are met. One —
continuous integration — is reported NOT VERIFIED because no GitHub Actions run
has executed from this session, and claiming CI is green on the strength of
local passes is precisely the substitution this milestone forbids. Under the
milestone's own rule ("if any required gate fails, report M8 as PARTIAL"), that
makes M8 PARTIAL.

Everything else in the milestone is complete, and the work found real defects
rather than confirming what was already believed.

---

## 1. What this milestone was for

Not to add features. To establish whether what already exists actually works
under realistic and adverse conditions — and to say so honestly where it does
not.

## 2. Baseline

Confirmed before any change: `HEAD == origin/main == 48cd0d13`, clean tree,
1,201 passed / 25 skipped, 1,211 passed / 15 skipped with TShark, ruff clean,
mypy clean over 116 files.

## 3. Defects found

Eleven, each with a regression test that fails without the fix. Three were in
my own test and benchmark code and are listed because they were producing
misleading green results.

### The serious one

**A capture could belong to exactly one investigation, for ever.**

`session_id` and `finding_id` are deterministic digests of their own content.
That is deliberate: it is what lets a finding be cited across a report, a
dashboard and a JSON export and still mean the same thing. But each was also a
single-column primary key. Analysing the same capture in a second
investigation therefore produced the same ids again, the insert failed with
`UNIQUE constraint failed: findings.finding_id`, the whole persist transaction
rolled back, and the second investigation was marked FAILED carrying a raw
SQLAlchemy error in its job record.

An analyst who examined a capture on its own and then wanted it inside a
broader multi-capture investigation would get a failed analysis and a database
error. Nothing in the interface would explain why.

It stayed hidden through M7 because every test used either a fresh database per
investigation or the same investigation twice. It surfaced only when the M8
acceptance walkthrough and the older M7 end-to-end spec ran against one shared
backend — each passing alone, both failing together.

The fix is a schema migration (`_migration_2`, `SCHEMA_VERSION` 1 → 2) widening
both primary keys to `(id, investigation_id)`. SQLite cannot alter a primary
key, so each table is rebuilt: drop the indexes SQLite carries across a
`RENAME`, create the new shape, copy every row, drop the old table. Every
existing row satisfies the wider key because the old one was strictly stricter,
so no data is lost. The step is a no-op on a database that already has the
composite key. `GET /api/findings/{id}` and `GET /api/sessions/{id}` now accept
an optional `investigation_id` to choose a copy.

Four tests cover it: two investigations over one capture, scoped lookups, a
version-1 database migrated with its rows intact and no leftover scaffolding,
and the migration re-run as a no-op.

### The rest

| # | Defect | How it was found | Fix |
|---|---|---|---|
| 1 | `/jobs`, `/sessions`, `/findings` and `/exports` answered **200 with an empty page** for an investigation that does not exist, while the detail route answered 404. A mistyped id showed "0 findings" instead of "not found". | Hostile-identifier test in the security audit | `_require_investigation` on all four |
| 2 | An oversized upload answered **422**, indistinguishable from a malformed one. | Upload-limit test | New `UploadTooLarge`; answers **413** |
| 3 | `HTTPException` bodies used Starlette's `{"detail": ...}` while the middleware used the application's `ErrorResponse`. A client had to understand two error contracts. | Observed while writing the 413 test | One handler, one shape; `detail` retained so the change is additive |
| 4 | The **HTML and PDF reports omitted `finding_id`** entirely. A finding in the HTML report could not be looked up in the JSON export. | Report parity test | Both now print it in full |
| 5 | Six filter controls had a **placeholder but no accessible name**. A placeholder is not a label and vanishes once the analyst types. | Accessibility test | `aria-label` on each |
| 6 | Selecting more files **replaced the upload staging list**, discarding already-uploaded captures and hiding the Analyse button — while the backend still held them. | The 22-step acceptance walkthrough | Appends instead of replacing; capture ids de-duplicated |
| 6a | The e2e restart supervisor deleted its request flag before killing the child, so the exit handler read the restart as a crash and tore the harness down. | The acceptance walkthrough failing at step 20 | Explicit state flag instead of a file probe |
| 6b | The restart step polled only for the API coming *back*, so it sailed past the old process still answering 200 and then hit a server mid-shutdown. Intermittent 500s. | An intermittent failure at step 21 | Wait for down, then for up |
| 7 | `hypothesis`, `starlette` and `joblib` were **imported but undeclared**, relying on what happened to be installed. | `tests/test_dependencies.py` | Declared; enforced by test |
| 8 | `ruff check .` walked `build/`, a setuptools artifact, and failed on copied sources. | The clean-install test | `extend-exclude` |
| 9 | The CI workflow tested Python 3.13 against a `requires-python = ">=3.12,<3.13"` pin. | The clean-install test | Matrix removed; 3.12 only |

### In my own verification code

| # | Defect | Why it mattered |
|---|---|---|
| A | `vitest` was collecting the Playwright specs, so `npm run test` printed `Test Files 2 failed \| 1 passed` beside `Tests 32 passed`. | A green-looking summary over a broken run |
| B | The benchmark harness clamped a negative stage difference to `0.0`, printing "security assessment: 0.0s". | Read as "this layer is free". It now measures each configuration over repeated runs and flags an increment smaller than the observed noise |
| C | Three frontend fixtures (`intelligence`, `ml`, `settings`) did not exist; vitest does not typecheck, so those tests passed on `undefined`. | Caught by `tsc --noEmit`; real fixtures captured from the running API |

Two further wrong assumptions were in tests I wrote, caught by the
property-based generator before they could mask anything: a capture declaring a
zero-length packet legitimately parses trailing zero bytes as further empty
records, and a 200,000-byte protocol line cannot be sent as a single pcap
record.

## 4. Performance

`benchmarks/thresholds.json` was written and **committed before** the results
it judges, so the order is visible in git history. Seven thresholds, each
derived from the deployment target — an analyst laptop with 4 cores and 8 GB.
An exploratory run had preceded the thresholds; that is disclosed inside the
thresholds file itself.

Four profiles, three repeats each, on Python 3.12.14 / macOS / 16 logical CPUs:

| profile | packets | median | packets/s | peak RSS | ground truth |
|---|---:|---:|---:|---:|---|
| small | 150 | 0.089 s | 1,686 | 190 MB | 25/25 sessions |
| medium | 1,200 | 0.859 s | 1,398 | 270 MB | 200/200 |
| large | 6,000 | 4.730 s | 1,268 | 625 MB | 1,000/1,000 |
| stress | 24,000 | 21.426 s | 1,120 | 1,800 MB | 4,000/4,000 |

**All 14 gated threshold checks passed.** Scaling exponent 1.060 (limit 1.2);
memory growth 75.7 KB/packet (limit 100) — the narrowest margin and the thing
most likely to fail first.

Ingestion, TCP reassembly, protocol and TLS analysis dominate at every size.
The security assessment adds roughly a third on top. ML inference is too small
to measure below the stress profile and is reported as within noise rather than
quoted.

## 5. Verification gates

| # | Gate | Result |
|---|---|---|
| 1 | Python test suite | **MET** — 1,350 passed, 25 skipped |
| 2 | With TShark cross-checks | **MET** — 1,360 passed, 15 skipped |
| 3 | `ruff` | **MET** |
| 4 | `mypy` | **MET** over 116 source files (`tests/`, `scripts/` outside scope) |
| 5 | Frontend unit tests | **MET** — 85 in 2 files |
| 6 | Frontend types and lint | **MET** |
| 7 | Frontend build | **MET** |
| 8 | End-to-end against the real stack | **MET** — nothing mocked |
| 9 | 22-step acceptance walkthrough with a backend restart | **MET** |
| 10 | Benchmark thresholds | **MET** — 14/14 |
| 11 | Ground truth under load | **MET** — every profile |
| 12 | Clean install from a bare checkout | **MET** |
| 13 | Lock file vs. a fresh resolve | **MET** — 45 packages, zero drift |
| 14 | Production frontend advisories | **MET** — zero |
| 15 | Nothing sensitive staged | **MET** |
| 16 | **Continuous integration green** | **NOT VERIFIED** |

## 6. New tests

196 tests added across six modules.

| module | tests |
|---|---:|
| `tests/test_security_audit.py` | 59 |
| `frontend/src/test/accessibility.test.tsx` | 53 |
| `tests/test_report_hardening.py` | 35 |
| `tests/test_robustness.py` | 24 |
| `tests/test_reliability.py` | 24 |
| `tests/test_dependencies.py` | 7 |
| `frontend/e2e/acceptance.spec.ts` | 1 spec, 22 steps |

Python suite: 1,201 → **1,350**. Frontend: 32 → **85**.

## 7. Security

Detailed in `docs/security-audit.md`. Six findings, all Low or Informational,
all fixed. No high or critical finding was identified — a statement about what
this review covered, not a claim that none exists.

`react-router-dom` 6.28 → 7.18.4 cleared the only advisory reaching the
production bundle; `npm audit --omit=dev` now reports zero. Five
development-only advisories remain, including one critical (`vitest`), all
requiring semver-major migrations. They are recorded with severity, scope and
reason for deferral rather than waived.

**No penetration test. No security certification. Not safe to expose to a
network.**

## 8. Clean installation

Executed, not asserted. From `git archive HEAD` into a fresh directory:

- **Engine only** (`pip install .`): installs with exactly three declared
  dependencies plus their transitives — 9 packages total. Importing the
  pipeline loads none of fastapi, sqlalchemy, sklearn, uvicorn, reportlab or
  jinja2. The CLI runs and analyses a real capture.
- **Full** (`[dev,backend,reporting-tests,ml]`): **1,346 passed, 25 skipped**,
  ruff clean, mypy clean — identical to the development environment.
- **Lock file**: zero drift against a fresh resolve; nothing missing, nothing
  extra.

## 9. What is not done

| Item | Status |
|---|---|
| Continuous integration observed to run | **NOT VERIFIED** |
| Analysis cancellation | **NOT IMPLEMENTED** (deliberate; absence is tested) |
| Hash-pinned dependencies | **NOT IMPLEMENTED** |
| Python advisory scanning | **NOT IMPLEMENTED** |
| SBOM | **NOT IMPLEMENTED** |
| Type checking of tests and scripts | **NOT IMPLEMENTED** (161 errors if widened) |
| Benchmarks on 4-core / 8 GB hardware | **NOT VERIFIED** |
| Five development-only npm advisories | **ACCEPTED, RECORDED** |
| Supervised classification | **NOT_VALIDATED**, unchanged |
| Rendered-pixel contrast sampling | **PARTIAL** (token level only) |

## 10. Documentation

New: `performance-benchmarks.md`, `security-audit.md`, `reliability-testing.md`,
`dependency-audit.md`, `release-readiness.md`, this report.

Updated: `requirements-matrix.md` (new **NOT VERIFIED** status; 46 new NFV
rows; NF13 and NF14 revised), `limitations.md`, `test-strategy.md`,
`deployment.md`.

## 11. Assessment

The milestone did what it was for. It found eight real application defects —
one of them serious enough that a capture could only ever belong to a single
investigation — three misleading-green defects in the verification code itself,
and two wrong assumptions in new tests. All were fixed rather than accommodated
by adjusting expectations. Every performance figure is measured, bounded by
stated conditions, and judged against thresholds committed beforehand.

The schema defect is worth dwelling on, because of how it was found. It was
invisible to 1,201 passing tests, to a full end-to-end run, and to a manual
walkthrough — every one of which used a fresh database or reused one
investigation. It appeared only when two independently-written end-to-end specs
were made to share a backend. That is an argument for the kind of testing this
milestone was for: the bugs that survive a green suite are the ones whose
preconditions the suite never creates.

M8 is **PARTIAL**, on one gate, for one reason: CI has not been observed to
run. That is the honest status and it is not waived.

## 12. Recommended next

**M9: submission preparation.** Not started here, as directed.

Before or alongside it, in order of value:

1. Trigger the CI workflow and record the result, closing the only unmet gate.
2. Widen `mypy` to `tests/` and `scripts/`, or state the exclusion in
   `pyproject.toml` with a reason.
3. Migrate vite 5→8 and vitest 2→5, clearing the five remaining advisories.
4. Add `pip-audit` and hash pinning.
5. Take one benchmark run on 4-core / 8 GB hardware, turning NFV46 from NOT
   VERIFIED into a measurement.
