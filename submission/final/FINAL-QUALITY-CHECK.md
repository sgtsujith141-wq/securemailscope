# Final quality check

Every result re-run against this working tree on 2026-09-23. Nothing carried
forward from an earlier milestone.

- **Commit at time of running:** `784b8737826974cf208bbbc9a0b38d8756077465`
- **Branch:** `main` · **Repository:** private, unchanged

## Automated gates

| Gate | Command | Result |
|---|---|---|
| Backend tests | `pytest -q` | **1,354 passed**, 25 skipped |
| TShark cross-check | `SECUREMAILSCOPE_TSHARK=1 pytest -q` | **1,364 passed**, 15 skipped |
| Lint | `ruff check .` | **clean** |
| Type check | `mypy` | **clean, 154 files** (`src/`, `tests/`, `scripts/`) |
| Frontend types | `npx tsc --noEmit` | **clean** |
| Frontend lint | `npm run lint` (`--max-warnings 0`) | **clean** |
| Frontend tests | `npm run test` | **88 passed** |
| Production build | `npm run build` | **clean** |
| Browser end-to-end | `npx playwright test` | **5 passed**, real backend |
| Python dependency audit | `pip-audit` | **0 known vulnerabilities** |
| Frontend audit | `npm audit` | **0 vulnerabilities** |

## Visual QA

Real application, investigation workspace loaded:

| Viewport | Horizontal overflow | Failed requests | Console errors |
|---|---|---|---|
| 1920 × 1080 | none | 0 | none |
| 1600 × 1000 | none | 0 | none |
| 1440 × 900 | none | 0 | none |
| 1280 × 720 | none | 0 | none |
| 1024 × 768 | none | 0 | none |

Screenshots were inspected individually, not merely produced. Three defects
were found that way and fixed: the posture band label clipped the score arc,
the severity strip stretched a full column for one value, and section accent
rules were being overridden by the panel shadow.

## SIH26159 requirement coverage

`submission/final/REQUIREMENT-COVERAGE.md` — **35 requirements audited**:
29 IMPLEMENTED, 6 PARTIAL, 0 NOT VERIFIED, 0 NOT IMPLEMENTED.

The six PARTIALs are five certificate requirements limited by TLS 1.3
encrypting the Certificate message, and the ML requirement, where the selected
anomaly method is a deterministic baseline and the supervised classifier is
`NOT_VALIDATED`.

## Presentation

| Check | Result |
|---|---|
| Page count | **exactly 6** |
| Official template retained | **yes** |
| Instruction slide removed | **yes**, asserted absent from PPTX XML and PDF text |
| `Zero-Day` present | **yes**, in PPTX XML and PDF text |
| `Your Team Name` | **absent** |
| `Team Zero Day` / `Team Zero-Day` / `Team zero day` | **absent** |
| `Zero Day` / `ZERO DAY` | **absent** |
| `SecureMailScope`, `SIH26159`, `Software`, NTRO | **all present** |
| Stale `SIH26164` / `CryptoDrishti` / `Phantom HQ` | **absent** |
| Visual share | **~45%** — 7 product screenshots plus diagrams across 6 slides |
| Every page rendered at 2× and inspected | **yes** |
| Clipped or overflowing text | **none** |
| Stretched screenshots | **none** — cropped to ratio, never scaled non-uniformly |

Enforced by `scripts/build_presentation.py`, which reads the PPTX XML and the
extracted PDF text and **exits non-zero** on any failure.

## Video

| Check | Result |
|---|---|
| Footage authentic | **yes** — Playwright against the real stack |
| Resolution / rate | 1920 × 1080, 30 fps, H.264 |
| Duration | 29.07 s of B-roll |
| Tokens, paths, personal data | **none** — frames inspected at 4, 12, 20, 26 s |
| Fake progress or cursor | **none** |
| Narration | **not recorded** |

Status: **VIDEO EDIT READY · HUMAN NARRATION PENDING.** No upload, no URL.

## Privacy audit

| Check | Result |
|---|---|
| Staged-file audit | `make secrets-check` clean before every commit |
| Full history audit | `scripts/audit_history.py` — 787 blobs across every ref |
| Captures / keys / tokens / databases in history | **none** |

The audit reported one finding during this sweep and it was a real defect in
the scanner: it matched the PEM banner inside its own pattern table. The
banner is now assembled at run time so current versions cannot self-match, and
the historical blobs are allowed by path with that reason recorded — silencing
the pattern would have blinded the scanner to a genuine key.

## Rollback

Verified: the archived deck PDF was extracted from history with `git show`
into a temporary directory and its SHA-256 matched the working copy byte for
byte, with the working tree untouched. See `docs/ROLLBACK.md`.

## Contribution attribution

| Field | Value |
|---|---|
| Authenticated GitHub user | `sgtsujith141-wq` |
| Repo-local author name | `sgtsujith141-wq` |
| Email attribution | **NOT VERIFIED** |
| Default branch | `main` |

`gh api user/emails` requires the `user` OAuth scope, which is not granted
here, so the configured commit email could not be confirmed against the
account. The existing author identity was preserved unchanged rather than
guessed at, and no historical commit was rewritten.

## Remaining blockers

| Item | Status | Why |
|---|---|---|
| Official SIH26159 theme | **BLOCKED** | Not recorded in this repository; deliberately not inferred from another problem statement |
| Registered Team ID | **BLOCKED** | Issued by the SIH portal at registration |
| Finished demo video | **PARTIAL** | Authentic B-roll captured; narration needs a human voice |
| Benchmarks on 4-core / 8 GB | **NOT VERIFIED** | No such hardware available |
| Publication / upload / submission | **AWAITING APPROVAL** | Each needs the team's decision |
