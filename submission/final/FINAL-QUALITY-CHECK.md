# Final quality check

Every result below was re-run against this working tree on 2026-09-23. Nothing
is carried forward from an earlier milestone.

Baseline commit at time of running: `bfc7be1049bf2ae28461e6dcd26636e17d342ce1`

## Automated gates

| Gate | Command | Result |
|---|---|---|
| Backend tests | `pytest -q` | **1,354 passed**, 25 skipped |
| TShark cross-check | `SECUREMAILSCOPE_TSHARK=1 pytest -q` | **1,364 passed**, 15 skipped |
| Lint | `ruff check .` | **clean** |
| Type check | `mypy` | **clean over 153 files** (`src/`, `tests/`, `scripts/`) |
| Frontend types | `npx tsc --noEmit` | **clean** |
| Frontend lint | `npm run lint` (`--max-warnings 0`) | **clean** |
| Frontend tests | `npm run test` | **88 passed** |
| Production build | `npm run build` | **clean**, 630 KB bundle |
| Browser end-to-end | `npx playwright test` | **5 passed** against the real backend |
| Python dependency audit | `pip-audit -r requirements-lock.txt` | **0 known vulnerabilities** |
| Frontend audit | `npm audit` | **0 vulnerabilities** (production and development) |

## Visual QA

Real application, four viewport widths, investigation workspace loaded:

| Viewport | Horizontal overflow | Failed requests | Console errors |
|---|---|---|---|
| 1920 × 1080 | none | 0 | none |
| 1440 × 900 | none | 0 | none |
| 1280 × 720 | none | 0 | none |
| 1024 × 768 | none | 0 | none |

## Presentation

| Check | Result |
|---|---|
| Page count | **exactly 6** |
| Official template retained | **yes** — headings, layout and visual identity untouched |
| Instruction slide removed | **yes** — asserted absent from the PPTX XML and the PDF text |
| Team name present as `Zero-Day` | **yes** — in both the PPTX XML and the extracted PDF text |
| `Your Team Name` | **absent** |
| `Team Zero Day` / `Team Zero-Day` / `Team zero day` | **absent** |
| `Zero Day` / `ZERO DAY` (wrong spellings) | **absent** |
| `SecureMailScope` present | **yes** |
| `SIH26159` present | **yes** |
| `Software` present | **yes** |
| Organisation present | **yes** — National Technical Research Organisation (NTRO) |
| Every page visually inspected | **yes** — rendered at 2× and reviewed individually |
| Clipped or overflowing text | **none** |
| Stretched or distorted screenshots | **none** — cropped to 16:9, never scaled non-uniformly |

All of the above are enforced by `scripts/build_presentation.py`, which reads
the PPTX XML and the extracted PDF text and **exits non-zero** on any failure.
The build cannot silently produce a deck with the wrong team name.

## Video authenticity

See `submission/demo/demo-verification.md` for the full table. Summary: all
footage is the genuine application on synthetic captures; no token, path,
personal data, terminal, notification or debug overlay appears; no analysis is
sped up to look instantaneous; no cursor is faked.

Status: **VIDEO EDIT READY · HUMAN NARRATION PENDING.** 29 seconds of
authentic 1080p/30fps B-roll exists. No finished video is claimed and nothing
has been uploaded.

## Git privacy

| Check | Result |
|---|---|
| Staged-file audit | `make secrets-check` clean before every commit |
| Full history audit | `scripts/audit_history.py` — every blob reachable from every ref |
| Captures in history | **none** |
| Key material in history | **none** |
| Tokens in history | **none** |
| Databases in history | **none** |
| Repository visibility | **private**, unchanged |

## Known unmet items

| Item | Status | Why |
|---|---|---|
| Official SIH26159 theme | **BLOCKED** | Not recorded in this repository. Deliberately not inferred from another problem statement, even one from the same organisation. |
| Team ID | **BLOCKED** | Issued by the SIH portal at registration; not derivable locally. |
| Finished demo video | **PARTIAL** | Authentic B-roll captured; narration requires a human voice. |
| Benchmarks on 4-core/8 GB | **NOT VERIFIED** | No such hardware available; recorded as unverified rather than estimated. |
| Contribution email verification | **NOT VERIFIED** | `gh api user/emails` needs the `user` OAuth scope, which is not granted. Existing author identity preserved unchanged. |
