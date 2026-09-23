# Final quality check

Every result below was re-run against this working tree on 2026-09-23. Nothing is
carried forward from an earlier milestone, and no number here is an estimate.

- **Branch:** `main` · **Repository:** private, unchanged
- **Nothing submitted, nothing uploaded, no licence added, visibility unchanged**

## Automated gates

| Gate | Command | Result |
|---|---|---|
| Backend tests | `pytest -q` | **1,357 passed**, 25 skipped |
| TShark cross-check | `SECUREMAILSCOPE_TSHARK=1 pytest -q` | **1,367 passed**, 15 skipped |
| Lint | `ruff check .` | **clean** |
| Type check | `mypy` | **clean, 156 files** (`src/`, `tests/`, `scripts/`) |
| Frontend types | `npx tsc --noEmit` | **clean** |
| Frontend lint | `npm run lint` (`--max-warnings 0`) | **clean** |
| Frontend tests | `npx vitest run` | **89 passed** |
| Production build | `npm run build` | **clean** |
| Browser end-to-end | `npx playwright test` | **5 passed**, real backend |
| Visual QA sweep | `npx playwright test visual-qa` | **passed**, 40 page loads |
| Python dependency audit | `pip-audit -r requirements-lock.txt` | **no known vulnerabilities** |
| Frontend audit | `npm audit --omit=dev` | **0 vulnerabilities** |
| History secret scan | `python scripts/audit_history.py` | **clean**, 796 blobs across every ref |
| Staged-file check | `scripts/check_staged.sh` | **clean** |

## Visual QA

Measured in a real browser against the real backend, on an analysed
investigation, by `frontend/e2e/visual-qa.spec.ts`. Every page of the
application at every supported size; the transcript is
`local-evidence/visual-qa.json`.

| Viewport | Pages checked | Horizontal overflow | Failed requests | Console errors |
|---|---|---|---|---|
| 1920 × 1080 | 10 | none | 0 | none |
| 1600 × 1000 | 10 | none | 0 | none |
| 1440 × 900 | 10 | none | 0 | none |
| 1280 × 720 | 10 | none | 0 | none |

Screenshots were also inspected individually rather than merely produced.
Defects found and fixed that way, in this sprint:

- the sidebar stopped at one viewport height, so the page background showed
  beneath it on any page taller than the screen;
- the evidence timeline printed `00:00:00.000 UT` — the unit clipped mid-word
  by an offset counted against a different format;
- the headline said "6 high-priority issues" beside severity chips reading
  "7 HIGH", because the headline counted only the page of findings the
  dashboard had fetched;
- two deck captions named a capture count the image contradicted, and two more
  were clipped by the template's footer band.

## Defects found and fixed in the product

Three were real engine or API faults, each now covered by a test that fails
without the fix:

| Defect | Where | Regression test |
|---|---|---|
| A drift id identified several comparisons at once, so a report could not cross-reference any one of them | `intelligence/drift.py` | `test_intelligence.py::test_a_drift_id_identifies_exactly_one_comparison` |
| A session opened in one investigation listed its findings once per investigation that contained the same capture — four findings rendered as eight | `backend/app.py` | `test_backend.py::test_a_session_shown_twice_does_not_duplicate_its_findings` |
| One intelligence tab rendered the previous tab's rows under its own schema while loading | `frontend/src/pages/Intelligence.tsx` | `app.test.tsx` — "does not render one section's rows under another section's tab" |

## SIH26159 requirement coverage

`submission/final/REQUIREMENT-COVERAGE.md` — **35 requirements audited**:
29 IMPLEMENTED, 6 PARTIAL, 0 NOT VERIFIED, 0 NOT IMPLEMENTED.

The six PARTIALs are five certificate requirements limited by TLS 1.3
encrypting the Certificate message, and the ML requirement, where the selected
anomaly method is a deterministic baseline and the supervised classifier is
`NOT_VALIDATED`.

## Submission artefacts

| Artefact | State |
|---|---|
| Six-slide deck | Built on the official template. Every title-page field resolved; the build fails on an `[UNRESOLVED]` marker, a seventh page, a wrong team name, a missing repository link or a missing video element. |
| Demonstration video | **Complete.** 3 min 11 s, 1920×1080, 30 fps, H.264 CRF 18, built from a Playwright recording of the real stack. Narration is synthesised and labelled as such. |
| Screenshots | 12, all regenerated from this build against the real backend. |
| Manifest | `MANIFEST.md` / `manifest.json` — SHA-256 of every file in the package. |

## Deliberately not done

- Nothing submitted to the SIH portal.
- No video uploaded anywhere; no public URL exists.
- Repository visibility unchanged (**private**).
- No licence added.
- No history rewritten, no branch force-pushed, no tag moved or deleted.
