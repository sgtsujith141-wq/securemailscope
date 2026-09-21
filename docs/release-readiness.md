# Release readiness

What has been verified, what has not, and what a person evaluating this project
should know before relying on it.

Assessed on 2026-09-21 at the end of M8.

## Overall

**Status: READY FOR DEMONSTRATION, NOT READY FOR PRODUCTION DEPLOYMENT.**

All sixteen verification gates are met, including continuous integration.

The application does what it claims on a developer or analyst machine, and the
claims have been checked rather than asserted. It is not hardened for any
environment other than the loopback interface of one trusted machine, it has
not been assessed by anyone outside this project, and several supply-chain and
validation gaps are open. Those are listed below rather than left for someone
to discover.

## Verification gates

Each gate is either met, met with a stated limit, or not met. None is waived.

| # | Gate | Result |
|---|---|---|
| 1 | Full Python test suite passes | **MET** — 1,350 passed, 25 skipped |
| 2 | Same suite passes with TShark cross-checks enabled | **MET** — 1,360 passed, 15 skipped; 10 cross-checks against an independent dissector |
| 3 | Lint clean | **MET** — `ruff` over the whole tree |
| 4 | Type check clean | **MET** — `mypy` over 116 source files. *Limit: `tests/` and `scripts/` are outside its configured scope.* |
| 5 | Frontend unit tests pass | **MET** — 85 tests in 2 files |
| 6 | Frontend type check and lint clean | **MET** — `tsc --noEmit`, `eslint --max-warnings 0` |
| 7 | Frontend builds | **MET** — 630 KB bundle, 180 KB gzipped |
| 8 | End-to-end suite passes against the real stack | **MET** — 5 specs, nothing mocked |
| 9 | 22-step acceptance walkthrough including a backend restart | **MET** |
| 10 | Benchmark thresholds met | **MET** — 14/14 gated checks |
| 11 | Ground truth matched at every benchmark profile | **MET** — including the stress profile |
| 12 | Clean install from a bare checkout | **MET** — engine-only and full, on Python 3.12 |
| 13 | Lock file matches a fresh resolve | **MET** — 45 packages, zero drift |
| 14 | Production frontend free of known advisories | **MET** — `npm audit --omit=dev`: zero |
| 15 | No capture data, key material or secrets staged for commit | **MET** — `make secrets-check` |
| 16 | Continuous integration green | **MET** — all five jobs green, run 35627938267 on commit `74ee1f1` |

All sixteen gates are met. Gate 16 is reported as met because a run was watched
to completion on GitHub Actions, not because local tests passed — that
substitution is exactly what this project is meant to avoid. The first run
failed two of five jobs; both failures were real defects, both were fixed, and
the rerun is green on Engine, Clean install, Frontend, End-to-end and
Benchmarks.

## What works, verified

- **Passive analysis.** The engine never opens a socket. Proven by replacing
  the socket constructors with raising stubs and running analysis, batch
  analysis and all three report renderers through them, plus an import-level
  check that no outbound client library is reachable from the engine.
- **Forensic pipeline.** Capture ingestion, TCP reassembly, email protocol
  analysis, STARTTLS detection, TLS record and handshake analysis, certificate
  parsing and RFC 5280 path verification — each with hand-derived expectations
  in committed manifests and cross-checked against TShark.
- **Security assessment.** A versioned policy with per-rule ownership,
  deterministic finding ids that change when the policy changes, and evidence
  references down to the packet.
- **Forensic intelligence.** Cryptographic fingerprints, server identity
  resolution, drift detection, cross-session correlation, an evidence timeline
  and blast-radius grouping, all derived from the analysis rather than
  reparsing.
- **Machine learning.** A rarity baseline in use and a trained anomaly model
  held back, with the distinction stated in the interface. Supervised
  classification reports `NOT_VALIDATED`.
- **Local application.** FastAPI over the unchanged engine, SQLite
  persistence, a React investigation interface, and JSON, HTML and PDF reports
  from one canonical model.
- **Reliability.** Atomic persistence with a tested rollback, visible failure
  of interrupted jobs on restart, six concurrency scenarios, and a schema whose
  migrations are tested in both directions — applied to a version-1 database
  without losing rows, and a no-op when re-run.
- **A capture may belong to several investigations.** Fixed in M8; before that
  the second investigation failed to persist and was marked FAILED with a raw
  database error.
- **Security controls.** A per-installation token, a host allowlist, an
  explicit CORS origin list, bounded collections, streamed upload validation
  and redacted error bodies — each with a test that fails if the control is
  removed.

## What does not work, or is not verified

| Item | Status | Detail |
|---|---|---|
| Analysis cancellation | **NOT IMPLEMENTED** | A running analysis finishes or fails. There is no endpoint, no CANCELLED status and no button. The absence is tested so it cannot be mistaken for a broken feature. |
| Certificate extraction on TLS 1.3 | **PARTIAL, permanent** | TLS 1.3 encrypts the Certificate message. No passive tool can read it. |
| Revocation checking | **NOT IMPLEMENTED, permanent** | Would require contacting an OCSP responder or fetching a CRL, which the passive-only rule forbids. `revocation_checks_performed` is 0 in every report. |
| Supervised risk classification | **NOT_VALIDATED** | Implemented and measured on synthetic data (macro-F1 0.5624). No independent representative validation has been obtained, so it is not fit for real-world use and the interface says so. Synthetic evaluation does not establish enterprise-wide accuracy. |
| Hash-pinned dependencies | **NOT IMPLEMENTED** | Versions are pinned and locked; bytes are not. |
| Python advisory scanning | **NOT IMPLEMENTED** | No `pip-audit` or Dependabot. |
| SBOM | **NOT IMPLEMENTED** | None generated. |
| Type checking of tests and scripts | **NOT IMPLEMENTED** | `mypy` covers `src/` only. A widened run reports 161 errors across 13 files, all in test and script code. |
| Five development-only npm advisories | **ACCEPTED, RECORDED** | vitest (critical), vite (high), esbuild, @vitest/mocker, vite-node. None ships to a browser. All need a semver-major migration. See `docs/dependency-audit.md`. |
| Benchmarks on the assumed minimum hardware | **NOT VERIFIED** | Thresholds are derived for 4 cores and 8 GB; the recorded run used a machine with 16 logical CPUs. |
| Contrast checking | **PARTIAL** | Computed from design tokens, not sampled from rendered pixels. |

## Known limits on the claims

**Memory is the binding constraint.** Peak resident memory is 625 MB for a
6,000-packet capture and 1.8 GB for a 24,000-packet one. The marginal cost is
about 76 KB per packet, against a 100 KB budget derived from an 8 GB machine.
Two analyses run concurrently in one process. The application should not be
described as handling 24,000-packet captures on the target hardware.

**All benchmarks are synthetic.** The corpus is generated from seven cipher
suites with a regular session structure. Real captures have retransmissions,
out-of-order segments and longer-lived connections. Nothing here measures
those.

**All ML evaluation is synthetic.** No real-world corpus was used, by design —
the project does not ingest private email traffic. Reported metrics describe
the synthetic dataset and nothing beyond it.

**The security audit is internal.** No third party assessed this. No
penetration test was performed. No security certification is claimed.

**Do not expose this to a network.** It is a local tool. The controls in place
are designed to resist a browser on the same machine, not a remote attacker.

## Provenance note

The requirements matrix is derived from the product definition and the
implementation directives, not from the canonical SIH26159 problem statement
text, which is not reproduced in this repository. When that text is attached,
the matrix must be reconciled against it line by line and anything missing
added with status `NOT IMPLEMENTED`.

## Commands

```
make check                                  # lint, type-check, test
SECUREMAILSCOPE_TSHARK=1 pytest -q          # with the independent cross-check
python scripts/run_benchmarks.py            # measure
python scripts/check_benchmarks.py          # judge against committed thresholds
make secrets-check                          # inspect the staging area
cd frontend && npm run test && npm run e2e  # frontend and end-to-end
```
