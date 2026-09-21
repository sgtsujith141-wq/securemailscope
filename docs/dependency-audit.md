# Dependency and supply-chain audit

What SecureMailScope depends on, why, and what is known to be wrong with it.

## Principle

The forensic engine depends on three packages and nothing else. Everything that
is not needed to parse a capture and reach a verdict — the web framework, the
database layer, the report renderers, scikit-learn — is an optional extra. This
keeps the engine installable and testable on a machine that has none of them,
and it means a vulnerability in the web stack cannot reach the analysis path.

`tests/test_dependencies.py` enforces this rather than describing it:
`test_the_forensic_engine_does_not_import_the_web_or_ml_stack` walks the AST of
every engine module, and `test_the_engine_imports_with_only_its_required_dependencies`
imports the pipeline in a subprocess and asserts that `fastapi`, `sqlalchemy`,
`sklearn`, `uvicorn`, `reportlab` and `jinja2` are absent from `sys.modules`.

## Python dependencies

### Required (the engine)

| package | version | why |
|---|---|---|
| scapy | 2.6.1 | Packet dissection. Used for reading only; `scapy_guard` disables its neighbour resolver so it cannot emit a packet. |
| pydantic | 2.9.2 | The analysis and report models, and their JSON serialisation. |
| cryptography | 43.0.3 | X.509 parsing and RFC 5280 path verification. The TLS record and handshake layers do not need it; `certificates/` degrades to NOT_AVAILABLE without it. |

### Optional extras

| extra | packages | why |
|---|---|---|
| `dev` | pytest 8.3.3, ruff 0.7.4, mypy 1.13.0, hypothesis 6.119.4 | Test, lint, type-check. hypothesis generates the malformed-input cases in `tests/test_robustness.py`. |
| `backend` | fastapi 0.115.5, starlette 0.41.3, uvicorn 0.32.1, sqlalchemy 2.0.36, jinja2 3.1.4, python-multipart 0.0.17, reportlab 4.2.5 | The local API, persistence and report rendering. |
| `reporting-tests` | pypdf 5.1.0, pypdfium2 4.30.0, httpx 0.27.2 | Verifying generated PDFs, and the transport behind `fastapi.testclient`. |
| `ml` | scikit-learn 1.5.2, numpy 2.1.3, joblib 1.6.0 | Model training and inference. |

`starlette` and `joblib` are declared explicitly even though they arrive
transitively, because the source imports them directly — `backend/app.py`
registers a handler for the base `HTTPException` the router itself raises, and
`ml/registry.py` loads and saves artifacts with joblib. Relying on a transitive
works until the parent package changes its own floor.

### Enforced properties

| property | test |
|---|---|
| Every third-party import is declared | `test_every_third_party_import_is_declared` |
| Every declared dependency is pinned with `==` | `test_every_declared_dependency_is_pinned_exactly` |
| Every declared dependency is actually used | `test_every_declared_dependency_is_actually_used` |
| No dependency comes from a URL or a git reference | `test_no_dependency_is_fetched_from_a_url_or_a_git_reference` |
| The lock file agrees with what is declared | `test_the_lock_file_matches_what_is_declared` |

### The lock file

`requirements-lock.txt` records all 45 packages in the fully-resolved
environment, including transitive dependencies, pinned exactly. A clean
install from a bare checkout on 2026-09-21 resolved to exactly this set: zero
drift, nothing missing, nothing extra.

**Hashes are not pinned.** `pip install --require-hashes` would defend against
an index serving different bytes under the same version; this project does not
use it. What the lock file does give is reproducibility of *versions*, which
catches a resolver picking up a different release. Adding hash pinning is a
reasonable future step and is recorded as not implemented rather than implied.

## Node dependencies

The frontend has 48 production and roughly 350 development packages.

### Known advisories

Checked with `npm audit` on 2026-09-21.

**Production bundle: zero known vulnerabilities** (`npm audit --omit=dev`).
Getting there required one upgrade during M8:

- `react-router-dom` 6.28.0 → **7.18.4**. Versions before this carried three
  advisories — XSS via open redirects, an open redirect via protocol-relative
  URLs, and an open redirect via a backslash in `<Link>` and `useNavigate`.
  This was the only advisory that reached code shipped to a browser. The
  application uses `BrowserRouter`, `Routes`, `Route`, `NavLink`, `Link`,
  `Navigate` and `useParams`, all unchanged in v7; the upgrade required no
  source changes and passes the full unit, type, lint and end-to-end suites.

Four further non-major upgrades were applied at the same time:
`vite` 5.4.11 → 5.4.21, `vitest` 2.1.5 → 2.1.9, `postcss` 8.4.49 → 8.5.28,
`@playwright/test` 1.49.0 → 1.55.1, `@vitejs/plugin-react` 4.3.3 → 4.7.0.

### Accepted, with reasons

Five advisories remain, all in development-only packages and all requiring a
semver-major upgrade:

| package | severity | advisory | why it is accepted |
|---|---|---|---|
| vitest | critical | RCE when the Vitest API server is listening and a malicious site is visited | Requires `vitest` 5.x (from 2.x). The API server is not enabled in this project's configuration; `npm run test` runs `vitest run`, which exits when the run ends. Exposure is limited to a developer machine during a test run. |
| @vitest/mocker | moderate | Path traversal / arbitrary file read via a redirect mock | Same upgrade. The project does not use `vi.mock` redirects. |
| vite | high | `server.fs.deny` bypass; dev server readable by any website | Requires `vite` 8.x (from 5.x). Applies to `npm run dev` only, never to the built bundle. |
| esbuild | moderate | Any website can send requests to the dev server and read the response | Same upgrade, same scope. |
| vite-node | moderate | Inherited from vite | Same upgrade. |

None of these ships to a browser: `npm run build` produces a bundle containing
none of them, which is why CI gates on `npm audit --omit=dev --audit-level=moderate`
and reports the development set here instead of failing the build.

The mitigation for all five is the same and is a matter of practice rather than
code: do not browse the web while a Vite dev server or a Vitest API server is
listening. Upgrading vite to 8.x and vitest to 5.x is the real fix and is
recorded as outstanding work, deferred because a two-and-three major-version
migration of the build toolchain is not verification work.

## Supply-chain posture

| control | status |
|---|---|
| Exact version pins in `pyproject.toml` | Implemented, enforced by test |
| Fully-resolved lock file including transitives | Implemented |
| Hash pinning (`--require-hashes`) | **Not implemented** |
| `package-lock.json` committed, CI uses `npm ci` | Implemented |
| No dependency from a URL, git ref or local path | Implemented, enforced by test |
| Engine dependency floor enforced | Implemented, enforced by test |
| Production npm tree audited in CI | Implemented |
| Development npm tree audited | Implemented, findings recorded above |
| Python advisory scanning (`pip-audit`, Dependabot) | **Not implemented** |
| Signed commits or tags | **Not implemented** |
| SBOM generation | **Not implemented** |

The four marked not implemented are genuine gaps, listed so that nobody reads
this document as a claim that the supply chain is verified end to end.
