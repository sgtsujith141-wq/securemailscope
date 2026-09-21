# Security audit

An internal review of the local API, the reports and the analysis engine,
carried out as part of M8. Every claim below is backed by a test in
`tests/test_security_audit.py`, `tests/test_robustness.py` or
`tests/test_report_hardening.py` that fails if the control is removed.

**This is not a penetration test and not a security certification.** No
external assessor was involved, no fuzzing campaign was run against a deployed
instance, and no formal threat model was reviewed by a third party. What
follows is a developer's audit of a local-only tool.

**The application is not safe to expose to a network.** It is designed to
listen on the loopback interface of one machine and is not hardened for
anything else. Do not put it behind a public address, a tunnel or a reverse
proxy on a shared host.

## Threat model

The application runs on the analyst's own machine and binds to 127.0.0.1. That
does not make it unreachable. Two attacks come *from* the local machine and
bind-address alone stops neither:

- **A web page the analyst visits** can issue requests to `http://127.0.0.1:8765`.
  The browser will send them; the same-origin policy governs only whether the
  page can *read* the reply.
- **DNS rebinding** lets an attacker-controlled hostname resolve to a public
  address on first load and to 127.0.0.1 afterwards, so the page's own origin
  becomes the local service.

A third source of risk is the data itself: every string in a report — server
names, cipher suite labels, certificate subjects, SNI values — comes from an
untrusted packet capture and is later rendered in a browser.

## Controls

### Authentication: a per-installation local token

A 32-byte URL-safe token is generated at first start and stored beside the
database in the application data directory, outside the repository, with mode
0600. It is never embedded in committed frontend source; the browser client
fetches it at runtime. Comparison is constant-time (`secrets.compare_digest`).

Every data endpoint requires it. `tests/test_security_audit.py` parametrises
thirteen endpoints and asserts each answers 401 without the token, including
all three report export formats. `/api/health` is deliberately open and is
tested to carry neither the token nor any filesystem path.

### DNS rebinding: a host allowlist

The first thing the middleware does — before any handler and before the body is
read — is compare the `Host` header against `127.0.0.1`, `localhost` and `::1`.
Anything else is refused with 400. A rebound name reaches the socket but arrives
carrying the attacker's hostname, so it is rejected. Tested with three hostile
hostnames and with each allowed name.

### Cross-origin reads: an explicit origin list

CORS is configured with a fixed list of four origins (the Vite dev server and
the API's own port, on both `127.0.0.1` and `localhost`), never `*`, with
`allow_credentials=False`. Tested: a hostile origin receives no
`access-control-allow-origin` header at all; a permitted one receives exactly
itself; credentials are never allowed.

### CSRF: authority is a header, never ambient

There are no cookies and no session state, so there is nothing for a browser to
attach automatically. A cross-site request can be *sent*, but the browser will
not add the token header on its own, and a cross-origin script cannot read the
token in order to add it. `test_there_are_no_cookies_so_there_is_no_cookie_csrf`
drives four state-changing endpoints from a token-less client carrying a hostile
`Origin` and asserts each is refused.

### Response headers

Every response carries `x-content-type-options: nosniff`,
`x-frame-options: DENY`, `referrer-policy: no-referrer` and
`content-security-policy: default-src 'none'; frame-ancestors 'none'`.

### Input handling

*Identifiers.* Path parameters are used as database lookup keys, never to build
a filesystem path or a SQL string. Twelve hostile values — SQL fragments,
traversal sequences, template expressions, a JNDI lookup string, a
right-to-left override, 2,000 characters of padding — are driven through five
endpoint templates and must answer 400, 404, 405 or 422, never 200, and must
not leak a traceback, an absolute path or a database error.

*Sort and search.* The sort column is looked up in a fixed dictionary and an
unknown value answers 422; search terms are bound parameters. Each hostile
string is driven through both and the session count is re-checked afterwards,
which an executed `DROP TABLE` would have changed.

*Uploads.* The stored path and filename are server-generated; the client's
filename is a display label only. Four traversal filenames are uploaded and the
resulting stored path is asserted to be inside the storage root with no `..`
component. Content is validated by magic bytes while streaming, not by
extension — an `.exe`, a PDF, a shell script, an empty file and a three-byte
truncated header are all refused.

*Size.* The upload limit (512 MB by default) is enforced while streaming and
the partial file is deleted. Since M8 this answers **413**, not 422, so a
client can distinguish "too big" from "not a capture". Tested against a
purpose-built 64 KB-limit instance rather than by sending half a gigabyte.

*Collections.* Every collection endpoint has a maximum `limit` enforced by
FastAPI (`le=`), ranging from 100 to 2,000 depending on the endpoint. Tested:
one over the ceiling answers 422, the ceiling itself succeeds, and `limit=0`,
`limit=-1` and `offset=-1` are all refused.

### Information disclosure

Unhandled errors are logged in full locally and answered with a short, fixed
body: `{"error": "internal_error", "detail": "the request could not be
completed. The reason was written to the local application log."}`. A test
raises an exception whose message deliberately contains both the data
directory path and the token, then asserts neither appears in the response.

No static file route serves the application data directory. Seven paths —
including `/app.sqlite3`, `/api.token`, `/.env`, `/.git/config` and two
traversal attempts — are asserted to answer 401, 404, 400 or 405 and never to
contain the token.

### Reports

*No execution.* The HTML report is rendered through Jinja2 with autoescape on.
Thirteen hostile titles, including four distinct script-injection payloads and
a Jinja expression, are rendered and asserted not to produce executable markup
— while still appearing in the document, because escaping must not mean
discarding.

*No fetching.* `render_html` calls `find_external_references` on its own output
and raises rather than returning a report that would load a font, script,
stylesheet or image when opened. The PDF is built from the report model
directly through ReportLab Platypus, which has no URL resolver. A structural
check walks the PDF catalogue and every page annotation for `/OpenAction`,
`/AA`, `/JavaScript`, `/Launch`, `/SubmitForm` and `/URI` actions.

*Nothing hidden.* Every CRITICAL and HIGH finding present in the JSON export is
asserted present in both the HTML and the PDF. Since M8 all three formats print
the `finding_id` in full, so a finding can be cross-referenced between them;
before M8 only the JSON did.

### Passive operation

The engine never opens a socket. `tests/test_robustness.py` installs a
`_BlockedSocket` fixture that replaces `socket.socket`, `socket.create_connection`,
`socket.getaddrinfo` and `socket.gethostbyname` with functions that raise, then
runs analysis over five fixtures, a batch analysis and all three report
renderers. A separate test asserts no engine module imports `requests`,
`urllib3`, `httpx`, `aiohttp`, `http.client`, `ftplib`, `smtplib`, `imaplib`,
`poplib` or `telnetlib`.

Scapy is the live hazard: it emits real ARP or NDP when asked to build a link
layer with an unresolved MAC. `securemailscope.scapy_guard` replaces its
neighbour resolver with one that raises.

**The one network path that does exist** is the browser talking to the local
backend over loopback — the dashboard fetching from `127.0.0.1:8765`. That is
the application's own user interface, not contact with an observed host, and no
capture content is sent anywhere beyond that process boundary.

## Findings from this audit

Six defects were found and fixed during M8. Each has a regression test.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Low | Four investigation sub-collections answered 200 with an empty page for an investigation that does not exist, while the detail route answered 404. An analyst who mistyped an id saw "0 findings" rather than "not found". | Fixed |
| 2 | Low | An oversized upload answered 422, indistinguishable from a malformed one. | Fixed: now 413 |
| 3 | Informational | `HTTPException` bodies used Starlette's `{"detail": ...}` while the middleware used the application's `ErrorResponse`, so a client had to understand two error contracts. | Fixed: one shape, `detail` retained |
| 4 | Low | The HTML and PDF reports omitted the `finding_id`, so a finding could not be cross-referenced back to the JSON export. | Fixed |
| 5 | Low | Six filter controls had a placeholder but no accessible name. | Fixed |
| 6 | Low | `hypothesis`, `starlette` and `joblib` were imported but undeclared. | Fixed; see `docs/dependency-audit.md` |

No high or critical finding was identified in this audit. That is a statement
about what this review covered, not a claim that none exists.

## What this audit did not cover

- No third-party assessment, formal threat model review or penetration test.
- No fuzzing campaign against a running instance; the property-based tests in
  `tests/test_robustness.py` generate inputs but run for bounded examples.
- No review of the Python interpreter, the operating system, or the browser.
- No assessment of physical or multi-user access to the machine. Anyone with
  the analyst's user account can read the token file and the database.
- No audit of the cryptographic *content* of captures beyond what the engine
  reports; this is an audit of the application, not of the traffic it analyses.
- Development dependencies carry five known advisories that require
  semver-major upgrades. See `docs/dependency-audit.md`.
