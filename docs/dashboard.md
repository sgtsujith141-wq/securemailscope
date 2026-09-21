# The dashboard

A local investigation interface: React 18, TypeScript in strict mode, Vite,
Tailwind and Recharts.

## Visual direction

Calm dark navy, restrained security-status colour, high information density
without clutter. Colour carries meaning — severity, status — and is not used
decoratively. Layouts are responsive and contrast meets an accessible ratio
against the dark background.

There are no fake terminals, no decorative network graphs, no random
animations, no invented statistics and no controls that do nothing.

## Areas

| Area | Contents |
|---|---|
| **Overview** | Capture and session totals, protocol distribution, coverage, findings by severity, per-investigation scores and system capabilities |
| **Investigations** | Upload, analysis progress, the investigation list, stored captures |
| *Investigation workspace* | Capture inventory, partial failures, assessment, intelligence counts, ML summary, job history |
| **Sessions** | Searchable, sortable, filterable, paginated table; detail page per session |
| **Security findings** | Score and coverage beside each other, filters, expandable findings with evidence |
| **Cryptographic intelligence** | Fingerprints, entities, drift, correlations, blast radius |
| **Evidence timeline** | Ordered events with packet references and filters |
| **ML analysis** | Three clearly separated sections — see below |
| **Reports** | JSON, HTML and PDF export |
| **Settings** | Only settings the backend acts on |

Direct navigation to `/investigations/{id}` and `/sessions/{id}` works, refresh
preserves the selected investigation, and an unknown route shows a real
not-found page.

## Three conventions

### Unknown is rendered as unknown

The shared `Value` component distinguishes:

| State | Shown as | Means |
|---|---|---|
| `UNKNOWN` | `UNKNOWN` | The capture could have shown it and did not |
| `NOT AVAILABLE` | `NOT AVAILABLE` | Passive capture can never show it — a TLS 1.3 certificate |
| `NOT APPLICABLE` | `NOT APPLICABLE` | The concept does not apply here |
| absent list | `none` | Genuinely empty |

A blank cell or a zero would collapse a distinction the engine worked to
preserve. The overview separates the same three ideas at the top level:
**NO FINDINGS** (analysed, nothing failed), **NOT ANALYSED** (no analysis has
run) and **INSUFFICIENT EVIDENCE** (analysed, but coverage could not support a
score).

**A score is never shown as 0 when it is unavailable.** Those say opposite
things.

### No decorative state

Every spinner corresponds to a request in flight. Progress is determinate only
when the backend reports a proportion — `captures_done / captures_total` — and
becomes indeterminate within a single capture, where the engine reports a named
stage but no fraction.

### A high-severity finding is never hidden by the aggregate

The overview and the findings workspace both state that the score summarises
weighted control coverage and does not supersede an individual finding.
Coverage is always shown beside the score, because a score of 100 over 4%
coverage is a statement about very little.

## The ML section

§16 of the M7 directive asks for care here, because M6's result is easy to
misrepresent. The page has three separate sections:

1. **Deterministic rarity analysis — the detector in use.** Stated plainly as
   *a deterministic frequency table, not a machine-learning model*.
2. **Experimental anomaly model — not in use.** Isolation Forest, trained,
   evaluated and **not selected**. Shown for transparency with its held-out
   numbers beside the baseline's.
3. **Supervised risk classifier.** `NOT_VALIDATED` on every prediction, with
   its reasons: not confirmed threats, not calibrated probabilities.

**No benchmark number is written into the frontend.** All of them are read from
the versioned evaluation artifact the backend serves, so the interface cannot
drift from the model that produced them. A test supplies a distinctive value
and asserts it reaches the page.

## Evidence navigation

`EvidenceLink` is reusable and renders a control **only when there is something
real to show**. A packet reference that leads nowhere is worse than no link: it
implies evidence can be inspected when it cannot.

Expanding it shows capture id, session id, packet number, capture timestamp,
stream offset, the source observation and the evidence status — validated
metadata, never payload bytes — with a link through to the session.

Findings, timeline events, drift comparisons, correlations and ML results all
reach their evidence this way.

## Error handling

An error boundary wraps the routed content. A forensic tool that renders a
blank page is worse than one that says it failed: an analyst cannot tell an
empty investigation from a crashed component, and might conclude there is no
evidence when there is. The boundary states that the analysis data is intact
and that the fault is in the interface.

This was not hypothetical — a rendering bug found during end-to-end testing
produced exactly that blank page, which is why the boundary exists.

## Testing

32 component tests with Vitest and React Testing Library drive specific backend
states: empty, failed, unscored, unknown, model-unavailable. Four Playwright
tests drive the real backend end to end.
