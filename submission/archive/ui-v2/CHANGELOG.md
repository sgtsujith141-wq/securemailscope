# ui-v2

The screenshot set from the interface that preceded the final redesign.

- **Source commit:** `35d2e3f07591d3fd26fffe45d4b8c3fee993febf`
- **Archived:** 2026-09-23T17:19:00Z
- **Contents:** 17 full-page captures at 1440x1100, taken by
  `demo-rehearsal.spec.ts` against the real backend on the synthetic demo
  dataset.

## Why it was superseded

The interface was judged flat and generic: four identical metric boxes at the
top of every page, a findings page that was a vertical stack of identical
rows, tables where a comparison was the content, and a single dark navy that
made every panel read the same.

The redesign that replaced it:

- **A command dashboard** — an attention hero stating the conclusion beside a
  posture arc, a per-session posture strip, four cryptographic modules of
  different shape, then priority findings beside the evidence timeline, then
  intelligence beside the report hand-off.
- **Findings as master/detail** rather than an accordion list.
- **The TLS handshake drawn as a chain**, each link tinted by the findings
  raised against it.
- **Drift as before/after pairs** rather than a six-column table, ordered so
  an observed change is not buried under "not comparable".
- **The timeline as a rail**, with each event's dot tinted by its evidence
  status.
- **A richer palette** — cyan, violet, emerald, amber and coral — used on
  rules, dots and bars, never as panel fills.

## Recovering it

```bash
git restore --source=35d2e3f07591d3fd26fffe45d4b8c3fee993febf -- submission/assets/screenshots-final/
```

Or open the PNGs in `screenshots/` directly. The current set lives in
`submission/assets/screenshots-final/` and uses the names section 21 of the
final directive specifies.
