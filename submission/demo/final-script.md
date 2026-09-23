# Final script — timing and shots combined

Read with `narration.md` (the words), `shot-list.md` (the shots) and
`storyboard.md` (the intent). This is the single sheet to edit from.

| Time | On screen | Narration | Notes |
|---|---|---|---|
| 0:00 | Dark, one line | "Your email says it uses TLS." | Two-second beat |
| 0:04 | Cut to a real HIGH finding | "But is the cryptography actually secure?" | Answer before the question lands |
| 0:08 | Three cuts: TLS 1.0 · 59/100 · packets 4–5 | — | ~0.8s each, no narration |
| 0:12 | Title card | — | Restrained. Name and one line |
| 0:18 | Architecture reveal | The problem, and why a scanner cannot answer it | Left-to-right, matched to the words |
| 0:45 | First-run screen | Passive by design | **Slow down** |
| 1:00 | Upload, analyse | What the pipeline does | Real duration, small trim only |
| 1:20 | Investigation overview | "59 out of 100. Weak." | Hold on the attention hero |
| 1:40 | Finding → evidence expands | Why it was flagged, packets 4 and 5 | **Slowest section. The argument.** |
| 2:05 | TLS 1.3, certificate NOT AVAILABLE | What the tool refuses to guess | **Hold longer than comfortable** |
| 2:30 | Drift, two captures | Attributable to the server | Hold on OBSERVED_CHANGE |
| 2:55 | PDF export, PDF open | Three report formats | — |
| 3:10 | Montage, ~1s per frame | The closing statement | — |
| 3:22 | End card | — | SecureMailScope · SIH26159 · Zero-Day |

**Total: ~3:30.**

## Available footage

`local-evidence/footage/securemailscope-raw-1080p.mp4` — 29 s, 1920×1080,
30 fps, H.264. Genuine Playwright capture of the real application driving the
real backend and the real forensic engine on the synthetic demo dataset,
recorded by `frontend/e2e/demo-capture.spec.ts`.

It covers: first-run, upload, real analysis, the finding, the evidence panel,
the TLS 1.3 session, drift, and PDF export — the substance of shots 5 through
11. It is **B-roll**, not a finished cut: the beats are short because
Playwright holds them only briefly, and there is no narration, no title card
and no montage.

Regenerate with:

```bash
cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture
```

## What remains

1. Re-record or extend the held beats by hand, following `shot-list.md`
2. Record the narration (a human voice — see below)
3. Assemble with the title card, the architecture reveal and the end card
4. Burn in `captions.srt`

## Narration

**No narration track has been produced.** No natural, high-quality voice is
available in this environment, and a default text-to-speech read would make a
serious forensic tool sound like a short-form video. The script is written to
be read by a person at roughly 155 words per minute.

Status: **VIDEO EDIT READY · HUMAN NARRATION PENDING.**
