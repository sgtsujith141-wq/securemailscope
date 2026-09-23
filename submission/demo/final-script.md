# Final script — the finished video

The video is built, not planned: `scripts/build_demo_video.py` assembles it
from a Playwright recording of the real application and the beat log that
recording produced. This sheet describes what was built.

**`submission/final/SecureMailScope-SIH26159-Demo.mp4` — 3 min 11 s,
1920x1080, 30 fps, H.264 CRF 18, AAC.**

## Structure

| # | Element | Content |
|---|---|---|
| 1 | Title card | SecureMailScope · the problem statement title · SIH26159 · NTRO · Zero-Day |
| 2 | Section card | *The problem* — encryption is visible; whether the cryptography is sound is not |
| 3 | Footage | The first-run screen: passive by design |
| 4 | Section card | *What goes in* — PCAP/PCAPNG already held; format read from the bytes |
| 5 | Footage | Nine synthetic captures uploaded, then analysed at real speed |
| 6 | Footage | The investigation dashboard: the attention hero, the posture arc, the four cryptographic modules, priority findings and the evidence timeline |
| 7 | Section card | *Evidence, not assertion* |
| 8 | Footage | The findings workspace, one finding in full, and the packets it was evaluated against |
| 9 | Footage | A session as a negotiation chain, tinted where a finding was raised |
| 10 | Section card | *Stated limits* — unknown is rendered as unknown |
| 11 | Footage | A TLS 1.3 certificate reported NOT AVAILABLE, with the reason |
| 12 | Section card | *Across captures* — fingerprints, entities, drift, correlation |
| 13 | Footage | Drift before/after, then the evidence timeline, then the ML page with its stated limits |
| 14 | Section card | *Verified, not asserted* — the real test counts |
| 15 | Footage | JSON, offline HTML and PDF export from one canonical model |
| 16 | End card | Passive · Local · Evidence-backed |

## Narration and captions

Every line is **both** spoken and burned in as a caption, and the same text is
written to `captions.srt` with the timings of the finished file. The voice is
synthesised by the operating system's speech engine; `demo-verification.md`
says so plainly. The video is fully usable with the sound off.

Acronyms are spelled out for the synthesiser only ("T L S"); the caption on
screen keeps the normal spelling.

## Beats, as recorded

The recording timestamps each narrated moment itself, so a caption cannot
describe something the footage is not showing. Recorded offsets, in seconds
from the first frame of the raw capture:

| Beat | At |
|---|---|
| `first-run` | 1.8 s |
| `upload` | 9.0 s |
| `analyse` | 15.6 s |
| `dashboard` | 18.5 s |
| `modules` | 25.9 s |
| `rows` | 32.9 s |
| `findings` | 40.6 s |
| `finding-detail` | 46.9 s |
| `evidence` | 54.2 s |
| `session` | 61.8 s |
| `tls13` | 71.6 s |
| `drift` | 78.6 s |
| `timeline` | 86.7 s |
| `ml` | 93.7 s |
| `reports` | 101.0 s |
| `end` | 110.2 s |

Raw footage: 112.8 s. The finished video is longer
because of the cards and because a shot is held, never sped up, when its line
of narration runs past it.

## Rebuilding

```bash
python scripts/build_demo_dataset.py
cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture && cd ..
.venv-release/bin/python scripts/build_demo_video.py
```

Add `--silent` to build the same cut with captions and no audio.

Status: **VIDEO COMPLETE.** Nothing has been uploaded; no public URL exists.
