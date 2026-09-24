# Final script — the finished video

The video is built, not planned. `scripts/build_demo_video.py` assembles it
from a Playwright recording of the real application and the beat log that
recording produced. This sheet describes what was built.

**`submission/final/SecureMailScope-SIH26159-Demo.mp4` — 2 min 58 s,
1920x1080, 30 fps, H.264 High, CRF 16, AAC 192 kbps at -16.0 LUFS.**

## Structure

| # | Element | Content |
|---|---|---|
| 1 | **Cold open** | A real HIGH finding, already on screen: TLS 1.0, static RSA, no forward secrecy |
| 2 | Title card | SecureMailScope · SIH26159 · NTRO · Zero-Day |
| 3 | Footage | The first-run screen: passive by design, nothing leaves the machine |
| 4 | Footage | Nine synthetic captures uploaded |
| 5 | Footage | Analysis at real speed; sessions rebuilt, protocols identified, TLS inspected |
| 6 | Footage | The dashboard: 59/100 WEAK, seven high-priority findings |
| 7 | Footage | TLS posture across every session; the findings list |
| 8 | Footage | **The finding, and packets #4 and #5** — the longest held section |
| 9 | Footage | A TLS 1.3 session: certificate NOT AVAILABLE, with the reason |
| 10 | Footage | A second investigation over two captures of one service |
| 11 | Footage | Drift: negotiated version, OBSERVED_CHANGE, TLS 1.2 → TLS 1.0 |
| 12 | Footage | Export: JSON, standalone HTML, PDF — really downloaded on screen |
| 13 | Stills | Two pages of the PDF that was just downloaded |
| 14 | Footage | Closing montage: timeline, ML page, findings |
| 15 | End card | Passive · Local · Evidence-backed |

Three full-screen elements in total: the title card, the end card, and
nothing else. Everything between them is the product.

## Captions

Short supportive labels, not a transcript: "TLS 1.0 negotiated", "Packets #4
and #5", "Observed cryptographic drift". At most two lines, 46 px bold, on an
opaque band — readable on a projector and on a phone. The same text is written
to `captions.srt` with the timings of the finished file.

## Narration

See `narration.md` for the words and the voice. It is synthesised, and that is
said plainly there and in `demo-verification.md`.

## Beats, as recorded

The recording timestamps each shot itself, so a caption cannot describe
something the footage is not showing. Offsets in seconds from the first frame
of the raw capture:

| Beat | At |
|---|---|
| `firstrun` | 1.6 s |
| `upload` | 5.7 s |
| `analyse` | 10.1 s |
| `overview` | 12.4 s |
| `modules` | 19.7 s |
| `finding` | 24.2 s |
| `finding-detail` | 27.8 s |
| `evidence` | 33.3 s |
| `verify` | 37.7 s |
| `tls13` | 45.5 s |
| `drift-setup` | 56.5 s |
| `drift` | 60.8 s |
| `report` | 73.9 s |
| `montage` | 81.4 s |
| `end` | 88.6 s |

Raw footage: 90.0 s. The finished cut is longer because of the two
cards, the PDF stills, and because a shot is held — never sped up — when its
line of narration runs past it. The cut also reorders: it opens on the finding,
which is recorded partway through the take.

## Rebuilding

```bash
python scripts/build_demo_dataset.py
cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture && cd ..
bash scripts/make_narration.sh
.venv-release/bin/python scripts/build_demo_video.py
```

Add `--silent` to build the same cut with captions and no audio.

Status: **VIDEO COMPLETE.** Nothing has been uploaded; no public URL exists.
