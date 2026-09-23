# Shot list

> **Superseded.** This is the plan the demonstration was designed from.
> The video itself is built and finished — see `final-script.md`, which
> describes what was actually assembled, and
> `submission/final/SecureMailScope-SIH26159-Demo.mp4`. This file is kept
> because the reasoning behind the shots is still worth reading, not
> because anything here is outstanding.

Every shot is the real application on synthetic captures. Nothing is mocked,
no output is staged, and no cursor movement is faked.

**Capture settings:** 1920×1080, 30 fps, browser at 1440×900 scaled up, or
1920×1080 native with the sidebar visible. Hide bookmarks. Use a clean browser
profile with no extensions and no personal tabs.

| # | Time | Shot | Source | Action |
|---|---|---|---|---|
| 1 | 0:00–0:06 | Finding detail, tight on `TLS-KEX-001` HIGH | live app, `02-weak-legacy-tls.pcap` | Static hold. No cursor. |
| 2 | 0:06–0:12 | Cut: score `59/100 WEAK`; cut: `TLS 1.0`; cut: packets `#4 #5` | live app | Three hard cuts, ~0.8s each |
| 3 | 0:12–0:18 | Title card | generated | Product name + one line |
| 4 | 0:18–0:45 | Architecture, built from `submission/assets/screenshots` | static composition | Slow reveal of the pipeline, left to right |
| 5 | 0:45–1:00 | First-run screen | live app, empty database | Static hold on the four steps |
| 6 | 1:00–1:20 | Upload: drop `02-weak-legacy-tls.pcap`, click Analyse | live app | Real interaction, real timing |
| 7 | 1:20–1:40 | Investigation overview appears | live app | Hold on "high-priority issues require attention" |
| 8 | 1:40–2:05 | Open `TLS-KEX-001`; expand Evidence | live app | Slow. Zoom to 125% on the evidence panel |
| 9 | 2:05–2:30 | TLS 1.3 session, certificate `NOT_AVAILABLE` | live app, `07-tls13-encrypted-certificate.pcap` | Hold on the reason text |
| 10 | 2:30–2:55 | Intelligence → Drift, the two-capture pair | live app, `08-drift-*.pcap` | Hold on `OBSERVED_CHANGE` |
| 11 | 2:55–3:10 | Reports → Download PDF → open the PDF | live app | Show the finding and its evidence in the PDF |
| 12 | 3:10–3:30 | Montage: overview, finding, evidence, drift, report | live app | ~1s each, then end card |

## Rules

- **No fake progress.** If the analysis takes four seconds, show four seconds.
  A small editorial trim is fine; speeding it up so it looks instant is not.
- **No fake cursor.** Move the mouse yourself, or don't show it.
- **No terminal.** The video is about the product, and a terminal risks
  showing a path or a token.
- **Never say "attack detected".** Nothing in this dataset is an attack.

## Before recording

- [ ] `python scripts/build_demo_dataset.py` — regenerate the captures
- [ ] Fresh data directory, so the first-run screen is genuinely empty
- [ ] Browser: clean profile, no bookmarks bar, no extensions, no other tabs
- [ ] Notifications off (macOS: Do Not Disturb)
- [ ] Screen recorder set to 1920×1080 @ 30fps, system audio off
