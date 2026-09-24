# Final script — the finished video

Written by `scripts/build_demo_video.py` from the cut it assembled, so
every timing below is the file's own. The footage is a Playwright
recording of the real application against the real backend: one
recording per shot, concatenated whole.

**`submission/final/SecureMailScope-SIH26159-Demo.mp4` — 2 min 59 s, 1920x1080, 30 fps, H.264 High, CRF 18, AAC 192 kbps at -16.0 LUFS.**

| Measurement | Value |
|---|---|
| Integrated | -16.0 LUFS |
| Range | 5.5 LU |
| True peak | -3.2 dBFS |

## The cut

| # | At | Length | Element | Narration | Caption |
|---:|---:|---:|---|---|---|
| 1 | 00:00:00 | 12.4s | card: SecureMailScope | `01-intro` | — |
| 2 | 00:00:12 | 16.9s | firstrun | `02-what` | Passive PCAP / PCAPNG analysis |
| 3 | 00:00:29 | 16.0s | upload | `03-problem`, `04-passive` | Authorised captures only · No live scan · the capture stays on this machine |
| 4 | 00:00:45 | 6.8s | overview | `05-analysis` | Controlled synthetic capture · 59/100 · WEAK |
| 5 | 00:00:52 | 11.9s | modules | `06-engine` | Session · protocol · TLS · assessment |
| 6 | 00:01:03 | 4.5s | finding | — | Findings, ranked by priority |
| 7 | 00:01:08 | 10.7s | finding-detail | `07-finding` | TLS-KEX-001 · HIGH · Static RSA · no forward secrecy |
| 8 | 00:01:19 | 12.6s | evidence | `08-evidence` | Packets #4 and #5 · Rule · severity · remediation |
| 9 | 00:01:31 | 7.0s | verify | `09-verify` | Packets #4–#5 · independently verifiable in Wireshark |
| 10 | 00:01:38 | 18.6s | tls13 | `10-tls13` | TLS 1.3 certificate · Reported NOT AVAILABLE, not guessed |
| 11 | 00:01:57 | 4.5s | drift-setup | — | A second observation of the same service |
| 12 | 00:02:01 | 16.1s | drift | `11-drift` | Cryptographic drift · TLS 1.2 → OBSERVED_CHANGE → TLS 1.0 |
| 13 | 00:02:17 | 11.6s | report | `12-report` | JSON · standalone HTML · PDF |
| 14 | 00:02:29 | 5.2s | pdf | — | The exported forensic report |
| 15 | 00:02:34 | 5.4s | pdf2 | — | Findings · packet references · remediation |
| 16 | 00:02:40 | 8.3s | montage | `13-summary` | Every finding traces to the packets that produced it |
| 17 | 00:02:48 | 11.2s | card: SecureMailScope | `14-close` | — |

2 full-screen cards and 2 report-page stills. Everything
else is the product being used.

## Captions

Short supportive labels, not a transcript. At most two lines, 46 px
bold on an opaque band, readable on a projector and on a phone. The
same text is written to `captions.srt` with the timings of this file.

## Narration

See `narration.md` for the spoken words, the voice and its settings.
The lines are mixed onto one continuous bed at absolute offsets rather
than butted together per clip, so there is no join in the audio at a
picture cut, and each line is faded in and out over 12 ms.
