# demo-v2 video footage

The v2 cut was 29 seconds of raw B-roll with no narration, no cards and no
captions. It is recorded here and kept in `local-evidence/video-archive/v1/`
(gitignored).

| Field | Value |
|---|---|
| Filename | `securemailscope-raw-1080p.mp4` |
| Duration | 29.07 s |
| Resolution | 1920x1080 @ 30 fps, H.264 |
| Narration | none |
| Captions | none |

## What replaced it

The finished video is committed, because it is a submission artefact rather
than an editing input:

| Field | Value |
|---|---|
| Path | `submission/final/SecureMailScope-SIH26159-Demo.mp4` |
| SHA-256 | `ea0db0abfd96743b6762b5c3bbd2011e659736a6b9c1950badfcb084fba941da` |
| Bytes | 13325686 |
| Duration | 197.9 s (3 min 17 s) |
| Resolution | 1920x1080 @ 30 fps, H.264 (yuv420p) |
| Audio | AAC, synthesised narration |
| Captions | burned in, and `submission/demo/captions.srt` |
| Built at commit | `35d2e3f07591d3fd26fffe45d4b8c3fee993febf` (working tree at release) |

Rebuild:

    cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture && cd ..
    .venv-release/bin/python scripts/build_demo_video.py
