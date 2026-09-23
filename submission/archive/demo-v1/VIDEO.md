# demo-v1 video footage

Large media stays out of Git. The cut itself lives in
`local-evidence/video-archive/v1/` (gitignored); this file is the record.

| Field | Value |
|---|---|
| Filename | `securemailscope-raw-1080p.mp4` |
| SHA-256 | `4e0dd7930f7aebfbfa3bbcf2deddbfb1aa6a6ca8b8b6e4ac32fd2c15e8dd1ec8` |
| Bytes | 1,887,847 |
| Duration | 29.07 s |
| Resolution | 1920x1080 |
| Frame rate | 30/1 |
| Source commit | `94ebaf44e3fe51b28137fceb0a6659c08fc2ff54` |
| Narration version | none recorded (script: `narration.md`) |
| Storyboard version | `storyboard.md` at this commit |
| Verification | `demo-verification.md` — 14 checks, all passing |

Regenerate with:

    cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture
