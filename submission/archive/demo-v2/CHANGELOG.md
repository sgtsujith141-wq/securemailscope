# demo-v2

The demonstration package as it stood when the video was still unfinished.

- **Source commit:** `35d2e3f07591d3fd26fffe45d4b8c3fee993febf`
- **Archived:** 2026-09-23T17:19:24Z

## Why it was superseded

At this point the package held 29 seconds of authentic B-roll, a storyboard, a
narration script and a shot list — and said so plainly. The video itself did
not exist.

It has been replaced by a finished 3 min 17 s cut, assembled by
`scripts/build_demo_video.py` from a longer Playwright recording. The pieces
that changed:

- **The recording now timestamps its own beats.** Captions are cut against
  `local-evidence/footage/beats.json`, written during the recording, so a
  caption cannot describe a shot the footage is not showing.
- **Captions and narration are generated together** and `captions.srt` is
  emitted from the assembled timeline, so the subtitle file cannot drift from
  the video.
- **The narration is synthesised** by the operating system's speech engine.
  That is stated in `demo-verification.md`, `video-description.md` and
  `submission/README.md`. It is not a person.
- **The storyboard and shot list are superseded** by `final-script.md`,
  which describes what was built rather than what was planned.

## Recovering it

```bash
git restore --source=35d2e3f07591d3fd26fffe45d4b8c3fee993febf -- submission/demo/
```
