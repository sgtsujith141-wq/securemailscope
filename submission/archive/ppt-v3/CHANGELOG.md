# ppt-v3

The deck as it stood before the final execution sprint: complete in structure,
but with two title-page values still unknown.

- **Source commit:** `35d2e3f07591d3fd26fffe45d4b8c3fee993febf`
- **Archived:** 2026-09-23T17:18:44Z
- **Verification at archive time:** 6 pages · official template retained ·
  instruction slide removed · team name exactly `Zero-Day` · no forbidden
  variant present

## Why it was superseded

- **Theme and Team ID were unresolved.** Both rendered as visible
  `[UNRESOLVED: ...]` markers in red. They are now filled: theme
  *Blockchain & Cybersecurity*, Team ID *146876*.
- **No repository link and no video element.** Slide 6 now carries a real
  hyperlink to the repository and a reserved element for the demonstration
  video, and the build fails if either is missing.
- **Screenshots were of the previous interface.** All nine product images were
  replaced with the redesigned dashboard, findings workspace and session view.
- **Two captions were wrong.** One said "seven synthetic captures" beside an
  image of nine, and two said "two captures" beside an image of nine. The
  capture count is now read from `demo/manifest.json` rather than typed.
- **Two captions were clipped** by the template's footer band on slide 6.
- **Test figures were stale**: 1,354 / 1,364 / 88 / 153, now 1,357 / 1,367 /
  89 / 155, each re-run for this release.

## Recovering it

```bash
git show 35d2e3f07591d3fd26fffe45d4b8c3fee993febfreMailScope-SIH26159-Zero-Day.pptx` in this directory directly.
`slide-renders/` holds every page as a PNG, so the deck can be read without
PowerPoint.
