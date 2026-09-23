# Recording checklist

## Before you start

- [ ] `python scripts/build_demo_dataset.py` — regenerate the nine captures
- [ ] Start a **fresh** data directory so the first-run screen is genuinely
      empty: `python -m securemailscope.backend.server --data-dir /tmp/demo-run`
- [ ] Start the interface with that server's token (see `docs/deployment.md`)
- [ ] Browser: clean profile · no bookmarks bar · no extensions · no other tabs
- [ ] macOS: Do Not Disturb on; no Slack, Mail or calendar alerts
- [ ] Screen recorder: **1920×1080, 30 fps**, system audio **off**
- [ ] Close every terminal window — a path or a token must never be on screen

## Verify before recording

- [ ] `http://127.0.0.1:5173` loads with the first-run screen
- [ ] The Settings page is **not** part of the route you will record
      (it displays a local storage path)
- [ ] No API token is visible anywhere in the interface

## While recording

- [ ] Move the cursor yourself, at a human pace — never script it
- [ ] Let the analysis take the time it takes; do not cut it to look instant
- [ ] Hold on the evidence panel and on the TLS 1.3 limitation longer than
      feels comfortable. Those two shots are the argument.

## After recording

- [ ] Scrub the whole take at 2× looking for: a token, a path, a notification,
      a personal tab, a debug overlay
- [ ] Confirm every number on screen matches the engine's real output
- [ ] Confirm nothing in the narration claims an attack was detected
- [ ] Confirm nothing claims the ML classifier is validated
- [ ] Export 1080p H.264, 30 fps

## Do not

- Speed up the analysis so it appears instantaneous
- Add a fake terminal, fake packets or a fake network graph
- Use stock "hacker" footage, matrix rain or hooded-figure imagery
- Use music you do not hold a licence for
- Upload anywhere without the user's explicit approval
