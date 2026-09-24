# video-pre-national-final

The demonstration video as it stood before the national-level polish pass.

Large media stays out of Git, the same way `demo-v1` and `demo-v2` record
theirs: the bytes live in `local-evidence/video-archive/pre-national-final/`
(gitignored) and this file is the record. The same file is also recoverable
from history, which is the stronger guarantee of the two:

    git show 7b59768dbf953c0d885acdfb36a1c4419416d3a2e |
|---|---|
| Filename | `SecureMailScope-SIH26159-Demo.mp4` |
| SHA-256 | `4db074fbdf7352627431696257489831a4e83409ef2ab28398b164853c19a63c` |
| Bytes | 44127814 |
| Duration | 191.4 s (3 min 11 s) |
| Resolution | 1920x1080 @ 30 fps, H.264 CRF 18 |
| Audio | AAC, **macOS `say` synthesis** |
| Source commit | `7b59768dbf953c0d885acdfb36a1c4419416d3a2` |

## Why it was superseded

The narration was operating-system speech synthesis, which the team rejected
as sounding artificial, and the cut was paced like a narrated slideshow: long
held shots, a caption carrying every line of the script, and eight seconds of
title before the product appeared.

It is replaced by a cut with neural narration, a cold open on a real finding,
short supportive captions rather than a transcript, and shots cut to two to
six seconds.
