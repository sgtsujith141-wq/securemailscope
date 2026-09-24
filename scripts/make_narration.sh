#!/usr/bin/env bash
# Generate the demonstration narration with a neural speech provider.
#
# The operating system's own speech synthesis was rejected for this project:
# it sounds synthetic, and a national-level submission should not open with a
# robot reading a script. This uses the ElevenLabs CLI, which must already be
# authenticated (`elevenlabs auth login`) -- no key is stored in this
# repository and none is ever committed.
#
# The audio itself is not committed either: it is large, it is regenerable,
# and this script plus submission/demo/narration.md are the record of it. The
# voice and the exact settings are pinned here so a rebuild sounds the same.
#
# Each line is generated as its own request so a single bad take can be
# regenerated without touching the rest, and so `scripts/check_narration.py`
# can quality-check them one at a time.
#
#   bash scripts/make_narration.sh            # all segments
#   bash scripts/make_narration.sh 08-evidence 10-tls13   # just these
set -euo pipefail

cd "$(dirname "$0")/.."
SCRIPT_JSON="submission/demo/narration-script.json"
if [[ ! -f "$SCRIPT_JSON" ]]; then
  echo "missing $SCRIPT_JSON" >&2
  exit 1
fi
if ! command -v elevenlabs >/dev/null 2>&1; then
  echo "the elevenlabs CLI is not installed; the cut still builds without" >&2
  echo "narration, and every line is carried by an on-screen caption." >&2
  exit 1
fi

python3 - "$SCRIPT_JSON" "$@" <<'PY' > /tmp/sms-narration.sh
import json, sys
d = json.load(open(sys.argv[1]))
wanted = set(sys.argv[2:])
print("set -e")
for segment in d["segments"]:
    # A segment is [name, text] or [name, text, {setting overrides}]. An
    # override exists only where a line read noticeably faster or slower than
    # the rest of the batch; the voice and model never change.
    name, text = segment[0], segment[1]
    overrides = segment[2] if len(segment) > 2 else {}
    if wanted and name not in wanted:
        continue
    body = json.dumps({
        "text": text, "model_id": d["model"],
        "voice_settings": {**d["settings"], **overrides},
    })
    params = json.dumps({"voice_id": d["voice_id"], "output_format": "mp3_44100_128"})
    print(
        f"elevenlabs text-to-speech convert --params {json.dumps(params)} "
        f"--json {json.dumps(body)} -o local-evidence/narration/{name}.mp3 "
        f"--intent 'generate narration for a hackathon product demonstration "
        f"video' >/dev/null && echo '  {name}'"
    )
PY
echo "generating narration with the pinned voice:"
bash /tmp/sms-narration.sh
rm -f /tmp/sms-narration.sh
echo "done."
