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
#   bash scripts/make_narration.sh
set -euo pipefail

cd "$(dirname "$0")/.."
SCRIPT_JSON="local-evidence/narration/script.json"
if [[ ! -f "$SCRIPT_JSON" ]]; then
  echo "missing $SCRIPT_JSON" >&2
  exit 1
fi
if ! command -v elevenlabs >/dev/null 2>&1; then
  echo "the elevenlabs CLI is not installed; the cut still builds without" >&2
  echo "narration, and every line is carried by an on-screen caption." >&2
  exit 1
fi

python3 - "$SCRIPT_JSON" <<'PY' > /tmp/sms-narration.sh
import json, sys
d = json.load(open(sys.argv[1]))
print("set -e")
for name, text in d["segments"]:
    body = json.dumps({
        "text": text, "model_id": d["model"],
        "voice_settings": {"stability": 0.42, "similarity_boost": 0.82,
                           "style": 0.18, "use_speaker_boost": True,
                           "speed": 1.06},
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
