#!/usr/bin/env python3
"""Quality-check generated narration without listening to it.

A neural speech model occasionally produces a bad take: a stutter that repeats
a consonant, a burst of clicking, a truncated syllable, or a line that simply
runs far longer than its word count can explain. Those are audible instantly
and invisible in a waveform thumbnail, so this measures them instead.

Four checks, each with a stated reason:

* **pace** -- words per second far outside the rest of the batch means the
  take stuttered or swallowed words. Compared against the batch median rather
  than a fixed number, because a voice's natural rate varies, and with a band
  that widens for short lines: a six-word sentence carries no inter-sentence
  pause to pull its average down, so it reads faster than a long one without
  anything being wrong with it.
* **clipping** -- samples at or beyond full scale, which a normaliser cannot
  undo.
* **consonant chatter** -- the `ch/ch/ch` failure. Short frames with high
  zero-crossing rate and high energy, repeating at a regular short period, are
  what a repeated plosive looks like numerically.
* **trailing silence** -- more than a second of nothing at the end usually
  means the take was cut off mid-thought and padded.

Exit status is non-zero if any segment fails, so a build can refuse to ship a
bad take.

The same measurements run over a finished video's own audio track, which is
where a defect actually has to be absent: a line can be clean on its own and
still be joined badly into the mix.

    python scripts/check_narration.py
    python scripts/check_narration.py --json
    python scripts/check_narration.py --mix submission/final/....mp4
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import shutil
import statistics
import subprocess
import sys
import wave
from array import array
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NARRATION = ROOT / "local-evidence" / "narration"

#: A frame short enough that one plosive lands inside it.
FRAME_MS = 20
#: Zero-crossing rate above this is fricative/plosive rather than voiced.
ZCR_NOISY = 0.28
#: A repeated-consonant burst repeats faster than natural syllables do.
CHATTER_MIN_PERIOD_MS = 60
CHATTER_MAX_PERIOD_MS = 200
#: How many evenly spaced noisy bursts in a row count as chatter.
CHATTER_RUN = 5


def _decode(path: Path) -> tuple[array, int]:
    """Decode to mono 16-bit PCM via ffmpeg, so no audio library is needed."""
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise SystemExit("ffmpeg is required and was not found on PATH.")
    raw = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [ffmpeg, "-v", "error", "-i", str(path), "-ac", "1", "-ar", "24000",
         "-f", "wav", "-"],
        check=True, capture_output=True,
    ).stdout
    import io

    with wave.open(io.BytesIO(raw)) as handle:
        frames = handle.readframes(handle.getnframes())
        rate = handle.getframerate()
    samples = array("h")
    samples.frombytes(frames)
    return samples, rate


def _frames(samples: array, rate: int) -> list[tuple[float, float]]:
    """(rms, zero-crossing rate) per frame."""
    size = int(rate * FRAME_MS / 1000)
    out: list[tuple[float, float]] = []
    for start in range(0, len(samples) - size, size):
        window = samples[start:start + size]
        total = sum(value * value for value in window)
        rms = math.sqrt(total / size) / 32768.0
        crossings = sum(
            1 for i in range(1, size)
            if (window[i - 1] >= 0) != (window[i] >= 0)
        )
        out.append((rms, crossings / size))
    return out


def analyse(path: Path, words: int) -> dict[str, float | int]:
    samples, rate = _decode(path)
    seconds = len(samples) / rate
    peak = max(abs(value) for value in samples) / 32768.0
    clipped = sum(1 for value in samples if abs(value) >= 32700)

    frames = _frames(samples, rate)
    loud = statistics.median([rms for rms, _ in frames if rms > 0.005] or [0.0])

    # Noisy, loud frames: candidate consonant bursts.
    noisy = [
        index for index, (rms, zcr) in enumerate(frames)
        if zcr > ZCR_NOISY and rms > loud * 0.9
    ]
    chatter = 0
    run = 1
    for first, second in itertools.pairwise(noisy):
        gap_ms = (second - first) * FRAME_MS
        if CHATTER_MIN_PERIOD_MS <= gap_ms <= CHATTER_MAX_PERIOD_MS:
            run += 1
            chatter = max(chatter, run)
        else:
            run = 1

    tail = 0.0
    for rms, _ in reversed(frames):
        if rms > 0.01:
            break
        tail += FRAME_MS / 1000

    return {
        "seconds": round(seconds, 2),
        "words": words,
        "wps": round(words / seconds, 3) if seconds else 0.0,
        "peak": round(peak, 4),
        "clipped_samples": clipped,
        "chatter_run": chatter,
        "trailing_silence": round(tail, 2),
    }


def scan_mix(path: Path, window: float = 6.0) -> list[dict[str, Any]]:
    """Run the same measurements across a finished track, window by window.

    A line that passed on its own can still be joined badly, and a defect in
    the delivered file is the only kind that matters. Windows overlap by half
    their length so a burst on a boundary is still seen whole by one of them.
    """
    samples, rate = _decode(path)
    size = int(window * rate)
    step = size // 2
    rows: list[dict[str, Any]] = []
    for start in range(0, max(1, len(samples) - step), step):
        chunk = samples[start:start + size]
        if len(chunk) < rate:
            break
        frames = _frames(chunk, rate)
        loud = statistics.median([rms for rms, _ in frames if rms > 0.005] or [0.0])
        noisy = [
            index for index, (rms, zcr) in enumerate(frames)
            if zcr > ZCR_NOISY and rms > loud * 0.9
        ]
        chatter, run = 0, 1
        for first, second in itertools.pairwise(noisy):
            gap_ms = (second - first) * FRAME_MS
            if CHATTER_MIN_PERIOD_MS <= gap_ms <= CHATTER_MAX_PERIOD_MS:
                run += 1
                chatter = max(chatter, run)
            else:
                run = 1
        rows.append({
            "at": round(start / rate, 2),
            "peak": round(max(abs(v) for v in chunk) / 32768.0, 4),
            "clipped_samples": sum(1 for v in chunk if abs(v) >= 32700),
            "chatter_run": chatter,
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--mix", type=Path,
                        help="Scan a finished audio or video file instead.")
    args = parser.parse_args()

    if args.mix:
        rows = scan_mix(args.mix)
        bad = [r for r in rows
               if r["chatter_run"] >= CHATTER_RUN or r["clipped_samples"]]
        if args.json:
            print(json.dumps({"windows": rows, "failures": bad}, indent=2))
        else:
            print(f"{len(rows)} overlapping windows across {args.mix.name}")
            print(f"  worst chatter run : "
                  f"{max((r['chatter_run'] for r in rows), default=0)} "
                  f"(fails at {CHATTER_RUN})")
            print(f"  clipped samples   : "
                  f"{sum(r['clipped_samples'] for r in rows)}")
            print(f"  peak              : "
                  f"{max((r['peak'] for r in rows), default=0.0)}")
            for row in bad:
                print(f"  FAIL at {row['at']:.2f}s: {row}")
            print("verdict: " + ("ok" if not bad else "FAIL"))
        return 1 if bad else 0

    script = json.loads(
        (ROOT / "submission" / "demo" / "narration-script.json").read_text()
    )
    results: dict[str, dict[str, Any]] = {}
    for segment in script["segments"]:
        # [name, text] or [name, text, {setting overrides}].
        name, text = segment[0], segment[1]
        path = NARRATION / f"{name}.mp3"
        if not path.is_file():
            print(f"missing: {name}", file=sys.stderr)
            return 2
        results[name] = dict(analyse(path, len(text.split())))

    rates = [float(r["wps"]) for r in results.values()]
    median = statistics.median(rates)

    failures: list[str] = []
    for name, r in results.items():
        reasons = []
        # Tolerance widens as the sample shrinks, because the rate estimate
        # from a short line is noisier than from a long one.
        slack = 0.35 + 2.0 / math.sqrt(float(r["words"]))
        if not (1 - slack) * median <= float(r["wps"]) <= (1 + slack) * median:
            reasons.append(
                f"pace {r['wps']} outside "
                f"{(1 - slack) * median:.2f}-{(1 + slack) * median:.2f}"
            )
        if int(r["clipped_samples"]) > 4:
            reasons.append(f"{r['clipped_samples']} clipped samples")
        if int(r["chatter_run"]) >= CHATTER_RUN:
            reasons.append(f"consonant chatter run {r['chatter_run']}")
        if float(r["trailing_silence"]) > 1.2:
            reasons.append(f"{r['trailing_silence']}s trailing silence")
        r["ok"] = not reasons
        r["reasons"] = reasons
        if reasons:
            failures.append(name)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"{'segment':14} {'secs':>6} {'wps':>6} {'peak':>6} "
              f"{'clip':>5} {'chat':>5} {'tail':>5}  verdict")
        for name, r in results.items():
            mark = "ok" if r["ok"] else "CHECK: " + "; ".join(r["reasons"])
            print(f"{name:14} {r['seconds']:6.2f} {r['wps']:6.3f} {r['peak']:6.3f} "
                  f"{r['clipped_samples']:5} {r['chatter_run']:5} "
                  f"{r['trailing_silence']:5.2f}  {mark}")
        print(f"\nmedian pace {median:.3f} words/second "
              f"({median * 60:.0f} words/minute)")
        if failures:
            print(f"\nregenerate: bash scripts/make_narration.sh "
                  f"{' '.join(failures)}", file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
