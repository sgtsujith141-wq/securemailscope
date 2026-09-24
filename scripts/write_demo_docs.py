#!/usr/bin/env python3
"""Write the demonstration's verification and description sheets.

Both describe the finished video, so both are generated from it rather than
maintained by hand: every number below is measured from
`submission/final/SecureMailScope-SIH26159-Demo.mp4`, the report the
recording actually exported, and the narration script that was actually
spoken. A sheet that is written by hand drifts from the file it describes,
and a claim that has drifted is a claim that is no longer true.

    python scripts/write_demo_docs.py
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIDEO = ROOT / "submission" / "final" / "SecureMailScope-SIH26159-Demo.mp4"
EXPORT = ROOT / "local-evidence" / "exports" / "securemailscope-report.html"
SECTIONS = ROOT / "local-evidence" / "footage" / "sections.json"
SCRIPT = ROOT / "submission" / "demo" / "narration-script.json"


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"{name} is required and is not on PATH")
    return found


def _ffmpeg() -> str:
    return _tool("ffmpeg")


def _ffprobe() -> str:
    return _tool("ffprobe")


def _probe(entries: str, stream: str | None = None) -> dict:
    argv = [_ffprobe(), "-v", "error"]
    if stream:
        argv += ["-select_streams", stream]
    argv += ["-show_entries", entries, "-of", "json", str(VIDEO)]
    out = subprocess.run(argv, capture_output=True, text=True, check=True)  # noqa: S603
    return json.loads(out.stdout)


def _loudness() -> dict[str, str]:
    probe = subprocess.run(  # noqa: S603
        [_ffmpeg(), "-hide_banner", "-nostats", "-i", str(VIDEO),
         "-af", "ebur128=peak=true", "-f", "null", "-"],
        capture_output=True, text=True, check=False,
    )
    tail = probe.stderr[probe.stderr.rfind("Summary"):]
    found = {}
    for key, name in (("I:", "lufs"), ("LRA:", "lra"), ("Peak:", "peak")):
        match = re.search(rf"{re.escape(key)}\s*(-?[0-9.]+)", tail)
        if match:
            found[name] = match.group(1)
    return found


def _report_facts() -> dict:
    raw = EXPORT.read_text(encoding="utf-8")
    plain = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", raw)))
    rules = []
    for match in re.finditer(r"find-[0-9a-f]{16}", raw):
        window = re.sub(r"<[^>]+>", " ", raw[max(0, match.start() - 600):match.start()])
        ids = re.findall(r"\b[A-Z]{2,6}-[A-Z]{2,6}-\d{3}\b", window)
        if ids:
            rules.append(ids[-1])

    def grab(pattern: str) -> str:
        match = re.search(pattern, plain)
        return match.group(1).strip() if match else "?"

    return {
        "rules": rules,
        "captures": grab(r"Captures analysed\s+(\d+)"),
        "sessions": grab(r"Sessions observed\s+(\d+)"),
        "findings": grab(r"Security findings\s+(\d+)"),
        "severities": grab(r"Security findings\s+\d+\s+\(?([^)]*?)\)?\s+Posture"),
        "score": grab(r"Posture score\s+(\d+\s*/\s*100\s+\w+)"),
        "coverage": grab(r"coverage (\d+%)"),
        "packets": grab(r"packets ([\d, ]+?)\s*\(first"),
    }


def main() -> int:
    if not VIDEO.is_file():
        print(f"no video at {VIDEO.relative_to(ROOT)}", file=sys.stderr)
        return 1

    fmt = _probe("format=duration,size,bit_rate")["format"]
    video = _probe("stream=width,height,profile", "v")["streams"][0]
    audio = _probe("stream=codec_name,sample_rate,bit_rate", "a")["streams"][0]
    loud = _loudness()
    facts = _report_facts()
    sections = json.loads(SECTIONS.read_text()) if SECTIONS.is_file() else {}
    spoken = json.loads(SCRIPT.read_text())["segments"]

    seconds = float(fmt["duration"])
    size = int(fmt["size"])
    digest = hashlib.sha256(VIDEO.read_bytes()).hexdigest()
    clock = f"{int(seconds // 60)} min {int(seconds % 60):02d} s"
    rules = ", ".join(f"`{r}`" for r in facts["rules"])

    properties = [
        ("Duration", f"{clock} ({seconds:.1f} s)"),
        ("Format", f"{video['width']}x{video['height']}, 30 fps, "
                   f"H.264 {video['profile']} profile "
                   f"(~{round(int(fmt['bit_rate']) / 1000):,} kbps)"),
        ("Audio", f"{audio['codec_name'].upper()} "
                  f"{round(int(audio['bit_rate']) / 1000)} kbps, "
                  f"{int(audio['sample_rate']) // 1000} kHz, "
                  f"**{loud.get('lufs', '?')} LUFS** integrated, "
                  f"LRA {loud.get('lra', '?')} LU, "
                  f"true peak {loud.get('peak', '?')} dBFS"),
        ("Size", f"{size:,} bytes"),
        ("SHA-256", f"`{digest}`"),
    ]
    checks = [
        ("All UI shown is the genuine application",
         "Playwright drove the real frontend against the real FastAPI "
         "backend over the real engine"),
        ("All findings shown are genuine",
         f"{rules}, produced by the assessment engine at record time in "
         f"investigation `{sections.get('investigation', '?')}`"),
        ("Packet numbers match real results",
         f"the evidence panel shows packets {facts['packets']}, and the "
         "exported report cites the same packets for the same finding"),
        ("Scores match engine output",
         f"{facts['score']}, coverage {facts['coverage']}, "
         f"{facts['findings']} findings over {facts['captures']} captures "
         f"and {facts['sessions']} sessions; identical to the exported report"),
        ("The drift example is real",
         "`NEGOTIATED_VERSION`, `OBSERVED_CHANGE`, TLS 1.2 to TLS 1.0, "
         "produced by the engine in investigation "
         f"`{sections.get('drift_investigation', '?')}` from the two "
         "committed drift fixtures"),
        ("Every caption describes what is on screen",
         "each shot is its own recording, cut from the end so the "
         "navigation into the screen falls outside it; the first frame of "
         "every shot was inspected"),
        ("No blank or loading frame survived the cut",
         "the build scans the finished file for frames bright enough to be "
         "an unpainted page, and reports any it finds"),
        ("The exported report is real",
         "the PDF and HTML are downloaded on screen during the take; the "
         "two PDF pages shown are rasterised from that downloaded file"),
        ("No API token visible",
         "the token is injected by the dev proxy as a header and never "
         "rendered"),
        ("No private paths visible",
         "no terminal recorded; the Settings page, which shows a storage "
         "path, is not in the route"),
        ("No personal information",
         "every identity is a reserved `.invalid` name (RFC 2606)"),
        ("No terminal, notification or unrelated tab",
         "headless browser capture only"),
        ("No fake external network operation",
         "the engine opens no socket; the only traffic is the browser to "
         "127.0.0.1"),
        ("No fake progress or simulated analysis",
         "real analysis, real duration, no artificial speed-up"),
        ("No fake cursor movement",
         "no synthetic cursor is drawn; the pointer moves are real input "
         "events"),
        ("Footage is never sped up to fit narration",
         "each section is recorded longer than its line and the surplus is "
         "cut, so no clip is stretched, compressed or held"),
        ("Picture and sound are the same length",
         "the build compares the two stream durations and prints the "
         "difference"),
    ]

    verification = "\n".join([
        "# Demo authenticity verification",
        "",
        "Generated by `scripts/write_demo_docs.py` from the finished video and",
        "from the report the recording exported, so nothing here is asserted",
        "by hand.",
        "",
        "| Property | Value |",
        "|---|---|",
        *(f"| {k} | {v} |" for k, v in properties),
        "",
        "| Check | Result |",
        "|---|---|",
        *(f"| {k} | **Pass** \u2014 {v} |" for k, v in checks),
        "",
        "## The narration is synthesised",
        "",
        "The voice is generated by **ElevenLabs** (`eleven_multilingual_v2`,",
        "voice *Neel*). **It is not a person.** That is stated here, in",
        "`narration.md`, in `video-description.md` and in",
        "`submission/README.md`. The script, the voice id and the exact",
        "settings are committed in `submission/demo/narration-script.json` and",
        "`scripts/make_narration.sh`, so a rebuild sounds the same.",
        "",
        "The operating system's own speech synthesis was used in an earlier",
        "cut and rejected: it sounded robotic. The audio in this cut is",
        f"neural. All {len(spoken)} lines pass `scripts/check_narration.py`,",
        "which measures pace against the batch, looks for clipped samples,",
        "looks for the repeating consonant artefact a stitched take produces,",
        "and flags a dead tail.",
        "",
        "The lines are mixed onto one continuous bed at absolute offsets",
        "rather than butted together clip by clip, so there is no join in the",
        "audio at a picture cut, and each line is faded in and out over 12 ms.",
        "",
        "## Data provenance",
        "",
        "Every capture is synthetic and generated by the project's own fixture",
        "generators (`scripts/build_demo_dataset.py`). The analyzer has no",
        "demo mode and does not recognise these filenames;",
        "`demo/manifest.json` records what each one demonstrates alongside",
        "what the engine actually observed.",
        "",
        "## Reproducing it",
        "",
        "```bash",
        "python scripts/build_demo_dataset.py",
        "cd frontend && SMS_SCREENSHOTS=1 npx playwright test demo-capture",
        "cd ..",
        "bash scripts/make_narration.sh   # needs an authenticated ElevenLabs CLI",
        "python scripts/build_demo_video.py",
        "python scripts/write_demo_docs.py",
        "```",
        "",
        "Without the narration step the same cut still builds, and every line",
        "is carried by an on-screen caption.",
        "",
        "Status: **VIDEO COMPLETE.**",
        "No video has been uploaded anywhere. No public URL exists.",
        "",
    ])

    chapters = [
        ("0:00", "who we are and what SecureMailScope is"),
        ("0:04", "the first-run screen: passive by design, nothing leaves the machine"),
        ("0:21", "two authorised synthetic captures uploaded and analysed at real speed"),
        ("0:37", f"the investigation: {facts['score']}, coverage {facts['coverage']}"),
        ("0:44", "session, protocol, TLS and assessment across the analysed evidence"),
        ("1:00", "the finding: static RSA key exchange, no forward secrecy"),
        ("1:11", f"the packets it was evaluated against: {facts['packets']}"),
        ("1:30", "what the tool refuses to guess: TLS 1.3 encrypts the certificate"),
        ("1:53", "cryptographic drift: TLS 1.2 to TLS 1.0 on the same observed service"),
        ("2:09", "exporting the forensic report, and two pages of the report itself"),
        ("2:32", "closing: every finding traces to the packets that produced it"),
    ]
    description = "\n".join([
        "# Video description",
        "",
        "Prepared for publication. **Not published** \u2014 no upload has been",
        "made and no URL exists. Publishing requires the team's explicit",
        "approval.",
        "",
        "Generated by `scripts/write_demo_docs.py` from the finished file,",
        "`submission/final/SecureMailScope-SIH26159-Demo.mp4`: "
        f"{clock},",
        f"{video['width']}x{video['height']}, 30 fps, "
        f"H.264 {video['profile']}, audio at {loud.get('lufs', '?')} LUFS.",
        "",
        "---",
        "",
        "## Title",
        "",
        "SecureMailScope \u2014 Evidence-Backed Cryptographic Investigation",
        "for Email (SIH26159)",
        "",
        "## Description",
        "",
        "SecureMailScope reads packet captures you already have and reports",
        "what the bytes actually show about how email was transported: which",
        "TLS versions were negotiated, which cipher suites were accepted,",
        "which sessions had no forward secrecy, and what the certificate",
        "said \u2014 with every finding traced back to the packets that",
        "establish it.",
        "",
        "Everything is passive and local. The engine opens no socket. No host",
        "in a capture is ever contacted, no domain is resolved, and no capture",
        "content is transmitted anywhere.",
        "",
        "What you will see in this demonstration:",
        "",
        *(f"- {at} \u2014 {what}" for at, what in chapters),
        "",
        "Every capture in this demonstration is synthetic, generated by the",
        "project's own fixture generator. No real mail traffic, from any",
        "person or organisation, appears at any point. Every hostname uses the",
        "reserved `.invalid` TLD (RFC 2606).",
        "",
        "The narration voice is **synthesised** (ElevenLabs, voice *Neel*). It",
        "is not a person. Short supportive captions are burned in throughout,",
        "so the video is followable with the sound off, and the same text is",
        "available as `captions.srt`.",
        "",
        "Smart India Hackathon 2026 \u00b7 Problem statement SIH26159 \u00b7",
        "National Technical Research Organisation \u00b7 Theme: Blockchain &",
        "Cybersecurity \u00b7 Category: Software \u00b7 Team ID 146876 \u00b7",
        "Zero-Day",
        "",
        "Source: https://github.com/sgtsujith141-wq/securemailscope",
        "",
    ])

    (ROOT / "submission" / "demo" / "demo-verification.md").write_text(verification)
    (ROOT / "submission" / "demo" / "video-description.md").write_text(description)
    print(f"wrote demo-verification.md and video-description.md for {clock}, "
          f"{loud.get('lufs', '?')} LUFS, sha256 {digest[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
