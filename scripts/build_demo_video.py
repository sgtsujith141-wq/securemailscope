#!/usr/bin/env python3
"""Assemble the demonstration video from genuine product footage.

The footage is a Playwright recording of the real application driving the real
backend over the real forensic engine on the synthetic demo dataset. Nothing
in it is staged, and this script adds nothing that claims otherwise: it cuts
the recording at the beat offsets the recording itself measured, burns the
narration in as captions and lays a synthesised narration track under it.

Three full-screen cards, and no more: a title, one mid-roll card, and an end
card. A card stops the product being on screen, and a demonstration that cuts
to a title every twenty seconds reads as a slide deck rather than a tool.

The exported PDF is shown as a full frame rasterised from the very file the
recording downloaded, because headless Chromium downloads a PDF rather than
displaying it. The HTML export, which is self-contained, is opened in the
browser during the recording itself.

The narration voice is **synthesised** by the operating system's speech
engine. It is not a person, and `submission/demo/video-description.md` says so.
Pass ``--silent`` to build the same video with captions and no audio.

    npx playwright test demo-capture          # record the footage
    python scripts/build_demo_video.py        # assemble it

Requires ffmpeg. The narration additionally requires macOS ``say``; without it
the build falls back to a silent cut and reports that it did.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOOTAGE = ROOT / "local-evidence" / "footage"
BUILD = ROOT / "local-evidence" / "video-build"
OUT_DEFAULT = ROOT / "submission" / "final" / "SecureMailScope-SIH26159-Demo.mp4"

WIDTH, HEIGHT, FPS = 1920, 1080, 30

# The product's own palette, so the cards and the footage belong together.
INK = (7, 12, 20)
INK_PANEL = (14, 22, 34)
MIST = (226, 234, 245)
MIST_DIM = (139, 157, 181)
CYAN = (34, 211, 238)
VIOLET = (167, 139, 250)
AMBER = (251, 146, 60)

FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
)
FONT_BOLD_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
)
FONT_MONO_CANDIDATES = (
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/Supplemental/Courier New.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)


def _font(candidates: tuple[str, ...]) -> str:
    for path in candidates:
        if Path(path).exists():
            return path
    raise SystemExit(
        "no usable font found. Install DejaVu or Liberation fonts and re-run."
    )


# ---------------------------------------------------------------------------
# the script: one entry per beat the recording marked, plus the cards
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Card:
    """A full-screen card between sections."""

    kind: str  # "title" | "section" | "end"
    seconds: float
    heading: str
    sub: str = ""
    note: str = ""
    narration: str = ""


#: Spoken and captioned text per recorded beat id. A beat with no entry here
#: is still included in the cut; it simply carries no caption.
NARRATION: dict[str, str] = {
    "first-run": (
        "SecureMailScope analyses email traffic captures. It is passive by "
        "design: no host in a capture is ever contacted, and nothing leaves "
        "this machine."
    ),
    "upload": (
        "Nine synthetic captures go in, covering SMTP, IMAP and POP3."
    ),
    "analyse": (
        "Analysis runs entirely locally, against the bytes in the capture."
    ),
    "dashboard": (
        "The investigation opens on its conclusion: seven high-priority "
        "cryptographic issues require attention, and the weakest capture "
        "scores fifty-nine out of a hundred."
    ),
    "modules": (
        "Beneath it: the TLS version of every session, the severity "
        "distribution, and what the certificates showed."
    ),
    "rows": (
        "Then the findings themselves, beside the evidence timeline they were "
        "drawn from."
    ),
    "findings": (
        "Each finding names the rule it failed, the session it came from and "
        "the confidence the engine assigned."
    ),
    "finding-detail": (
        "Static RSA key exchange. No forward secrecy: anyone who later "
        "obtains the server's long-term key can decrypt this session."
    ),
    "evidence": (
        "Packets 4 and 5 \u2014 the exact packets the rule was evaluated "
        "against. Open the same two in Wireshark and check."
    ),
    "session": (
        "A session reads as the chain it is: entry point, version, cipher "
        "suite, key exchange, certificate."
    ),
    "tls13": (
        "A TLS 1.3 certificate is encrypted on the wire. It is reported as "
        "not available, with the reason \u2014 never guessed."
    ),
    "intelligence": (
        "A fingerprint groups configurations. It identifies a setup, not an "
        "operator \u2014 and the page says so."
    ),
    "drift": (
        # Covers the whole sweep through the section -- drift, then
        # correlations, then blast radius -- because the caption stays up for
        # all three and must describe what is on screen for every second of it.
        "Drift compares one endpoint across captures; where the clients asked "
        "different questions it says inconclusive. Correlations and blast "
        "radius stay inside the captures analysed."
    ),
    "timeline": (
        "Every timeline event carries its evidence status: observed in a "
        "packet, or inferred."
    ),
    "ml": (
        "The anomaly detector actually in use is a deterministic rarity "
        "baseline, not a machine-learning model, and the interface says so."
    ),
    "reports": (
        "One canonical model produces JSON, a self-contained HTML document "
        "and a PDF. Their facts cannot disagree."
    ),
    "open-report": (
        "Here is that export, opened straight from disk. It fetches nothing "
        "external, and it is the same report the engine just produced."
    ),
    "end": "",
}

TITLE_CARD = Card(
    kind="title",
    seconds=8.0,
    heading="SecureMailScope",
    sub="AI-Assisted Cryptographic Security Posture Assessment\nfor Secure Email Communications",
    note="Smart India Hackathon 2026  ·  SIH26159  ·  NTRO  ·  Zero-Day",
    narration=(
        "SecureMailScope. Cryptographic security posture assessment for "
        "secure email communications."
    ),
)

#: Section cards, keyed by the beat they precede.
#:
#: Exactly one. A full-screen card stops the product being on screen, and a
#: demonstration that cuts to a title every twenty seconds reads as a slide
#: deck rather than a tool. Title, this, and the end card is the whole set.
SECTION_CARDS: dict[str, Card] = {
    "finding-detail": Card(
        kind="section", seconds=4.4,
        heading="Evidence, not assertion",
        sub="Every finding is traceable to the packets that establish it.",
        note=("Packet number \u00b7 timestamp \u00b7 stream offset \u00b7 "
              "the observation it came from"),
        narration=(
            "Every finding here is traceable to the packets that establish it."
        ),
    ),
}

END_CARD = Card(
    kind="end", seconds=10.0,
    heading="SecureMailScope",
    sub="Passive  ·  Local  ·  Evidence-backed",
    note="",
    narration=(
        "Passive, local, and evidence-backed. SecureMailScope, by Zero-Day."
    ),
)

#: Lines printed under the end card's strapline, as a small block. Kept apart
#: from `sub` so they render at their own size rather than inheriting it.
END_CARD_FOOTER = (
    "Smart India Hackathon 2026  ·  Problem statement SIH26159",
    "National Technical Research Organisation",
    "Theme: Blockchain & Cybersecurity  ·  Category: Software",
    "Team ID 146876  ·  Zero-Day",
    "github.com/sgtsujith141-wq/securemailscope",
)


# ---------------------------------------------------------------------------
# cards
# ---------------------------------------------------------------------------
def _render_card(card: Card, path: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", (WIDTH, HEIGHT), INK)
    draw = ImageDraw.Draw(image)

    # A soft wash in the product's two accent hues, drawn as a handful of
    # translucent ellipses rather than a real gradient: PIL has no gradient
    # primitive and this is indistinguishable at video bitrates.
    wash = Image.new("RGB", (WIDTH, HEIGHT), INK)
    wash_draw = ImageDraw.Draw(wash)
    for index in range(26):
        spread = 1500 - index * 46
        alpha = index / 26
        colour = (
            int(INK[0] + (CYAN[0] - INK[0]) * 0.10 * alpha),
            int(INK[1] + (CYAN[1] - INK[1]) * 0.10 * alpha),
            int(INK[2] + (CYAN[2] - INK[2]) * 0.10 * alpha),
        )
        wash_draw.ellipse(
            [-260 - spread // 4, HEIGHT - spread // 2, spread, HEIGHT + spread // 2],
            fill=colour,
        )
    for index in range(22):
        spread = 1300 - index * 50
        alpha = index / 22
        colour = (
            int(INK[0] + (VIOLET[0] - INK[0]) * 0.08 * alpha),
            int(INK[1] + (VIOLET[1] - INK[1]) * 0.08 * alpha),
            int(INK[2] + (VIOLET[2] - INK[2]) * 0.08 * alpha),
        )
        wash_draw.ellipse(
            [WIDTH - spread, -spread // 2, WIDTH + spread // 3, spread // 2],
            fill=colour,
        )
    image.paste(wash, (0, 0))
    draw = ImageDraw.Draw(image)

    # A fine technical grid, the same motif the application's hero uses.
    for x in range(0, WIDTH, 48):
        draw.line([(x, 0), (x, HEIGHT)], fill=(15, 23, 35), width=1)
    for y in range(0, HEIGHT, 48):
        draw.line([(0, y), (WIDTH, y)], fill=(15, 23, 35), width=1)

    bold = ImageFont.truetype(
        _font(FONT_BOLD_CANDIDATES), 66 if card.kind == "section" else 92
    )
    body = ImageFont.truetype(_font(FONT_CANDIDATES), 40)
    small = ImageFont.truetype(_font(FONT_MONO_CANDIDATES), 25)

    accent = {"title": CYAN, "section": VIOLET, "end": CYAN}[card.kind]

    top = 330 if card.kind != "section" else 400
    draw.line([(300, top - 50), (300 + 150, top - 50)], fill=accent, width=6)

    draw.text((300, top), card.heading, font=bold, fill=MIST)
    offset = top + (118 if card.kind != "section" else 100)
    for line in card.sub.split("\n"):
        draw.text((300, offset), line, font=body, fill=MIST_DIM)
        offset += 58
    if card.note:
        draw.text((300, offset + 44), card.note, font=small, fill=(100, 116, 139))

    if card.kind == "end":
        offset += 52
        for index, line in enumerate(END_CARD_FOOTER):
            colour = CYAN if index == len(END_CARD_FOOTER) - 1 else (118, 134, 158)
            draw.text((300, offset), line, font=small, fill=colour)
            offset += 40
    return image.save(path)


# ---------------------------------------------------------------------------
# narration
# ---------------------------------------------------------------------------
#: Acronyms a speech synthesiser reads as words. Spelling them out is only
#: for the audio: the caption on screen keeps the normal spelling, because
#: "T L S" printed under a dashboard would look like a mistake.
_SPOKEN_ACRONYMS = {
    "TLS": "T L S",
    "SMTP": "S M T P",
    "IMAP": "I M A P",
    "POP3": "P O P 3",
    "JSON": "J S O N",
    "HTML": "H T M L",
    "PDF": "P D F",
    "RSA": "R S A",
    "RFC": "R F C",
    "ML": "M L",
}


def _for_speech(text: str) -> str:
    """The same sentence, spelled for the synthesiser rather than the reader."""
    import re

    def swap(match: re.Match[str]) -> str:
        return _SPOKEN_ACRONYMS[match.group(0)]

    pattern = r"\b(" + "|".join(sorted(_SPOKEN_ACRONYMS, key=len, reverse=True)) + r")\b"
    return re.sub(pattern, swap, text)


def _speak(text: str, path: Path, voice: str, rate: int) -> float:
    """Synthesise one line. Returns its duration in seconds, or 0.0.

    `say` frequently writes its file and then never exits, holding the audio
    session open. Worse, the AIFF it leaves behind is truncated -- the header
    carries the length, so a half-written file has no readable duration. So a
    timed-out attempt is killed, its output discarded, and the line retried.

    After three failures the line is left silent rather than aborting the
    build: the caption still carries the words, so the video is still
    complete and still says what it is showing.
    """
    binary = shutil.which("say")
    if binary is None or not text.strip():
        return 0.0

    aiff = path.with_suffix(".aiff")
    for attempt in (1, 2, 3):
        aiff.unlink(missing_ok=True)
        path.unlink(missing_ok=True)
        process = subprocess.Popen(  # noqa: S603 - resolved path, fixed argv
            [binary, "-v", voice, "-r", str(rate), "-o", str(aiff),
             _for_speech(text)],
        )
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            print(f"  note: `say` hung, retry {attempt}/3 for {path.name}")
            continue
        if process.returncode != 0 or not aiff.is_file():
            print(f"  note: `say` failed, retry {attempt}/3 for {path.name}")
            continue

        convert = subprocess.run(  # noqa: S603 - resolved path, fixed argv
            [_ffmpeg(), "-y", "-loglevel", "error", "-i", str(aiff),
             "-ar", "48000", "-ac", "2", str(path)],
            check=False,
        )
        aiff.unlink(missing_ok=True)
        if convert.returncode == 0 and path.is_file():
            seconds = _duration(path)
            if seconds > 0.2:
                return seconds
        print(f"  note: unusable audio, retry {attempt}/3 for {path.name}")

    aiff.unlink(missing_ok=True)
    path.unlink(missing_ok=True)
    print(f"  WARNING: no narration for {path.name}; the caption still carries it")
    return 0.0


def _ffmpeg() -> str:
    binary = shutil.which("ffmpeg")
    if binary is None:
        raise SystemExit("ffmpeg is required and was not found on PATH.")
    return binary


def _ffprobe() -> str:
    binary = shutil.which("ffprobe")
    if binary is None:
        raise SystemExit("ffprobe is required and was not found on PATH.")
    return binary


def _duration(path: Path) -> float:
    result = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffprobe(), "-v", "error", "-show_entries", "format=duration",
         "-of", "default=nw=1:nk=1", str(path)],
        check=True, capture_output=True, text=True,
    )
    raw = result.stdout.strip()
    # ffprobe prints "N/A" for a truncated file rather than failing, and a
    # bare float() on that raises a ValueError that says nothing useful.
    try:
        return float(raw)
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# segments
# ---------------------------------------------------------------------------
def _render_caption(text: str, path: Path) -> Path | None:
    """Draw the caption band as an RGBA image.

    ffmpeg is not guaranteed to be built with libfreetype -- the one on this
    machine is not -- so ``drawtext`` cannot be relied on. Rendering the band
    with Pillow and compositing it with ``overlay`` needs no ffmpeg text
    support at all, and gives exact control over the typography.
    """
    if not text.strip():
        return None
    from PIL import Image, ImageDraw, ImageFont

    face = ImageFont.truetype(_font(FONT_BOLD_CANDIDATES), 44)
    lines = textwrap.wrap(text, width=62)[:3]
    line_height = 62
    band_height = line_height * len(lines) + 64

    band = Image.new("RGBA", (WIDTH, band_height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(band)
    draw.rectangle([0, 0, WIDTH, band_height], fill=(4, 8, 15, 242))
    draw.line([(0, 0), (WIDTH, 0)], fill=(34, 211, 238, 190), width=4)

    y = 32
    for line in lines:
        width = draw.textbbox((0, 0), line, font=face)[2]
        draw.text(((WIDTH - width) / 2, y), line, font=face, fill=(226, 234, 245, 255))
        y += line_height
    band.save(path)
    return path


def _encode_card(card: Card, png: Path, audio: Path | None, out: Path) -> None:
    seconds = card.seconds
    if audio is not None and audio.exists():
        seconds = max(seconds, _duration(audio) + 1.1)
    argv = [_ffmpeg(), "-y", "-loglevel", "error",
            "-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}", "-i", str(png)]
    if audio is not None and audio.exists():
        argv += ["-i", str(audio),
                 "-filter_complex", "[1:a]adelay=500|500,apad[a]",
                 "-map", "0:v", "-map", "[a]", "-shortest"]
    else:
        argv += ["-f", "lavfi", "-t", f"{seconds:.3f}",
                 "-i", "anullsrc=channel_layout=stereo:sample_rate=48000",
                 "-map", "0:v", "-map", "1:a"]
    # A gentle fade in and out, so a card does not cut hard into the footage.
    argv += ["-vf", f"fps={FPS},format=yuv420p,fade=t=in:st=0:d=0.45,"
                    f"fade=t=out:st={max(0.0, seconds - 0.45):.3f}:d=0.45",
             "-c:v", "libx264", "-preset", "slow", "-crf", "18",
             "-c:a", "aac", "-b:a", "192k", "-t", f"{seconds:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _encode_clip(source: Path, start: float, length: float, caption: Path | None,
                 audio: Path | None, out: Path) -> None:
    """Cut one segment, composite its caption band and lay its narration under it.

    When the narration runs past the footage the final frame is held with
    ``tpad`` rather than the footage being sped up to fit: the recording is
    evidence, and its timing is not adjusted.
    """
    seconds = length
    if audio is not None and audio.exists():
        seconds = max(seconds, _duration(audio) + 0.8)
    hold = max(0.0, seconds - length)

    argv = [_ffmpeg(), "-y", "-loglevel", "error",
            "-ss", f"{start:.3f}", "-t", f"{length:.3f}", "-i", str(source)]
    inputs = 1
    caption_index = None
    if caption is not None:
        argv += ["-i", str(caption)]
        caption_index = inputs
        inputs += 1
    audio_index = None
    if audio is not None and audio.exists():
        argv += ["-i", str(audio)]
        audio_index = inputs
        inputs += 1

    chain = [
        f"[0:v]fps={FPS},scale={WIDTH}:{HEIGHT},"
        f"tpad=stop_mode=clone:stop_duration={hold:.3f}[base]"
    ]
    video_label = "[base]"
    if caption_index is not None:
        chain.append(f"[base][{caption_index}:v]overlay=x=0:y=H-h[capped]")
        video_label = "[capped]"
    chain.append(f"{video_label}format=yuv420p[v]")

    if audio_index is not None:
        chain.append(f"[{audio_index}:a]adelay=250|250,apad[a]")
        audio_map = "[a]"
    else:
        argv += ["-f", "lavfi", "-t", f"{seconds:.3f}",
                 "-i", "anullsrc=channel_layout=stereo:sample_rate=48000"]
        audio_map = f"{inputs}:a"

    argv += ["-filter_complex", ";".join(chain),
             "-map", "[v]", "-map", audio_map,
             "-c:v", "libx264", "-preset", "slow", "-crf", "18",
             "-c:a", "aac", "-b:a", "192k",
             "-t", f"{seconds:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _timecode(seconds: float) -> str:
    whole = int(seconds)
    ms = int(round((seconds - whole) * 1000))
    return f"{whole // 3600:02d}:{whole // 60 % 60:02d}:{whole % 60:02d},{ms:03d}"


def _write_srt(entries: list[tuple[float, float, str]], path: Path) -> None:
    """Write the captions as an .srt, with the timings of the finished file.

    The burned-in band is the primary caption; this exists so the same text is
    available as a separate track, and so the subtitle file can never claim a
    timing the video does not have -- both come from the assembled segments.
    """
    lines: list[str] = []
    for index, (start, end, text) in enumerate(entries, start=1):
        wrapped = "\n".join(textwrap.wrap(text, width=76)[:3])
        lines.append(
            f"{index}\n{_timecode(start)} --> {_timecode(end)}\n{wrapped}\n"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


def _frame_page(page_png: Path, out: Path) -> Path:
    """Centre a portrait page on a 1920x1080 canvas in the product's ink.

    Scaling a portrait page to fill a landscape frame would either crop the
    page or distort it. Letterboxing it keeps the document readable and
    obviously a document.
    """
    from PIL import Image

    canvas = Image.new("RGB", (WIDTH, HEIGHT), INK)
    with Image.open(page_png) as page:
        scale = (HEIGHT - 64) / page.height
        size = (max(1, int(page.width * scale)), HEIGHT - 64)
        # `Image.Resampling` is the current spelling; the old `Image.LANCZOS`
        # alias is not visible to the type checker.
        resized = page.convert("RGB").resize(size, Image.Resampling.LANCZOS)
        canvas.paste(resized, ((WIDTH - size[0]) // 2, 32))
    canvas.save(out)
    return out


def _encode_still(
    png: Path, caption: Path | None, audio: Path | None, out: Path,
    *, seconds: float,
) -> None:
    """A held still with the same caption band and narration as a clip."""
    length = seconds
    if audio is not None and audio.exists():
        length = max(length, _duration(audio) + 1.0)

    argv = [_ffmpeg(), "-y", "-loglevel", "error",
            "-loop", "1", "-framerate", str(FPS), "-t", f"{length:.3f}",
            "-i", str(png)]
    inputs = 1
    caption_index = None
    if caption is not None:
        argv += ["-loop", "1", "-framerate", str(FPS), "-t", f"{length:.3f}",
                 "-i", str(caption)]
        caption_index = inputs
        inputs += 1
    audio_index = None
    if audio is not None and audio.exists():
        argv += ["-i", str(audio)]
        audio_index = inputs
        inputs += 1

    chain = [f"[0:v]fps={FPS},scale={WIDTH}:{HEIGHT}[base]"]
    label = "[base]"
    if caption_index is not None:
        chain.append(f"[base][{caption_index}:v]overlay=x=0:y=H-h[capped]")
        label = "[capped]"
    chain.append(f"{label}format=yuv420p[v]")

    if audio_index is not None:
        chain.append(f"[{audio_index}:a]adelay=350|350,apad[a]")
        audio_map = "[a]"
    else:
        argv += ["-f", "lavfi", "-t", f"{length:.3f}",
                 "-i", "anullsrc=channel_layout=stereo:sample_rate=48000"]
        audio_map = f"{inputs}:a"

    argv += ["-filter_complex", ";".join(chain),
             "-map", "[v]", "-map", audio_map,
             "-c:v", "libx264", "-preset", "slow", "-crf", "18",
             "-c:a", "aac", "-b:a", "192k",
             "-t", f"{length:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _find_footage() -> Path:
    """The most recent Playwright recording."""
    candidates = sorted(
        (ROOT / "frontend" / "test-results").rglob("*.webm"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise SystemExit(
            "no recording found. Run:  cd frontend && "
            "SMS_SCREENSHOTS=1 npx playwright test demo-capture"
        )
    return candidates[0]


#: Spellings that must never appear on screen or in the narration. The team
#: registered as exactly "Zero-Day".
FORBIDDEN_TEAM_STRINGS = (
    "Team Zero-Day", "Team Zero Day", "Team zero day", "Team ZERO-DAY",
    "Zero Day", "Your Team Name",
)


def _check_text() -> None:
    """Refuse to build a video that spells the team name wrongly."""
    corpus = "\n".join(
        [TITLE_CARD.heading, TITLE_CARD.sub, TITLE_CARD.note, TITLE_CARD.narration,
         END_CARD.heading, END_CARD.sub, END_CARD.note, END_CARD.narration]
        + [f"{c.heading} {c.sub} {c.note} {c.narration}" for c in SECTION_CARDS.values()]
        + list(NARRATION.values())
    )
    bad = [s for s in FORBIDDEN_TEAM_STRINGS if s in corpus]
    if bad:
        raise SystemExit(f"forbidden team spelling in the video text: {bad}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT)
    parser.add_argument("--voice", default="Samantha")
    parser.add_argument("--rate", type=int, default=168)
    parser.add_argument("--silent", action="store_true",
                        help="Build with captions only and no audio narration.")
    args = parser.parse_args()

    _check_text()

    beats_file = FOOTAGE / "beats.json"
    if not beats_file.is_file():
        raise SystemExit(f"no beat log at {beats_file}. Record the footage first.")
    record = json.loads(beats_file.read_text())
    beats = record["beats"]

    source = _find_footage()
    total = _duration(source)
    print(f"footage : {source.relative_to(ROOT)}  ({total:.1f}s)")

    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)

    spoken = shutil.which("say") is not None and not args.silent
    if not spoken:
        print("narration: none (captions only)"
              if args.silent else
              "narration: unavailable on this platform; building captions only")

    pieces: list[Path] = []
    #: (start_seconds, end_seconds, caption) for every captioned segment, in
    #: the order they appear in the finished file.
    subtitles: list[tuple[float, float, str]] = []
    elapsed = 0.0

    def add_card(card: Card, name: str) -> None:
        png = BUILD / f"{name}.png"
        _render_card(card, png)
        audio = None
        if spoken and card.narration:
            audio = BUILD / f"{name}.wav"
            _speak(card.narration, audio, args.voice, args.rate)
        out = BUILD / f"{name}.mp4"
        _encode_card(card, png, audio, out)
        pieces.append(out)
        nonlocal elapsed
        elapsed += _duration(out)

    add_card(TITLE_CARD, "00-title")

    for index, beat in enumerate(beats):
        beat_id = beat["id"]
        start = beat["at_ms"] / 1000.0
        end = (
            beats[index + 1]["at_ms"] / 1000.0
            if index + 1 < len(beats)
            else min(total, start + 4.0)
        )
        length = max(0.6, min(end, total) - start)
        if start >= total:
            print(f"  skip {beat_id}: beyond the end of the recording")
            continue

        if beat_id in SECTION_CARDS:
            add_card(SECTION_CARDS[beat_id], f"{index:02d}-card-{beat_id}")

        text = NARRATION.get(beat_id, "")
        caption = _render_caption(text, BUILD / f"{index:02d}-{beat_id}.png")
        audio = None
        if spoken and text:
            audio = BUILD / f"{index:02d}-{beat_id}.wav"
            _speak(text, audio, args.voice, args.rate)
        clip = BUILD / f"{index:02d}-{beat_id}.mp4"
        _encode_clip(source, start, length, caption, audio, clip)
        pieces.append(clip)
        clip_seconds = _duration(clip)
        if text:
            subtitles.append((elapsed, elapsed + clip_seconds, text))
        elapsed += clip_seconds
        print(f"  {beat_id:<15} {start:6.1f}s  +{length:4.1f}s")

    # The exported PDF, shown as a full frame. Headless Chromium downloads a
    # PDF rather than displaying it, so the page is rasterised from the very
    # file this recording downloaded -- not from a stock image, and not from a
    # different build of the report.
    exported_pdf = ROOT / record.get(
        "exported_pdf", "local-evidence/exports/securemailscope-report.pdf"
    )
    if exported_pdf.is_file():
        page_png = BUILD / "98-pdf-page.png"
        rendered = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(ROOT / "scripts" / "render_report_page.py"),
             str(exported_pdf), str(page_png), "--width", "1400"],
            check=False, capture_output=True, text=True,
        )
        if rendered.returncode == 0 and page_png.is_file():
            framed = _frame_page(page_png, BUILD / "98-pdf-frame.png")
            text = (
                "And the same report as a PDF, paginated, with the generation "
                "metadata on every page."
            )
            audio = None
            if spoken:
                audio = BUILD / "98-pdf.wav"
                _speak(text, audio, args.voice, args.rate)
            caption = _render_caption(text, BUILD / "98-pdf-caption.png")
            clip = BUILD / "98-pdf.mp4"
            _encode_still(framed, caption, audio, clip, seconds=9.0)
            clip_seconds = _duration(clip)
            subtitles.append((elapsed, elapsed + clip_seconds, text))
            elapsed += clip_seconds
            pieces.append(clip)
            print(f"  {'exported pdf':<15} rasterised from the downloaded file")
        else:
            print("  exported pdf: no renderer available, omitted")

    add_card(END_CARD, "99-end")

    listing = BUILD / "concat.txt"
    listing.write_text("".join(f"file '{p.name}'\n" for p in pieces))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-y", "-loglevel", "error",
         "-f", "concat", "-safe", "0", "-i", str(listing),
         "-c:v", "libx264", "-preset", "slow", "-crf", "18",
         "-pix_fmt", "yuv420p", "-r", str(FPS),
         "-x264-params", "ref=4:bframes=3",
         "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart",
         str(args.out)],
        check=True, cwd=BUILD,
    )

    _write_srt(subtitles, ROOT / "submission" / "demo" / "captions.srt")

    import hashlib

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    seconds = _duration(args.out)
    print()
    print(f"video   : {args.out.relative_to(ROOT)}")
    print(f"duration: {int(seconds // 60)}:{int(seconds % 60):02d}  "
          f"({seconds:.1f}s)  {WIDTH}x{HEIGHT} @ {FPS}fps H.264")
    print(f"size    : {args.out.stat().st_size:,} bytes")
    print(f"sha256  : {digest}")
    if not 150 <= seconds <= 260:
        print(f"\nWARNING: {seconds:.0f}s is outside the 3-4 minute target.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
