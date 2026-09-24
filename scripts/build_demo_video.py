#!/usr/bin/env python3
"""Assemble the demonstration video from genuine product footage.

The footage is a Playwright recording of the real application driving the real
backend over the real forensic engine on the synthetic demo dataset. This
script cuts it, lays the narration under it and adds two cards -- an opening
title and an end card. Nothing else is added, and nothing is invented: every
frame of product is the recording, and every caption is a label for what that
frame is showing.

The cut opens on the finding rather than on a title, so the first thing a
viewer sees is the product doing the thing the project exists to do. That shot
is recorded partway through the take; assembling out of recording order is
ordinary editing, not a staged result.

Narration is generated separately by `scripts/make_narration.sh` using a
neural speech provider and committed to `local-evidence/narration/` (which is
gitignored -- the script that produces it is committed instead). If a segment
is missing the cut still builds: the caption carries the point and the segment
plays without voice.

    SMS_SCREENSHOTS=1 npx playwright test demo-capture   # record
    bash scripts/make_narration.sh                       # narrate
    python scripts/build_demo_video.py                   # assemble
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOOTAGE = ROOT / "local-evidence" / "footage"
NARRATION = ROOT / "local-evidence" / "narration"
BUILD = ROOT / "local-evidence" / "video-build"
OUT_DEFAULT = ROOT / "submission" / "final" / "SecureMailScope-SIH26159-Demo.mp4"

WIDTH, HEIGHT, FPS = 1920, 1080, 30
SAMPLE_RATE = 48000
#: Silence before a line starts inside its shot, and after it ends.
LEAD, TAIL = 0.35, 0.55
GAP = 0.45              # breath between two lines spoken over one shot
TAG = 1.20              # footage kept after a line ends, before the cut
SILENT = 4.50           # how long a shot with no line of its own runs
CRF = "18"

INK = (7, 12, 20)
MIST = (226, 234, 245)
MIST_DIM = (139, 157, 181)
CYAN = (34, 211, 238)
VIOLET = (167, 139, 250)

FONT_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
)
FONT_BOLD_CANDIDATES = (
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
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
    raise SystemExit("no usable font found; install DejaVu or Liberation fonts")


# ---------------------------------------------------------------------------
# the cut
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Shot:
    """One segment of product footage.

    `beat` names the section's own recording, local-evidence/footage/<beat>.webm.
    One file per shot is what makes the cut trustworthy: Playwright drops
    frames while the page is busy, so an offset into a single long recording
    does not point at the frame it was measured against, while a whole file
    cannot drift from what it recorded. `narration` names a file in
    local-evidence/narration; `captions` are short labels, not a transcript.
    """

    beat: str
    narration: str | tuple[str, ...] | None = None
    captions: tuple[str, ...] = ()
    seconds: float | None = None          # cap the window; None = whole clip
    zoom: float = 1.0                     # gentle push-in over the shot
    lead: float = 0.0                     # silence before the line starts


@dataclass
class Card:
    kind: str
    seconds: float
    heading: str
    sub: str = ""
    note: str = ""
    narration: str | None = None
    footer: tuple[str, ...] = field(default_factory=tuple)


#: The team introduces itself over the title, the way it would in the room.
#: The card is held for as long as that takes.
TITLE_CARD = Card(
    kind="title", seconds=4.4, narration="01-intro",
    heading="SecureMailScope",
    sub="Cryptographic security posture, from the packets you already have.",
    note="Smart India Hackathon 2026  ·  SIH26159  ·  NTRO  ·  Zero-Day",
)

END_CARD = Card(
    kind="end", seconds=7.5, narration="14-close",
    heading="SecureMailScope",
    sub="Passive  ·  Local-first  ·  Evidence-linked",
    footer=(
        "Smart India Hackathon 2026  ·  Problem statement SIH26159",
        "National Technical Research Organisation",
        "Theme: Blockchain & Cybersecurity  ·  Category: Software",
        "Team ID 146876  ·  Zero-Day",
        "github.com/sgtsujith141-wq/securemailscope",
    ),
)

#: The cut, in order. A presentation, not an advertisement: it opens on the
#: title the way a team opens a talk, then shows the product doing the work.
CUT: list[Shot | Card] = [
    TITLE_CARD,
    Shot("firstrun", narration="02-what",
         captions=("Passive PCAP / PCAPNG analysis",)),
    Shot("upload", narration=("03-problem", "04-passive"),
         captions=("Authorised captures only",
                   "No live scan \u00b7 the capture stays on this machine")),
    Shot("overview", narration="05-analysis",
         captions=("Controlled synthetic capture", "59/100 \u00b7 WEAK"), zoom=1.04),
    Shot("modules", narration="06-engine",
         captions=("Session \u00b7 protocol \u00b7 TLS \u00b7 assessment",)),
    Shot("finding", narration=None,
         captions=("Findings, ranked by priority",)),
    Shot("finding-detail", narration="07-finding",
         captions=("TLS-KEX-001 \u00b7 HIGH", "Static RSA \u00b7 no forward secrecy"),
         zoom=1.04),
    Shot("evidence", narration="08-evidence",
         captions=("Packets #4 and #5", "Rule \u00b7 severity \u00b7 remediation"),
         zoom=1.05),
    Shot("verify", narration="09-verify",
         captions=("Packets #4\u2013#5 \u00b7 independently verifiable in Wireshark",),
         zoom=1.03),
    Shot("tls13", narration="10-tls13",
         captions=("TLS 1.3 certificate", "Reported NOT AVAILABLE, not guessed")),
    Shot("drift-setup", narration=None,
         captions=("A second observation of the same service",)),
    Shot("drift", narration="11-drift",
         captions=("Cryptographic drift", "TLS 1.2 \u2192 OBSERVED_CHANGE \u2192 TLS 1.0"),
         zoom=1.04),
    Shot("report", narration="12-report",
         captions=("JSON \u00b7 standalone HTML \u00b7 PDF",)),
    # Long enough to read, now that the page is drawn at a size that can be.
    Shot("__pdf__", narration=None, captions=("The exported forensic report",),
         seconds=5.2),
    Shot("__pdf2__", narration=None,
         captions=("Findings \u00b7 packet references \u00b7 remediation",), seconds=5.4),
    Shot("montage", narration="13-summary",
         captions=("Every finding traces to the packets that produced it",)),
    END_CARD,
]


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------
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
        check=False, capture_output=True, text=True,
    )
    try:
        return float(result.stdout.strip())
    except ValueError:
        return 0.0


def _render_card(card: Card, path: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", (WIDTH, HEIGHT), INK)
    wash = ImageDraw.Draw(image)
    for index in range(26):
        spread = 1500 - index * 46
        alpha = index / 26
        wash.ellipse(
            [-260 - spread // 4, HEIGHT - spread // 2, spread, HEIGHT + spread // 2],
            fill=tuple(int(INK[i] + (CYAN[i] - INK[i]) * 0.10 * alpha) for i in range(3)),
        )
    for index in range(22):
        spread = 1300 - index * 50
        alpha = index / 22
        wash.ellipse(
            [WIDTH - spread, -spread // 2, WIDTH + spread // 3, spread // 2],
            fill=tuple(int(INK[i] + (VIOLET[i] - INK[i]) * 0.08 * alpha) for i in range(3)),
        )
    draw = ImageDraw.Draw(image)
    for x in range(0, WIDTH, 48):
        draw.line([(x, 0), (x, HEIGHT)], fill=(15, 23, 35), width=1)
    for y in range(0, HEIGHT, 48):
        draw.line([(0, y), (WIDTH, y)], fill=(15, 23, 35), width=1)

    bold = ImageFont.truetype(_font(FONT_BOLD_CANDIDATES), 96)
    body = ImageFont.truetype(_font(FONT_CANDIDATES), 40)
    small = ImageFont.truetype(_font(FONT_MONO_CANDIDATES), 25)

    top = 340
    draw.line([(300, top - 50), (450, top - 50)], fill=CYAN, width=6)
    draw.text((300, top), card.heading, font=bold, fill=MIST)
    offset = top + 124
    for line in card.sub.split("\n"):
        draw.text((300, offset), line, font=body, fill=MIST_DIM)
        offset += 58
    if card.note:
        draw.text((300, offset + 40), card.note, font=small, fill=(100, 116, 139))
    if card.footer:
        offset += 52
        for index, line in enumerate(card.footer):
            colour = CYAN if index == len(card.footer) - 1 else (118, 134, 158)
            draw.text((300, offset), line, font=small, fill=colour)
            offset += 40
    image.save(path)


def _render_caption(lines: tuple[str, ...], path: Path) -> Path | None:
    """Short labels in a band, not a transcript of the narration."""
    if not lines:
        return None
    from PIL import Image, ImageDraw, ImageFont

    face = ImageFont.truetype(_font(FONT_BOLD_CANDIDATES), 46)
    wrapped: list[str] = []
    for line in lines:
        wrapped.extend(textwrap.wrap(line, width=52)[:2])
    wrapped = wrapped[:2] if len(lines) > 2 else wrapped[:2]

    line_height = 64
    band_height = line_height * len(wrapped) + 56
    band = Image.new("RGBA", (WIDTH, band_height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(band)
    draw.rectangle([0, 0, WIDTH, band_height], fill=(4, 8, 15, 232))
    draw.line([(0, 0), (WIDTH, 0)], fill=(34, 211, 238, 210), width=4)
    y = 26
    for line in wrapped:
        width = draw.textbbox((0, 0), line, font=face)[2]
        draw.text(((WIDTH - width) / 2, y), line, font=face, fill=(226, 234, 245, 255))
        y += line_height
    band.save(path)
    return path


#: How wide the exported page is drawn on the 16:9 canvas. Fitting a portrait
#: page to the frame height leaves it about a third of the width and its text
#: too small to read from a seat; this is wide enough to read and still leaves
#: a margin either side.
PAGE_WIDTH = 1180


def _frame_page(page_png: Path, out: Path) -> Path:
    """Draw a portrait page on a 16:9 canvas, top-anchored and readable.

    The page is scaled for legibility rather than to fit, so what runs past
    the bottom of the frame is simply not shown. The top of a report page is
    where the summary and the first finding are, which is what the shot is
    there to show.
    """
    from PIL import Image

    canvas = Image.new("RGB", (WIDTH, HEIGHT), INK)
    with Image.open(page_png) as page:
        scale = PAGE_WIDTH / page.width
        size = (PAGE_WIDTH, max(1, int(page.height * scale)))
        drawn = page.convert("RGB").resize(size, Image.Resampling.LANCZOS)
        canvas.paste(drawn, ((WIDTH - PAGE_WIDTH) // 2, 24))
    canvas.save(out)
    return out


def _encode_video(
    inputs: list[str], chain: list[str], label: str, seconds: float, out: Path,
) -> None:
    """Encode one segment, video only.

    Narration is not attached here. Laying a line under each clip and then
    concatenating means a join inside the audio at every cut, and a join is
    where a click comes from. Instead every clip is silent, and one continuous
    narration track is mixed over the finished picture.
    """
    argv = [_ffmpeg(), "-y", "-loglevel", "error", *inputs,
            "-filter_complex", ";".join(chain), "-map", label,
            "-an",
            "-c:v", "libx264", "-preset", "slow", "-crf", CRF,
            "-profile:v", "high", "-pix_fmt", "yuv420p", "-r", str(FPS),
            "-t", f"{seconds:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _encode_card(card: Card, png: Path, seconds: float, out: Path) -> None:
    fade = max(0.0, seconds - 0.4)
    _encode_video(
        ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}", "-i", str(png)],
        [f"[0:v]fps={FPS},format=yuv420p,fade=t=in:st=0:d=0.4,"
         f"fade=t=out:st={fade:.3f}:d=0.4[v]"],
        "[v]", seconds, out,
    )


def _encode_still(png: Path, caption: Path | None, seconds: float, out: Path) -> None:
    inputs = ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}", "-i", str(png)]
    chain = [f"[0:v]fps={FPS},scale={WIDTH}:{HEIGHT}[base]"]
    label = "[base]"
    if caption is not None:
        inputs += ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}",
                   "-i", str(caption)]
        chain.append("[base][1:v]overlay=x=0:y=H-h[capped]")
        label = "[capped]"
    chain.append(f"{label}format=yuv420p[v]")
    _encode_video(inputs, chain, "[v]", seconds, out)


def _encode_shot(source: Path, start: float, length: float, shot: Shot,
                 caption: Path | None, seconds: float, out: Path) -> None:
    """Cut one shot, push in gently, composite its caption.

    Where the line of narration runs past the footage the final frame is held
    rather than the footage being sped up: the recording is evidence, and its
    timing is not adjusted to fit a script.
    """
    hold = max(0.0, seconds - length)
    inputs = ["-ss", f"{start:.3f}", "-t", f"{length:.3f}", "-i", str(source)]
    steps = [f"fps={FPS}", f"scale={WIDTH}:{HEIGHT}"]
    if shot.zoom > 1.0:
        steps.append(
            f"zoompan=z='min(zoom+{(shot.zoom - 1) / (seconds * FPS):.6f},{shot.zoom})'"
            f":d=1:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)'"
            f":s={WIDTH}x{HEIGHT}:fps={FPS}"
        )
    steps.append(f"tpad=stop_mode=clone:stop_duration={hold:.3f}")
    chain = ["[0:v]" + ",".join(steps) + "[base]"]
    label = "[base]"
    if caption is not None:
        inputs += ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}",
                   "-i", str(caption)]
        chain.append("[base][1:v]overlay=x=0:y=H-h[capped]")
        label = "[capped]"
    chain.append(f"{label}format=yuv420p[v]")
    _encode_video(inputs, chain, "[v]", seconds, out)


def _build_narration(
    placements: list[tuple[float, Path]], total: float, out: Path,
) -> None:
    """One continuous narration track, each line mixed in at its own offset.

    No concatenation and therefore no joins: the lines are delayed onto a
    single silent bed and summed. They never overlap, so `normalize=0` is
    exact addition rather than the attenuation `amix` applies by default.
    """
    argv = [_ffmpeg(), "-y", "-loglevel", "error",
            "-f", "lavfi", "-t", f"{total:.3f}",
            "-i", f"anullsrc=channel_layout=stereo:sample_rate={SAMPLE_RATE}"]
    chain: list[str] = []
    labels = ["[0:a]"]
    for index, (offset, path) in enumerate(placements, start=1):
        argv += ["-i", str(path)]
        ms = int(round(offset * 1000))
        # A short fade at each end of a line, so a take that starts on a hard
        # transient cannot produce a click when it is summed in.
        chain.append(
            f"[{index}:a]aresample={SAMPLE_RATE},afade=t=in:st=0:d=0.012,"
            f"areverse,afade=t=in:st=0:d=0.012,areverse,"
            f"adelay={ms}|{ms}[n{index}]"
        )
        labels.append(f"[n{index}]")
    chain.append(
        "".join(labels) + f"amix=inputs={len(labels)}:normalize=0:dropout_transition=0"
        f",atrim=0:{total:.3f},asetpts=N/SR/TB[a]"
    )
    argv += ["-filter_complex", ";".join(chain), "-map", "[a]",
             "-ar", str(SAMPLE_RATE), "-ac", "2", "-c:a", "pcm_s16le",
             "-t", f"{total:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _aac_args() -> list[str]:
    """Encoder arguments that actually deliver the stated audio bitrate.

    ffmpeg's built-in AAC encoder treats `-b:a` as a ceiling and rate-controls
    below it, so a narration track with pauses in it lands near 130 kb/s no
    matter what is asked for. AudioToolbox will hold a constant rate, so it is
    preferred where it exists and the built-in encoder is the fallback.
    """
    have = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-hide_banner", "-encoders"],
        capture_output=True, text=True, check=False,
    ).stdout
    if " aac_at " in have:
        return ["-c:a", "aac_at", "-aac_at_mode", "cbr", "-b:a", "192k"]
    return ["-c:a", "aac", "-b:a", "192k"]


def _normalise_audio(source: Path, out: Path) -> None:
    """Bring the narration track to -16 LUFS with a -1 dBTP ceiling.

    Two passes, because one-pass `loudnorm` only estimates and lands a couple
    of LU away -- audible as a video quieter than everything else a judge has
    just watched. The measurement from the first pass feeds the second.
    """
    probe = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-hide_banner", "-i", str(source),
         "-af", "loudnorm=I=-16:TP=-1.0:LRA=11:print_format=json",
         "-f", "null", "-"],
        check=False, capture_output=True, text=True,
    )
    # ffmpeg prints the measurement as a JSON object and then keeps writing:
    # the muxing summary and a final progress line follow it. Take the block
    # from its opening brace to its own closing brace, not to end of output.
    measured: dict[str, str] = {}
    lines = probe.stderr.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip() != "{":
            continue
        for close in range(index + 1, len(lines)):
            if lines[close].strip() == "}":
                with contextlib.suppress(json.JSONDecodeError):
                    measured = json.loads("\n".join(lines[index:close + 1]))
                break
        break

    needed = ("input_i", "input_tp", "input_lra", "input_thresh", "target_offset")
    if all(key in measured for key in needed):
        chain = (
            "loudnorm=I=-16:TP=-1.0:LRA=11"
            f":measured_I={measured['input_i']}"
            f":measured_TP={measured['input_tp']}"
            f":measured_LRA={measured['input_lra']}"
            f":measured_thresh={measured['input_thresh']}"
            f":offset={measured['target_offset']}:linear=true"
        )
    else:
        print("  note: loudness measurement unavailable; single-pass fallback")
        chain = "loudnorm=I=-16:TP=-1.0:LRA=11"
    # A limiter after normalisation, so nothing can clip: -1 dBTP is 0.891.
    # `level` is on by default and would lift the whole track up to that
    # ceiling, undoing the normalisation and landing about a loudness unit
    # hot. The limiter is here to catch peaks, not to set the level.
    chain += ",alimiter=limit=0.891:level=disabled"

    subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-y", "-loglevel", "error", "-i", str(source),
         "-af", chain, "-ar", str(SAMPLE_RATE), "-ac", "2",
         "-c:a", "pcm_s16le", str(out)],
        check=True,
    )


def _content_starts(source: Path, limit: float = 6.0) -> float:
    """Where the recorded page stops loading and the product is on screen.

    A recording opens on the browser's blank white page and stays bright
    until the dark application paints. Rather than trimming a guessed number
    of seconds, measure it: walk the opening frames and take the first one
    whose average luma has dropped into the application's range. The
    application sits near luma 15-40 and a blank page near 235, so the
    threshold is nowhere near either. Nothing is moving during those frames,
    so nothing of the demonstration is lost.
    """
    # `file=-` sends the measurements to stdout. Left on ffmpeg's own output
    # they are printed at info level, which a quiet build never shows, and the
    # trim silently becomes zero.
    probe = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-v", "error", "-t", f"{limit:.2f}", "-i", str(source),
         "-vf",
         "signalstats,metadata=print:key=lavfi.signalstats.YAVG:file=-",
         "-f", "null", "-"],
        capture_output=True, text=True, check=False,
    )
    at = 0.0
    for line in probe.stdout.splitlines():
        stamp = re.search(r"pts_time:([0-9.]+)", line)
        if stamp:
            at = float(stamp.group(1))
            continue
        luma = re.search(r"lavfi\.signalstats\.YAVG=([0-9.]+)", line)
        if luma and float(luma.group(1)) < 110.0:
            # Start on the first fully painted frame, not just before it: a
            # single white frame at a cut is the most visible defect there is.
            return at + 0.08
    return 0.0


def _pdf_pages(pdf: Path, count: int) -> list[Path]:
    """Rasterise the first pages of the report this recording downloaded.

    Headless Chromium downloads a PDF rather than displaying it, so the PDF is
    shown in the cut as pages rendered from the very file the run produced.
    """
    pages: list[Path] = []
    for number in range(1, count + 1):
        single = BUILD / f"pdf-page-{number}.pdf"
        png = BUILD / f"pdf-page-{number}.png"
        try:
            from pypdf import PdfReader, PdfWriter

            reader = PdfReader(str(pdf))
            if number > len(reader.pages):
                break
            writer = PdfWriter()
            writer.add_page(reader.pages[number - 1])
            with single.open("wb") as handle:
                writer.write(handle)
        except ImportError:
            single = pdf
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(ROOT / "scripts" / "render_report_page.py"),
             str(single), str(png), "--width", "1500"],
            check=False, capture_output=True, text=True,
        )
        if result.returncode == 0 and png.is_file():
            pages.append(_frame_page(png, BUILD / f"pdf-frame-{number}.png"))
    return pages


def _bright_frames(video: Path, ceiling: float = 200.0) -> list[float]:
    """Every frame bright enough to be an unpainted page rather than the product.

    The application and the title cards are dark throughout, so a bright frame
    in the finished video means a browser load flash survived the cut. One of
    those at a join is the most obvious defect a viewer can see, so the build
    looks for them rather than trusting that the trim worked.
    """
    probe = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-v", "error", "-i", str(video),
         "-vf",
         "signalstats,metadata=print:key=lavfi.signalstats.YAVG:file=-",
         "-f", "null", "-"],
        capture_output=True, text=True, check=False,
    )
    found: list[float] = []
    at = 0.0
    for line in probe.stdout.splitlines():
        stamp = re.search(r"pts_time:([0-9.]+)", line)
        if stamp:
            at = float(stamp.group(1))
            continue
        luma = re.search(r"lavfi\.signalstats\.YAVG=([0-9.]+)", line)
        if luma and float(luma.group(1)) > ceiling:
            found.append(at)
    return found


def _loudness(video: Path) -> dict[str, str]:
    """Measure the finished file, rather than assert what it was asked for."""
    probe = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-hide_banner", "-nostats", "-i", str(video),
         "-af", "ebur128=peak=true", "-f", "null", "-"],
        capture_output=True, text=True, check=False,
    )
    tail = probe.stderr[probe.stderr.rfind("Summary"):]
    out: dict[str, str] = {}
    for key, label in (("I:", "integrated"), ("LRA:", "range"),
                       ("Peak:", "true_peak")):
        found = re.search(rf"{re.escape(key)}\s*(-?[0-9.]+)\s*(LUFS|LU|dBFS)", tail)
        if found:
            out[label] = f"{found.group(1)} {found.group(2)}"
    return out


def _write_final_script(
    assembled: list[tuple[str, float, float, list[str], tuple[str, ...]]],
    video: Path, loudness: dict[str, str], path: Path,
) -> None:
    """Describe the video that was actually built, not one that was planned.

    Written by the build from the cut it just assembled, so the sheet cannot
    drift from the file the way a hand-maintained one does.
    """
    seconds = _duration(video)
    lines = [
        "# Final script \u2014 the finished video",
        "",
        "Written by `scripts/build_demo_video.py` from the cut it assembled, so",
        "every timing below is the file's own. The footage is a Playwright",
        "recording of the real application against the real backend: one",
        "recording per shot, concatenated whole.",
        "",
        f"**`{video.relative_to(ROOT)}` \u2014 "
        f"{int(seconds // 60)} min {int(seconds % 60):02d} s, "
        f"{WIDTH}x{HEIGHT}, {FPS} fps, H.264 High, CRF {CRF}, AAC 192 kbps"
        + (f" at {loudness['integrated']}" if "integrated" in loudness else "")
        + ".**",
        "",
    ]
    if loudness:
        lines += [
            "| Measurement | Value |", "|---|---|",
            *(f"| {k.replace('_', ' ').capitalize()} | {v} |"
              for k, v in loudness.items()),
            "",
        ]
    lines += [
        "## The cut",
        "",
        "| # | At | Length | Element | Narration | Caption |",
        "|---:|---:|---:|---|---|---|",
    ]
    for index, (label, at, length, spoken, captions) in enumerate(assembled, 1):
        lines.append(
            f"| {index} | {_timecode(at)[:8]} | {length:.1f}s | {label} | "
            f"{', '.join(f'`{n}`' for n in spoken) or '\u2014'} | "
            f"{' \u00b7 '.join(captions) or '\u2014'} |"
        )
    cards = sum(1 for label, *_ in assembled if label.startswith("card"))
    stills = sum(1 for label, *_ in assembled if label.startswith("pdf"))
    lines += [
        "",
        f"{cards} full-screen cards and {stills} report-page stills. Everything",
        "else is the product being used.",
        "",
        "## Captions",
        "",
        "Short supportive labels, not a transcript. At most two lines, 46 px",
        "bold on an opaque band, readable on a projector and on a phone. The",
        "same text is written to `captions.srt` with the timings of this file.",
        "",
        "## Narration",
        "",
        "See `narration.md` for the spoken words, the voice and its settings.",
        "The lines are mixed onto one continuous bed at absolute offsets rather",
        "than butted together per clip, so there is no join in the audio at a",
        "picture cut, and each line is faded in and out over 12 ms.",
        "",
    ]
    path.write_text("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT)
    parser.add_argument("--silent", action="store_true",
                        help="Build the same cut with captions and no narration.")
    args = parser.parse_args()

    log = FOOTAGE / "sections.json"
    if not log.is_file():
        raise SystemExit(
            f"no recording at {log}. Run:  cd frontend && "
            "SMS_SCREENSHOTS=1 npx playwright test demo-capture"
        )
    record = json.loads(log.read_text())
    clips = {p.stem: p for p in sorted(FOOTAGE.glob("*.webm"))}
    print(f"footage : {len(clips)} section recordings in "
          f"{FOOTAGE.relative_to(ROOT)}")

    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)

    pdf = ROOT / record.get(
        "exported_pdf", "local-evidence/exports/securemailscope-report.pdf")
    pdf_pages = _pdf_pages(pdf, 2) if pdf.is_file() else []

    def narration_for(name: str | tuple[str, ...] | None) -> list[Path]:
        """Every line a shot speaks, in order, skipping any not yet recorded."""
        if args.silent or not name:
            return []
        names = (name,) if isinstance(name, str) else name
        found: list[Path] = []
        for one in names:
            candidate = NARRATION / f"{one}.mp3"
            if candidate.is_file():
                found.append(candidate)
            else:
                missing.append(one)
        return found

    pieces: list[Path] = []
    assembled: list[tuple[str, float, float, list[str], tuple[str, ...]]] = []
    placements: list[tuple[float, Path]] = []
    subtitles: list[tuple[float, float, str]] = []
    elapsed = 0.0
    missing: list[str] = []

    for index, item in enumerate(CUT):
        name = f"{index:02d}"
        lines = narration_for(item.narration)
        # A pause between consecutive lines, so two sentences do not run into
        # one another the way a single breathless take would.
        spoken = sum(_duration(a) for a in lines) + GAP * max(0, len(lines) - 1)

        if isinstance(item, Card):
            seconds = max(item.seconds, spoken + LEAD + TAIL)
            png = BUILD / f"{name}-card.png"
            _render_card(item, png)
            clip = BUILD / f"{name}-card.mp4"
            _encode_card(item, png, seconds, clip)
            label = f"card: {item.heading}"
        elif item.beat.startswith("__pdf"):
            which = 0 if item.beat == "__pdf__" else 1
            if which >= len(pdf_pages):
                print(f"  {'pdf':<16} page {which + 1} unavailable, omitted")
                continue
            seconds = max(item.seconds or 4.0, spoken + LEAD + TAIL)
            caption = _render_caption(item.captions, BUILD / f"{name}-caption.png")
            clip = BUILD / f"{name}-pdf.mp4"
            _encode_still(pdf_pages[which], caption, seconds, clip)
            label = f"{item.beat.strip('_'):<16}"
        else:
            if item.beat not in clips:
                print(f"  {'skip':<16} {item.beat}: not recorded")
                continue
            source = clips[item.beat]
            total = _duration(source)
            floor = _content_starts(source)
            # Each section is recorded longer than the shot needs: it opens by
            # navigating to the screen it is about, and it ends settled on it.
            # Take the shot from the END of the recording, so the navigation
            # falls outside it and the caption never describes a screen that
            # has not arrived yet. The surplus is dropped rather than held,
            # because a shot that runs on in silence is what makes a
            # presentation drag.
            want = spoken + LEAD + TAIL + TAG if spoken else SILENT
            if item.seconds:
                want = min(want, item.seconds)
            length = max(0.8, min(total - floor, want))
            begin = max(floor, total - length)
            seconds = max(length, spoken + LEAD + TAIL)
            caption = _render_caption(item.captions, BUILD / f"{name}-caption.png")
            clip = BUILD / f"{name}-{item.beat}.mp4"
            _encode_shot(source, begin, length, item, caption, seconds, clip)
            label = f"{item.beat:<16}"

        actual = _duration(clip)
        at = elapsed + LEAD
        for line in lines:
            placements.append((at, line))
            at += _duration(line) + GAP
        # Cards carry no caption band; only shots do.
        captions = () if isinstance(item, Card) else item.captions
        if captions:
            subtitles.append((elapsed, elapsed + actual, " \u00b7 ".join(captions)))
        pieces.append(clip)
        assembled.append((label.strip(), elapsed, actual,
                          [a.stem for a in lines], captions))
        print(f"  {label:<16} +{actual:5.1f}s"
              f"{'' if lines else '   (no line)'}")
        elapsed += actual

    # ---- picture ---------------------------------------------------------
    listing = BUILD / "concat.txt"
    listing.write_text("".join(f"file '{p.name}'\n" for p in pieces))
    picture = BUILD / "picture.mp4"
    subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-y", "-loglevel", "error",
         "-f", "concat", "-safe", "0", "-i", str(listing),
         "-c:v", "libx264", "-preset", "slow", "-crf", CRF,
         "-profile:v", "high", "-pix_fmt", "yuv420p", "-r", str(FPS),
         "-x264-params", "ref=4:bframes=3", "-an", str(picture)],
        check=True, cwd=BUILD,
    )
    runtime = _duration(picture)

    # ---- sound -----------------------------------------------------------
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if placements:
        track = BUILD / "narration.wav"
        _build_narration(placements, runtime, track)
        normalised = BUILD / "narration-normalised.wav"
        _normalise_audio(track, normalised)
        subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
            [_ffmpeg(), "-y", "-loglevel", "error",
             "-i", str(picture), "-i", str(normalised),
             "-map", "0:v", "-map", "1:a", "-c:v", "copy",
             *_aac_args(), "-ar", str(SAMPLE_RATE),
             "-shortest", "-movflags", "+faststart", str(args.out)],
            check=True,
        )
    else:
        subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
            [_ffmpeg(), "-y", "-loglevel", "error", "-i", str(picture),
             "-f", "lavfi", "-t", f"{runtime:.3f}",
             "-i", f"anullsrc=channel_layout=stereo:sample_rate={SAMPLE_RATE}",
             "-map", "0:v", "-map", "1:a", "-c:v", "copy",
             *_aac_args(), "-ar", str(SAMPLE_RATE),
             "-shortest", "-movflags", "+faststart", str(args.out)],
            check=True,
        )

    _write_srt(subtitles, ROOT / "submission" / "demo" / "captions.srt")
    loudness = _loudness(args.out)
    _write_final_script(
        assembled, args.out, loudness,
        ROOT / "submission" / "demo" / "final-script.md",
    )

    glare = _bright_frames(args.out)
    if glare:
        print("WARNING: blank or near-white frames at "
              + ", ".join(f"{t:.2f}s" for t in glare[:8]), file=sys.stderr)

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    seconds = _duration(args.out)
    audio_seconds = _stream_duration(args.out, "a")
    print()
    if missing:
        print(f"WARNING: no narration for {', '.join(missing)}", file=sys.stderr)
    print(f"video   : {args.out.relative_to(ROOT)}")
    print(f"duration: {int(seconds // 60)}:{int(seconds % 60):02d}  ({seconds:.2f}s)"
          f"  {WIDTH}x{HEIGHT} @ {FPS}fps H.264 High CRF {CRF}")
    print(f"audio   : {audio_seconds:.2f}s  (drift {abs(seconds - audio_seconds):.2f}s)")
    print(f"size    : {args.out.stat().st_size:,} bytes")
    print(f"sha256  : {digest}")
    if not 165 <= seconds <= 195:
        print(f"\nNOTE: {seconds:.0f}s is outside the 2:45-3:15 target.",
              file=sys.stderr)
    return 0


def _stream_duration(path: Path, kind: str) -> float:
    result = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffprobe(), "-v", "error", "-select_streams", kind,
         "-show_entries", "stream=duration", "-of", "default=nw=1:nk=1", str(path)],
        check=False, capture_output=True, text=True,
    )
    try:
        return float(result.stdout.strip().splitlines()[0])
    except (ValueError, IndexError):
        return 0.0


def _timecode(seconds: float) -> str:
    whole = int(seconds)
    ms = int(round((seconds - whole) * 1000))
    return f"{whole // 3600:02d}:{whole // 60 % 60:02d}:{whole % 60:02d},{ms:03d}"


def _write_srt(entries: list[tuple[float, float, str]], path: Path) -> None:
    lines = [
        f"{index}\n{_timecode(start)} --> {_timecode(end)}\n"
        f"{chr(10).join(textwrap.wrap(text, width=70)[:2])}\n"
        for index, (start, end, text) in enumerate(entries, start=1)
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    raise SystemExit(main())
