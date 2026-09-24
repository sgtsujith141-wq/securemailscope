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
CRF = "16"

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

    `beat` and `until` name marks in the recording's own beat log, so a shot
    can never drift from what was recorded. `narration` names a file in
    local-evidence/narration; `captions` are short labels, not a transcript.
    """

    beat: str
    until: str | None = None
    narration: str | None = None
    captions: tuple[str, ...] = ()
    seconds: float | None = None          # cap the window; None = to `until`
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


TITLE_CARD = Card(
    kind="title", seconds=4.4,
    heading="SecureMailScope",
    sub="Cryptographic security posture, from the packets you already have.",
    note="Smart India Hackathon 2026  ·  SIH26159  ·  NTRO  ·  Zero-Day",
)

END_CARD = Card(
    kind="end", seconds=7.5,
    heading="SecureMailScope",
    sub="Passive  ·  Local  ·  Evidence-backed",
    footer=(
        "Smart India Hackathon 2026  ·  Problem statement SIH26159",
        "National Technical Research Organisation",
        "Theme: Blockchain & Cybersecurity  ·  Category: Software",
        "Team ID 146876  ·  Zero-Day",
        "github.com/sgtsujith141-wq/securemailscope",
    ),
)

#: The cut, in order. The first shot is the hook: the product already showing
#: a real weak finding, before any title.
CUT: list[Shot | Card] = [
    Shot("finding-detail", until="evidence", narration="01-hook",
         captions=("TLS 1.0 negotiated", "Static RSA · no forward secrecy", "HIGH"),
         zoom=1.05),
    TITLE_CARD,
    Shot("firstrun", until="upload", narration="02-input",
         captions=("Passive PCAP analysis", "Nothing leaves this machine")),
    Shot("upload", until="analyse", narration=None,
         captions=("Nine synthetic captures",)),
    Shot("analyse", until="overview", narration="03-pipeline",
         captions=("Sessions rebuilt", "SMTP · IMAP · POP3 · STARTTLS · TLS")),
    Shot("overview", until="modules", narration="04-analysis",
         captions=("59/100 · WEAK", "7 high-priority findings"), zoom=1.04),
    Shot("modules", until="finding", narration=None,
         captions=("TLS posture across every session",)),
    Shot("finding", until="finding-detail", narration=None,
         captions=("Findings, ranked by priority",)),
    Shot("evidence", until="verify", narration="05-evidence",
         captions=("Packets #4 and #5", "Evidence linked"), zoom=1.06),
    Shot("verify", until="tls13", narration="06-verify",
         captions=("Open the same packets in Wireshark",), zoom=1.04),
    Shot("tls13", until="drift", narration="07-tls13",
         captions=("TLS 1.3 certificate unavailable", "Reported, not guessed")),
    Shot("drift-setup", until="drift", narration=None,
         captions=("Two captures of the same service",)),
    Shot("drift", until="report", narration="08-drift",
         captions=("Observed cryptographic drift", "TLS 1.2 → TLS 1.0"), zoom=1.05),
    Shot("report", until="montage", narration="09-report",
         captions=("JSON · HTML · PDF",)),
    Shot("__pdf__", narration=None, captions=("The exported forensic report",),
         seconds=4.2),
    Shot("__pdf2__", narration=None,
         captions=("Findings · packet references · remediation",), seconds=4.6),
    Shot("montage", until="end", narration="10-close", captions=()),
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


def _frame_page(page_png: Path, out: Path) -> Path:
    """Centre a portrait page on a 16:9 canvas in the product's ink."""
    from PIL import Image

    canvas = Image.new("RGB", (WIDTH, HEIGHT), INK)
    with Image.open(page_png) as page:
        scale = (HEIGHT - 56) / page.height
        size = (max(1, int(page.width * scale)), HEIGHT - 56)
        canvas.paste(
            page.convert("RGB").resize(size, Image.Resampling.LANCZOS),
            ((WIDTH - size[0]) // 2, 28),
        )
    canvas.save(out)
    return out


def _encode(
    video_inputs: list[str], chain: list[str], video_label: str,
    audio: Path | None, seconds: float, out: Path, *, lead: float = 0.0,
) -> None:
    """Encode one segment: video filter chain, optional narration under it."""
    argv = [_ffmpeg(), "-y", "-loglevel", "error", *video_inputs]
    chain = list(chain)
    if audio is not None and audio.exists():
        argv += ["-i", str(audio)]
        index = len([a for a in video_inputs if a == "-i"])
        delay = int(lead * 1000)
        chain.append(f"[{index}:a]adelay={delay}|{delay},apad[a]")
        audio_map = "[a]"
    else:
        argv += ["-f", "lavfi", "-t", f"{seconds:.3f}",
                 "-i", "anullsrc=channel_layout=stereo:sample_rate=48000"]
        audio_map = f"{len([a for a in video_inputs if a == '-i'])}:a"
    argv += ["-filter_complex", ";".join(chain),
             "-map", video_label, "-map", audio_map,
             "-c:v", "libx264", "-preset", "slow", "-crf", CRF,
             "-pix_fmt", "yuv420p", "-r", str(FPS),
             "-c:a", "aac", "-b:a", "192k",
             "-t", f"{seconds:.3f}", str(out)]
    subprocess.run(argv, check=True)  # noqa: S603


def _encode_card(card: Card, png: Path, audio: Path | None, out: Path) -> None:
    seconds = card.seconds
    if audio is not None and audio.exists():
        seconds = max(seconds, _duration(audio) + 1.0)
    fade = max(0.0, seconds - 0.4)
    _encode(
        ["-loop", "1", "-framerate", str(FPS), "-t", f"{seconds:.3f}", "-i", str(png)],
        [f"[0:v]fps={FPS},format=yuv420p,fade=t=in:st=0:d=0.4,"
         f"fade=t=out:st={fade:.3f}:d=0.4[v]"],
        "[v]", audio, seconds, out, lead=0.35,
    )


def _encode_still(png: Path, caption: Path | None, audio: Path | None,
                  out: Path, *, seconds: float) -> None:
    length = seconds
    if audio is not None and audio.exists():
        length = max(length, _duration(audio) + 0.8)
    inputs = ["-loop", "1", "-framerate", str(FPS), "-t", f"{length:.3f}", "-i", str(png)]
    chain = [f"[0:v]fps={FPS},scale={WIDTH}:{HEIGHT}[base]"]
    label = "[base]"
    if caption is not None:
        inputs += ["-loop", "1", "-framerate", str(FPS), "-t", f"{length:.3f}",
                   "-i", str(caption)]
        chain.append("[base][1:v]overlay=x=0:y=H-h[capped]")
        label = "[capped]"
    chain.append(f"{label}format=yuv420p[v]")
    _encode(inputs, chain, "[v]", audio, length, out, lead=0.3)


def _encode_shot(source: Path, start: float, length: float, shot: Shot,
                 caption: Path | None, audio: Path | None, out: Path) -> None:
    """Cut one shot, push in gently, composite its caption, lay the line under."""
    seconds = length
    if audio is not None and audio.exists():
        seconds = max(seconds, _duration(audio) + shot.lead + 0.7)
    hold = max(0.0, seconds - length)

    inputs = ["-ss", f"{start:.3f}", "-t", f"{length:.3f}", "-i", str(source)]
    steps = [f"fps={FPS}", f"scale={WIDTH}:{HEIGHT}"]
    if shot.zoom > 1.0:
        # A slow push-in, a few per cent over the shot. Enough to keep a
        # static page feeling alive; small enough that nothing is cropped out.
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
    _encode(inputs, chain, "[v]", audio, seconds, out, lead=shot.lead)


def _normalise(source: Path, out: Path) -> None:
    """Bring the finished cut to -16 LUFS with a -1 dBTP ceiling.

    Two passes, because one-pass `loudnorm` only estimates: it lands a couple
    of LU away, which is audible as a video that is quieter than everything
    else a judge has just watched. The measurement from the first pass is fed
    back into the second, and the video stream is copied so normalising costs
    no picture quality.
    """
    probe = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-hide_banner", "-i", str(source),
         "-af", "loudnorm=I=-16:TP=-1.0:LRA=11:print_format=json",
         "-f", "null", "-"],
        check=False, capture_output=True, text=True,
    )
    # ffmpeg prints the measurement as a JSON object at the very end of
    # stderr, preceded by its own log lines. Taking everything from the last
    # opening brace caught a nested one; matching the final balanced block
    # from the last line that is exactly "{" does not.
    measured: dict[str, str] = {}
    lines = probe.stderr.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        if lines[index].strip() == "{":
            with contextlib.suppress(json.JSONDecodeError):
                measured = json.loads("\n".join(lines[index:]))
            break

    if all(k in measured for k in
           ("input_i", "input_tp", "input_lra", "input_thresh", "target_offset")):
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
    # A limiter after normalisation, so a loud syllable cannot clip.
    chain += ",alimiter=limit=0.891"

    subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-y", "-loglevel", "error", "-i", str(source),
         "-af", chain, "-c:v", "copy", "-c:a", "aac", "-b:a", "192k",
         "-movflags", "+faststart", str(out)],
        check=True,
    )


def _find_footage() -> Path:
    candidates = sorted(
        (ROOT / "frontend" / "test-results").rglob("*.webm"),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    if not candidates:
        raise SystemExit(
            "no recording found. Run:  cd frontend && "
            "SMS_SCREENSHOTS=1 npx playwright test demo-capture"
        )
    return candidates[0]


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT_DEFAULT)
    parser.add_argument("--silent", action="store_true",
                        help="Build the same cut with captions and no narration.")
    args = parser.parse_args()

    beats_file = FOOTAGE / "beats.json"
    if not beats_file.is_file():
        raise SystemExit(f"no beat log at {beats_file}. Record the footage first.")
    record = json.loads(beats_file.read_text())
    marks = {b["id"]: b["at_ms"] / 1000.0 for b in record["beats"]}
    order = [b["id"] for b in record["beats"]]

    source = _find_footage()
    total = _duration(source)
    print(f"footage : {source.relative_to(ROOT)}  ({total:.1f}s)")

    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)

    pdf = ROOT / record.get("exported_pdf", "local-evidence/exports/securemailscope-report.pdf")
    pdf_pages = _pdf_pages(pdf, 2) if pdf.is_file() else []

    pieces: list[Path] = []
    subtitles: list[tuple[float, float, str]] = []
    elapsed = 0.0
    missing_narration: list[str] = []

    for index, item in enumerate(CUT):
        name = f"{index:02d}"
        if isinstance(item, Card):
            png = BUILD / f"{name}-card.png"
            _render_card(item, png)
            clip = BUILD / f"{name}-card.mp4"
            audio = None
            if not args.silent and item.narration:
                candidate = NARRATION / f"{item.narration}.mp3"
                audio = candidate if candidate.is_file() else None
            _encode_card(item, png, audio, clip)
            pieces.append(clip)
            elapsed += _duration(clip)
            print(f"  {'card':<16} {item.heading}")
            continue

        audio = None
        if not args.silent and item.narration:
            candidate = NARRATION / f"{item.narration}.mp3"
            if candidate.is_file():
                audio = candidate
            else:
                missing_narration.append(item.narration)
        caption = _render_caption(item.captions, BUILD / f"{name}-caption.png")
        clip = BUILD / f"{name}-{item.beat.strip('_')}.mp4"

        if item.beat.startswith("__pdf"):
            which = 0 if item.beat == "__pdf__" else 1
            if which >= len(pdf_pages):
                print(f"  {'pdf':<16} page {which + 1} unavailable, omitted")
                continue
            _encode_still(pdf_pages[which], caption, audio, clip,
                          seconds=item.seconds or 4.0)
        else:
            if item.beat not in marks:
                print(f"  {'skip':<16} {item.beat}: not in the beat log")
                continue
            start = marks[item.beat]
            if item.until and item.until in marks:
                end = marks[item.until]
            else:
                nxt = order.index(item.beat) + 1
                end = marks[order[nxt]] if nxt < len(order) else min(total, start + 5)
            length = max(0.8, min(end, total) - start)
            if item.seconds:
                length = min(length, item.seconds)
            _encode_shot(source, start, length, item, caption, audio, clip)

        seconds = _duration(clip)
        if item.captions:
            subtitles.append((elapsed, elapsed + seconds, " · ".join(item.captions)))
        elapsed += seconds
        pieces.append(clip)
        print(f"  {item.beat:<16} +{seconds:5.1f}s"
              f"{'  (no narration)' if item.narration and audio is None else ''}")

    listing = BUILD / "concat.txt"
    listing.write_text("".join(f"file '{p.name}'\n" for p in pieces))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    joined = BUILD / "joined.mp4"
    subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [_ffmpeg(), "-y", "-loglevel", "error",
         "-f", "concat", "-safe", "0", "-i", str(listing),
         "-c:v", "libx264", "-preset", "slow", "-crf", CRF,
         "-profile:v", "high", "-pix_fmt", "yuv420p", "-r", str(FPS),
         "-x264-params", "ref=4:bframes=3",
         "-c:a", "aac", "-b:a", "192k", str(joined)],
        check=True, cwd=BUILD,
    )
    _normalise(joined, args.out)

    _write_srt(subtitles, ROOT / "submission" / "demo" / "captions.srt")

    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    seconds = _duration(args.out)
    print()
    if missing_narration:
        print(f"WARNING: no narration for {', '.join(missing_narration)}",
              file=sys.stderr)
    print(f"video   : {args.out.relative_to(ROOT)}")
    print(f"duration: {int(seconds // 60)}:{int(seconds % 60):02d}  ({seconds:.1f}s)"
          f"  {WIDTH}x{HEIGHT} @ {FPS}fps H.264 CRF {CRF}")
    print(f"size    : {args.out.stat().st_size:,} bytes")
    print(f"sha256  : {digest}")
    if not 165 <= seconds <= 195:
        print(f"\nNOTE: {seconds:.0f}s is outside the 2:45-3:15 target.",
              file=sys.stderr)
    return 0


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
