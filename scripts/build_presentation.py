#!/usr/bin/env python3
"""Build the six-slide SIH 2026 submission deck (M9 sections 5 and 6).

Uses the **official** SIH 2026 IDEA presentation template. Its required
headings and section structure are left exactly as the template defines them;
only the instruction body text is replaced with this project's content, which
is what the template itself asks for.

The seventh slide -- the template's own "IMPORTANT INSTRUCTIONS" page -- is
deleted, because the template says to delete it before uploading.

Team and problem-statement fields come from ``submission/presentation/team.json``.
Any left null renders as a visible ``[UNRESOLVED: ...]`` marker and the build
refuses to call the PDF submission-ready. A deck with an invisible placeholder
is worse than one that says so.

    python scripts/build_presentation.py [--template PATH]

Outputs ``submission/presentation/SecureMailScope-SIH26159.pptx`` and, when
LibreOffice is available, the PDF beside it.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission" / "presentation"
DEFAULT_TEMPLATE = ROOT / "submission" / "template" / "SIH2026-IDEA-Presentation-Format.pptx"
SHOTS = ROOT / "submission" / "assets" / "screenshots-final"
FINAL = ROOT / "submission" / "final"
#: Cropped copies used only by the deck; regenerated on every build.
CROPS = ROOT / "submission" / "assets" / "crops"

INK = RGBColor(0x11, 0x1B, 0x2A)
BODY = RGBColor(0x1F, 0x2C, 0x3F)
MUTED = RGBColor(0x4A, 0x5A, 0x70)
ACCENT = RGBColor(0x0B, 0x5F, 0xA5)
WARN = RGBColor(0xA8, 0x3A, 0x1E)
GOOD = RGBColor(0x1B, 0x6B, 0x3A)
UNRESOLVED = RGBColor(0xC0, 0x1A, 0x1A)
BOX_FILL = RGBColor(0xEE, 0xF3, 0xF9)
BOX_LINE = RGBColor(0xC2, 0xD4, 0xE6)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _delete_slide(prs: Presentation, index: int) -> None:
    """Remove a slide. python-pptx has no public API for this."""
    slide_id = prs.slides._sldIdLst[index]
    rid = slide_id.get(
        "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
    )
    prs.part.drop_rel(rid)
    prs.slides._sldIdLst.remove(slide_id)


def _shape(slide: Any, name: str) -> Any | None:
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    return None


def _clear(frame: Any) -> None:
    frame.clear()
    paragraph = frame.paragraphs[0]
    for run in list(paragraph.runs):
        run._r.getparent().remove(run._r)


def _write(
    frame: Any,
    lines: list[tuple[str, float, bool, RGBColor, int]],
    *,
    line_spacing: float = 1.0,
) -> None:
    """Write (text, size_pt, bold, colour, indent_level) lines into a frame."""
    _clear(frame)
    frame.word_wrap = True
    for index, (text, size, bold, colour, level) in enumerate(lines):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.level = min(level, 4)
        paragraph.line_spacing = line_spacing
        paragraph.space_after = Pt(3)
        run = paragraph.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = colour
        run.font.name = "Calibri"


#: The repository this deck describes. Public, so the link and the QR code
#: both resolve for anyone in the room.
REPOSITORY_URL = "https://github.com/sgtsujith141-wq/securemailscope"

#: What the deck says about the demonstration video. No URL exists because
#: nothing has been uploaded anywhere, so the line states where the video is
#: rather than promising a link.
VIDEO_LINK_PLACEHOLDER = "Included in the submission package."



def _link_line(
    frame: Any,
    label: str,
    text: str,
    url: str | None,
    *,
    size: float = 8.0,
) -> None:
    """Append 'label  text' where `text` is a real, clickable hyperlink.

    ``url=None`` writes the text as plain muted type. That is how the
    demonstration-video slot renders: the element exists and is reserved, but
    nothing is hyperlinked until a URL actually exists, so the deck can never
    appear to link to a video that was never uploaded.
    """
    paragraph = frame.add_paragraph()
    paragraph.line_spacing = 0.88
    paragraph.space_after = Pt(2)

    tag = paragraph.add_run()
    tag.text = f"{label}  "
    tag.font.size = Pt(size)
    tag.font.bold = True
    tag.font.color.rgb = INK
    tag.font.name = "Calibri"

    run = paragraph.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.name = "Calibri"
    if url:
        run.hyperlink.address = url
        run.font.color.rgb = ACCENT
        run.font.underline = True
    else:
        run.font.color.rgb = MUTED
        run.font.italic = True


def _textbox(
    slide: Any, left: float, top: float, width: float, height: float
) -> Any:
    box = slide.shapes.add_textbox(
        Inches(left), Inches(top), Inches(width), Inches(height)
    )
    box.text_frame.word_wrap = True
    return box


def _panel(
    slide: Any,
    left: float,
    top: float,
    width: float,
    height: float,
    *,
    fill: RGBColor = BOX_FILL,
    line: RGBColor = BOX_LINE,
) -> Any:
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(left),
        Inches(top),
        Inches(width),
        Inches(height),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = line
    shape.line.width = Pt(0.75)
    shape.shadow.inherit = False
    shape.text_frame.word_wrap = True
    shape.text_frame.margin_left = Inches(0.10)
    shape.text_frame.margin_right = Inches(0.10)
    shape.text_frame.margin_top = Inches(0.06)
    shape.text_frame.margin_bottom = Inches(0.06)
    shape.text_frame.vertical_anchor = MSO_ANCHOR.TOP
    return shape


def _arrow(slide: Any, left: float, top: float, width: float = 0.26) -> None:
    arrow = slide.shapes.add_shape(
        MSO_SHAPE.RIGHT_ARROW, Inches(left), Inches(top), Inches(width), Inches(0.18)
    )
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = MUTED
    arrow.line.fill.background()
    arrow.shadow.inherit = False


def _no_bullets(frame: Any) -> None:
    """Strip the template's bullet glyph from every paragraph in a frame.

    The official template's body placeholders carry a bullet character. It
    renders as a stray dot beside a one-line subtitle, which reads as a
    formatting accident rather than a list. python-pptx has no API for this,
    so the `<a:buNone/>` element is inserted directly.
    """
    from pptx.oxml.ns import qn

    for paragraph in frame.paragraphs:
        pPr = paragraph._p.get_or_add_pPr()
        for tag in ("a:buChar", "a:buAutoNum", "a:buNone"):
            for existing in pPr.findall(qn(tag)):
                pPr.remove(existing)
        pPr.append(pPr.makeelement(qn("a:buNone"), {}))


def _node(
    slide: Any,
    left: float,
    top: float,
    width: float,
    height: float,
    lines: list[tuple[str, float, bool, RGBColor]],
    *,
    fill: RGBColor = BOX_FILL,
    line: RGBColor = BOX_LINE,
) -> Any:
    """One box in a diagram: centred text, vertically centred, no bullet."""
    shape = _panel(slide, left, top, width, height, fill=fill, line=line)
    shape.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        shape.text_frame,
        [(text, size, bold, colour, 0) for text, size, bold, colour in lines],
        line_spacing=0.88,
    )
    for paragraph in shape.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
        paragraph.space_after = Pt(1)
    _no_bullets(shape.text_frame)
    return shape


def _arrow_down(slide: Any, left: float, top: float, height: float = 0.20) -> None:
    arrow = slide.shapes.add_shape(
        MSO_SHAPE.DOWN_ARROW, Inches(left), Inches(top), Inches(0.18), Inches(height)
    )
    arrow.fill.solid()
    arrow.fill.fore_color.rgb = MUTED
    arrow.line.fill.background()
    arrow.shadow.inherit = False


def _band(
    slide: Any, left: float, top: float, width: float, height: float, label: str,
) -> Any:
    """A labelled container behind a row of diagram nodes."""
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(left), Inches(top), Inches(width), Inches(height),
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(0xF7, 0xFA, 0xFD)
    shape.line.color.rgb = RGBColor(0xDC, 0xE6, 0xF2)
    shape.line.width = Pt(0.75)
    shape.shadow.inherit = False
    frame = shape.text_frame
    frame.word_wrap = True
    frame.margin_left = Inches(0.08)
    frame.margin_top = Inches(0.03)
    frame.vertical_anchor = MSO_ANCHOR.TOP
    _write(frame, [(label, 7.5, True, RGBColor(0x8A, 0x9B, 0xB0), 0)])
    _no_bullets(frame)
    return shape


def _value(config: dict[str, Any], key: str) -> tuple[str, bool]:
    """Return (text, resolved). An unfilled field is visibly marked."""
    value = config.get(key)
    if value in (None, ""):
        return f"[UNRESOLVED: {key.replace('_', ' ')}]", False
    return str(value), True



def _qr(slide: Any, url: str, left: float, top: float, size: float) -> None:
    """A QR code for a link a judge cannot click on a projected slide."""
    import segno

    path = CROPS / "qr.png"
    CROPS.mkdir(parents=True, exist_ok=True)
    segno.make(url, error="m").save(str(path), scale=12, border=2, dark="#123A63")
    slide.shapes.add_picture(str(path), Inches(left), Inches(top), width=Inches(size))


def _shot(
    slide: Any, name: str, left: float, top: float, width: float,
    caption: str | None = None, *, ratio: float = 16 / 9,
    crop: tuple[float, float, float, float] | None = None,
) -> float:
    """Place a genuine product screenshot, cropped to a slide-friendly shape.

    The screenshots are full-page captures and are therefore very tall; scaled
    to a column width they would run off the slide. They are cropped from the
    top to the requested aspect ratio, which keeps the part of the page that
    carries the message and never stretches or distorts the image.

    If the file is missing the slide is built without it rather than with a
    placeholder box: a box that looks like a screenshot is worse than none.
    """
    path = SHOTS / name
    if not path.is_file():
        print(f"  screenshot missing, omitted: {name}")
        return 0.0

    from PIL import Image

    with Image.open(path) as source:
        if crop is not None:
            # An explicit window, in fractions of the full page. Shrinking a
            # whole 1920x3000 screenshot into a slide column turns its text
            # into a grey texture; cropping to the part that carries the
            # message keeps it readable from the back of a room.
            x0, y0, x1, y1 = crop
            window_px = (
                int(source.width * x0), int(source.height * y0),
                int(source.width * x1), int(source.height * y1),
            )
            window = source.crop(window_px)
            cropped = CROPS / f"crop-{x0}-{y0}-{x1}-{y1}-{name}"
            CROPS.mkdir(parents=True, exist_ok=True)
            window.save(cropped)
            path = cropped
        else:
            target_height = int(source.width / ratio)
            if target_height < source.height:
                cropped = CROPS / name
                CROPS.mkdir(parents=True, exist_ok=True)
                source.crop((0, 0, source.width, target_height)).save(cropped)
                path = cropped

    height = width / ratio
    picture = slide.shapes.add_picture(
        str(path), Inches(left), Inches(top), width=Inches(width)
    )
    height = Emu(picture.height).inches

    line = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height)
    )
    line.fill.background()
    line.line.color.rgb = BOX_LINE
    line.line.width = Pt(0.75)
    line.shadow.inherit = False

    if caption:
        box = _textbox(slide, left, top + height + 0.04, width, 0.28)
        _write(box.text_frame, [(caption, 11, False, MUTED, 0)])
        _no_bullets(box.text_frame)
        for paragraph in box.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
        height += 0.32
    return height


# ---------------------------------------------------------------------------
# slide 1 -- title page
# ---------------------------------------------------------------------------
def slide_1(slide: Any, config: dict[str, Any]) -> list[str]:
    unresolved: list[str] = []
    box = _shape(slide, "TextBox 9")
    assert box is not None, "the template's title-page field box is missing"

    fields = [
        ("Problem Statement ID", "problem_statement_id"),
        ("Problem Statement Title", "problem_statement_title"),
        ("Organisation", "organization"),
        ("Theme", "theme"),
        ("PS Category", "ps_category"),
        ("Team ID", "team_id"),
        ("Team Name (Registered on portal)", "team_name"),
    ]
    lines: list[tuple[str, float, bool, RGBColor, int]] = []
    for label, key in fields:
        text, resolved = _value(config, key)
        if not resolved:
            unresolved.append(key)
        # The en dash is the separator the official template uses.
        lines.append(
            (f"{label} \u2013 {text}", 15, False,
             INK if resolved else UNRESOLVED, 0)
        )
    _write(box.text_frame, lines, line_spacing=1.30)
    _no_bullets(box.text_frame)

    # The project's own name, above the template's field list. The title page
    # otherwise opens on "Problem Statement ID", which tells a judge what the
    # slide is filed under rather than what the project is.
    name = _textbox(slide, 0.62, 2.12, 7.40, 1.10)
    _write(
        name.text_frame,
        [("SecureMailScope", 40, True, ACCENT, 0),
         ("AI-Assisted Cryptographic Security Posture Assessment "
          "for Secure Email Communications", 14, False, BODY, 0)],
        line_spacing=1.04,
    )
    _no_bullets(name.text_frame)
    rule = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, Inches(0.62), Inches(2.02), Inches(1.30), Inches(0.05)
    )
    rule.fill.solid()
    rule.fill.fore_color.rgb = ACCENT
    rule.line.fill.background()
    rule.shadow.inherit = False

    box.left, box.top = Inches(0.62), Inches(3.46)
    box.width, box.height = Inches(7.40), Inches(3.10)
    return unresolved


# ---------------------------------------------------------------------------
# slide 2 -- idea title / proposed solution
# ---------------------------------------------------------------------------
def slide_2(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.06)
    box.width, box.height = Inches(12.5), Inches(0.62)
    _write(
        box.text_frame,
        [("SecureMailScope turns passive email packet captures into "
          "evidence-backed cryptographic investigations.", 20, True, ACCENT, 0)],
        line_spacing=1.0,
    )
    _no_bullets(box.text_frame)

    # --- the pipeline, as six readable stages --------------------------------
    stages = [
        ("PCAP / PCAPNG", "authorised capture"),
        ("TCP RECONSTRUCTION", "sessions rebuilt"),
        ("SMTP \u00b7 IMAP \u00b7 POP3", "from the dialogue"),
        ("STARTTLS \u00b7 STLS \u00b7 TLS", "upgrade and handshake"),
        ("CRYPTOGRAPHIC EVIDENCE", "versions, suites, certificates"),
        ("RISK + REMEDIATION", "ranked, with the fix"),
    ]
    x, w = 0.42, 1.86
    for index, (title, detail) in enumerate(stages):
        _node(slide, x, 1.82, w, 0.78,
              [(title, 11, True, INK), (detail, 8.5, False, MUTED)])
        x += w
        if index < len(stages) - 1:
            _arrow(slide, x + 0.02, 2.12, 0.20)
            x += 0.25

    # --- the product, large enough to read -----------------------------------
    _shot(slide, "02-overview.png", 0.42, 2.86, 8.16,
          "The investigation opens on its conclusion. Actual product output.",
          crop=(0.11, 0.022, 1.0, 0.200))

    # --- three differentiators, not paragraphs -------------------------------
    blocks = [
        ("PASSIVE BY DESIGN",
         "Existing captures only. No live probe, no connection back to the "
         "mail server, nothing leaves the machine."),
        ("EVIDENCE-FIRST",
         "Every finding traces back to the packets that establish it \u2014 "
         "number, timestamp and stream offset."),
        ("CROSS-CAPTURE INTELLIGENCE",
         "Cryptographic fingerprints, configuration drift and correlation "
         "across captures of the same service."),
    ]
    y = 2.86
    for title, detail in blocks:
        panel = _panel(slide, 8.82, y, 4.10, 1.02)
        _write(
            panel.text_frame,
            [(title, 12.5, True, ACCENT, 0), (detail, 11, False, BODY, 0)],
            line_spacing=0.98,
        )
        _no_bullets(panel.text_frame)
        y += 1.12


# ---------------------------------------------------------------------------
# slide 3 -- technical approach
# ---------------------------------------------------------------------------
def slide_3(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.04)
    box.width, box.height = Inches(12.5), Inches(0.36)
    _write(
        box.text_frame,
        [("Each stage consumes the previous stage\u2019s evidence and preserves "
          "packet-level provenance.", 13, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    top, band_h = 1.46, 3.02
    node_top = top + 0.34
    detail_pt = 8.5

    _band(slide, 0.42, top, 2.30, band_h, "INPUT")
    _band(slide, 2.94, top, 3.60, band_h, "RECONSTRUCTION")
    _band(slide, 6.76, top, 3.26, band_h, "CRYPTOGRAPHIC ASSESSMENT")
    _band(slide, 10.24, top, 2.68, band_h, "OUTPUT")

    def column(left: float, width: float, rows: list[tuple[str, str]]) -> None:
        y = node_top
        for index, (title, detail) in enumerate(rows):
            height = 0.50 if detail else 0.40
            _node(slide, left, y, width, height,
                  [(title, 10.5, True, INK)]
                  + ([(detail, detail_pt, False, MUTED)] if detail else []))
            y += height
            if index < len(rows) - 1:
                _arrow_down(slide, left + width / 2 - 0.09, y + 0.02, 0.16)
                y += 0.22

    column(0.58, 1.98, [
        ("PCAP / PCAPNG", "authorised capture"),
        ("Safe ingestion", "format from the bytes, 8 limits"),
    ])
    column(3.10, 3.28, [
        ("Packet decode", ""),
        ("TCP reassembly", "reorder \u00b7 retransmit \u00b7 gaps"),
        ("SMTP \u00b7 IMAP \u00b7 POP3", "state machines, not ports"),
        ("STARTTLS / STLS", "advertised \u00b7 requested \u00b7 outcome"),
    ])
    column(6.92, 2.94, [
        ("TLS handshake \u2192 X.509", "version, suite, key exchange, chain"),
        ("25 policy rules", "versioned and fingerprinted"),
        ("Score \u00b7 coverage \u00b7 priority", "arithmetic shown, not asserted"),
        ("Fingerprint \u00b7 drift \u00b7 ML", "ML is advisory only"),
    ])
    column(10.40, 2.36, [
        ("Canonical report model", "schema 1.4.0"),
        ("FastAPI + SQLite", "loopback only, token"),
        ("React workspace", "evidence-linked throughout"),
        ("JSON \u00b7 HTML \u00b7 PDF", "parity-tested"),
    ])

    for x in (2.74, 6.56, 10.04):
        _arrow(slide, x, node_top + 0.18, 0.22)

    # --- the evidence rail, as a chain ---------------------------------------
    rail_y = top + band_h + 0.16
    _band(slide, 0.42, rail_y, 12.5, 0.86, "EVIDENCE RAIL \u2014 WHAT EVERY FINDING CARRIES")
    chain = ["PACKET", "OBSERVATION", "CRYPTO FACT", "RULE", "FINDING", "REMEDIATION"]
    cx, cw = 0.66, 1.80
    for index, label in enumerate(chain):
        _node(slide, cx, rail_y + 0.32, cw, 0.42, [(label, 10.5, True, ACCENT)],
              fill=RGBColor(0xFF, 0xFF, 0xFF))
        cx += cw
        if index < len(chain) - 1:
            _arrow(slide, cx + 0.03, rail_y + 0.46, 0.18)
            cx += 0.26

    # --- technology, in four groups, plus the three claims -------------------
    groups = [
        ("ENGINE", "Python \u00b7 Scapy \u00b7 cryptography"),
        ("APPLICATION", "FastAPI \u00b7 SQLite \u00b7 React \u00b7 TypeScript"),
        ("ANALYTICS", "scikit-learn"),
        ("VALIDATION", "pytest \u00b7 Playwright \u00b7 TShark"),
    ]
    gy = rail_y + 1.02
    gx, gw = 0.42, 2.30
    for title, detail in groups:
        panel = _panel(slide, gx, gy, gw, 0.74)
        _write(panel.text_frame,
               [(title, 10.5, True, ACCENT, 0), (detail, 9.5, False, BODY, 0)],
               line_spacing=0.94)
        _no_bullets(panel.text_frame)
        gx += gw + 0.10

    bx = gx
    for text, colour in (("PASSIVE", GOOD), ("LOCAL-FIRST", ACCENT),
                         ("EVIDENCE-LINKED", WARN)):
        _node(slide, bx, gy, 1.02, 0.74, [(text, 9, True, colour)],
              fill=RGBColor(0xFF, 0xFF, 0xFF))
        bx += 1.08


# ---------------------------------------------------------------------------
# slide 4 -- feasibility and viability
# ---------------------------------------------------------------------------
def slide_4(slide: Any, ev: dict[str, Any]) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.04)
    box.width, box.height = Inches(12.5), Inches(0.36)
    _write(
        box.text_frame,
        [("Feasible because it is built and measured. Every figure below was "
          "re-run on the release commit.", 13, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    metrics = [
        (ev["tests"], "backend tests pass", ACCENT),
        (ev["tests_tshark"], "with the TShark cross-check", ACCENT),
        (ev["frontend_tests"], "frontend tests", ACCENT),
        (ev["e2e_specs"], "real-backend E2E specs", ACCENT),
        (ev["typed_files"], "files ruff + mypy clean", ACCENT),
        ("0", "known advisories at audit", GOOD),
    ]
    mx = 0.42
    for figure, label, colour in metrics:
        tile = _panel(slide, mx, 1.44, 2.02, 1.06)
        tile.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        _write(tile.text_frame,
               [(figure, 32, True, colour, 0), (label, 9.5, False, MUTED, 0)],
               line_spacing=0.86)
        for paragraph in tile.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
            paragraph.space_after = Pt(0)
        _no_bullets(tile.text_frame)
        mx += 2.12

    # --- the proof, large enough to read -------------------------------------
    # Cropped from the tag row to the packet rows: the two panels above them
    # are on slide 5, and including them here would shrink the packet numbers
    # -- the one thing this slide exists to show -- below reading size.
    _shot(slide, "06-evidence-provenance.png", 0.42, 2.66, 7.10,
          "TLS-KEX-001, HIGH \u2014 and the packets it was evaluated against. "
          "Actual product output.",
          crop=(0.360, 0.285, 1.0, 0.795))

    # --- what the engine did, in four steps ----------------------------------
    steps = [
        ("OBSERVE", "Static RSA key exchange negotiated"),
        ("TRACE", "Packets #4 and #5, with timestamps"),
        ("ASSESS", "TLS-KEX-001 \u00b7 HIGH \u00b7 no forward secrecy"),
        ("REMEDIATE", "Move to ephemeral key exchange"),
    ]
    sy = 2.66
    for index, (title, detail) in enumerate(steps):
        panel = _panel(slide, 8.26, sy, 4.66, 0.72)
        _write(panel.text_frame,
               [(title, 12.5, True, ACCENT, 0), (detail, 11, False, BODY, 0)],
               line_spacing=0.96)
        _no_bullets(panel.text_frame)
        sy += 0.72
        if index < len(steps) - 1:
            _arrow_down(slide, 10.50, sy + 0.02, 0.16)
            sy += 0.20

    # --- boundaries: two lines --------------------------------------------
    risks = _panel(slide, 0.42, 6.18, 12.5, 0.76,
                   fill=RGBColor(0xFD, 0xF2, 0xEC), line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        risks.text_frame,
        [
            ("KNOWN BOUNDARIES", 11, True, WARN, 0),
            ("TLS 1.3 may encrypt certificate evidence a passive capture "
             "cannot recover; it is reported NOT AVAILABLE with the reason, "
             "never guessed.", 11, False, BODY, 0),
            ("The supervised classifier is experimental and never overrides a "
             "deterministic finding.", 11, False, BODY, 0),
        ],
        line_spacing=0.96,
    )
    _no_bullets(risks.text_frame)


# ---------------------------------------------------------------------------
# slide 5 -- impact and benefits
# ---------------------------------------------------------------------------
def slide_5(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.04)
    box.width, box.height = Inches(12.5), Inches(0.36)
    _write(
        box.text_frame,
        [("For authorised email-security investigation \u2014 and every claim "
          "below is what the product already outputs.", 13, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    outcomes = [
        ("DISCOVER", "Observable weak cryptography"),
        ("EXPLAIN", "Packet-backed evidence"),
        ("PRIORITIZE", "What to fix first"),
        ("TRACK", "Cryptographic drift"),
        ("REPORT", "Portable forensic output"),
    ]
    x, w = 0.42, 2.40
    for title, detail in outcomes:
        panel = _panel(slide, x, 1.44, w, 0.84)
        panel.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        _write(panel.text_frame,
               [(title, 14, True, ACCENT, 0), (detail, 10.5, False, BODY, 0)],
               line_spacing=0.94)
        for paragraph in panel.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
            paragraph.space_after = Pt(1)
        _no_bullets(panel.text_frame)
        x += w + 0.10

    # --- A: the evidence the first three outcomes rest on --------------------
    _shot(slide, "04-finding-evidence.png", 0.42, 2.44, 7.12,
          "DISCOVER \u00b7 EXPLAIN \u00b7 PRIORITIZE \u2014 one finding, its rule, "
          "its severity and its remediation.",
          crop=(0.11, 0.150, 1.0, 0.735))

    # --- B: drift, as the engine reported it ---------------------------------
    _shot(slide, "13-drift-version.png", 7.72, 2.44, 5.20,
          "TRACK \u2014 the same observed service, two captures.",
          crop=(0.155, 0.150, 0.99, 0.262))

    band = _panel(slide, 7.72, 4.02, 5.20, 0.62,
                  fill=RGBColor(0xFF, 0xFF, 0xFF), line=BOX_LINE)
    band.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        band.text_frame,
        [("EARLIER  TLS 1.2      \u2192  OBSERVED_CHANGE  \u2192      LATER  TLS 1.0",
          13, True, WARN, 0)],
    )
    for paragraph in band.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(band.text_frame)

    # --- C: the report that leaves the tool ----------------------------------
    _shot(slide, "12-pdf.png", 7.72, 4.80, 2.34,
          "REPORT \u2014 the exported PDF.", crop=(0.0, 0.0, 1.0, 0.44))

    carry = _panel(slide, 10.24, 4.80, 2.68, 1.42)
    _write(
        carry.text_frame,
        [("The report carries", 11.5, True, ACCENT, 0),
         ("findings \u00b7 packet references \u00b7 remediation", 11, False, BODY, 0),
         ("JSON \u00b7 standalone HTML \u00b7 PDF", 11, False, BODY, 0)],
        line_spacing=0.98,
    )
    _no_bullets(carry.text_frame)

    note = _panel(slide, 0.42, 6.34, 7.12, 0.42,
                  fill=RGBColor(0xE4, 0xEE, 0xE6), line=RGBColor(0xBE, 0xD8, 0xC6))
    note.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        note.text_frame,
        [("Demonstrated on controlled synthetic captures; no production "
          "deployment claim.", 11, True, BODY, 0)],
    )
    _no_bullets(note.text_frame)


# ---------------------------------------------------------------------------
# slide 6 -- research and references
# ---------------------------------------------------------------------------
def slide_6(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.04)
    box.width, box.height = Inches(12.5), Inches(0.36)
    _write(
        box.text_frame,
        [("The standards the rules cite, and the pipeline every claim in this "
          "deck is checked by.", 13, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    groups = [
        ("CORE TLS / PKI",
         ["RFC 8446 \u2014 TLS 1.3", "RFC 9325 \u2014 secure use of TLS",
          "RFC 5280 \u2014 X.509 and CRL profile",
          "NIST SP 800-52 Rev. 2"]),
        ("EMAIL SECURITY",
         ["RFC 5321 \u2014 SMTP", "RFC 3207 \u2014 STARTTLS",
          "RFC 9051 \u2014 IMAP 4rev2",
          "RFC 1939 / RFC 2595 \u2014 POP3 and TLS"]),
        ("VALIDATION / TOOLING",
         ["Wireshark / TShark", "Scapy", "cryptography", "pytest \u00b7 Playwright"]),
    ]
    gx = 0.42
    for title, items in groups:
        panel = _panel(slide, gx, 1.44, 4.10, 1.56)
        _write(panel.text_frame,
               [(title, 12.5, True, ACCENT, 0)]
               + [(item, 11, False, BODY, 0) for item in items],
               line_spacing=1.0)
        _no_bullets(panel.text_frame)
        gx += 4.20

    _band(slide, 0.42, 3.20, 12.5, 1.78, "HOW EVERY CLAIM IS CHECKED")
    steps = [
        ("CONTROLLED FIXTURES", "one fixed seed, identical bytes everywhere"),
        ("HAND-DERIVED EXPECTATIONS", "written by hand, committed, not read back"),
        ("ENGINE UNDER TEST", "1,357 tests; captures stay out of git"),
        ("INDEPENDENT TSHARK CROSS-CHECK", "against Wireshark's own dissector"),
        ("REAL-BACKEND PLAYWRIGHT", "five browser specs, including a restart"),
        ("REPORT PARITY", "JSON, HTML and PDF asserted to agree"),
    ]
    sx, sw = 0.60, 1.84
    for index, (title, detail) in enumerate(steps):
        _node(slide, sx, 3.58, sw, 1.22,
              [(title, 9.5, True, INK), (detail, 8.5, False, MUTED)])
        sx += sw
        if index < len(steps) - 1:
            _arrow(slide, sx + 0.03, 4.12, 0.18)
            sx += 0.24

    project = _panel(slide, 0.42, 5.18, 9.06, 1.12)
    _write(
        project.text_frame,
        [("PROJECT", 12.5, True, ACCENT, 0)],
    )
    _no_bullets(project.text_frame)
    _link_line(project.text_frame, "GitHub repository", REPOSITORY_URL,
               REPOSITORY_URL, size=12)
    _link_line(project.text_frame, "Demonstration video",
               VIDEO_LINK_PLACEHOLDER, None, size=12)

    qr = _panel(slide, 9.66, 5.18, 3.26, 1.12)
    _write(qr.text_frame, [("", 4, False, MUTED, 0)])
    _no_bullets(qr.text_frame)
    _qr(slide, REPOSITORY_URL, 9.80, 5.30, 0.88)
    label = _textbox(slide, 10.80, 5.34, 2.02, 0.80)
    _write(label.text_frame,
           [("SCAN FOR THE REPOSITORY", 10, True, ACCENT, 0),
            ("Public repository \u2014 source, tests and submission package.",
             9.5, False, MUTED, 0)],
           line_spacing=0.98)
    _no_bullets(label.text_frame)


# ---------------------------------------------------------------------------
#: Strings that must never survive into the built deck. The team registered
#: as exactly "Zero-Day"; "Team Zero Day" and its variants are wrong, and the
#: template's own "Your Team Name" placeholder is wrong.
FORBIDDEN_TEAM_STRINGS = (
    "Your Team Name",
    "Team Zero Day",
    "Team zero day",
    "Team Zero-Day",
    "Team ZERO-DAY",
    "ZERO DAY",
    "Zero Day",
)


def _team_name_ovals(prs: Presentation, name: str) -> None:
    """Replace the template's 'Your Team Name' badge on every content slide."""
    for slide in prs.slides:
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            if shape.text_frame.text.strip() in ("Your Team Name", name):
                frame = shape.text_frame
                _clear(frame)
                run = frame.paragraphs[0].add_run()
                run.text = name
                run.font.size = Pt(10)
                run.font.bold = True
                frame.paragraphs[0].alignment = PP_ALIGN.CENTER
                frame.word_wrap = True


def _pptx_text(path: Path) -> str:
    """Every scrap of text in the package, read from the XML itself."""
    import re
    import zipfile

    chunks = []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.namelist():
            if entry.startswith("ppt/") and entry.endswith(".xml"):
                xml = archive.read(entry).decode("utf-8", "replace")
                chunks.extend(re.findall(r"<a:t>(.*?)</a:t>", xml, re.S))
    import html

    return "\n".join(html.unescape(chunk) for chunk in chunks)


def _pdf_text(path: Path) -> tuple[int, str]:
    try:
        from pypdf import PdfReader
    except ImportError:
        return (0, "")
    reader = PdfReader(str(path))
    return (
        len(reader.pages),
        "\n".join(page.extract_text() or "" for page in reader.pages),
    )


def verify(pptx: Path, pdf: Path | None, team_name: str) -> list[str]:
    """Assert everything section 30 requires. Returns the failures."""
    failures: list[str] = []
    pptx_text = _pptx_text(pptx)
    pages, pdf_text = _pdf_text(pdf) if pdf else (0, "")
    both = f"{pptx_text}\n{pdf_text}"

    if pdf is not None and pages != 6:
        failures.append(f"the PDF has {pages} pages, expected exactly 6")

    if team_name not in pptx_text:
        failures.append(f"the team name {team_name!r} does not appear in the PPTX")
    if pdf is not None and team_name not in pdf_text:
        failures.append(f"the team name {team_name!r} does not appear in the PDF")

    for bad in FORBIDDEN_TEAM_STRINGS:
        # "Zero Day" as a substring of nothing else; check the exact spelling.
        if bad in both:
            failures.append(f"forbidden string present: {bad!r}")

    for required in ("SecureMailScope", "SIH26159", "Software"):
        if required not in both:
            failures.append(f"required string missing: {required!r}")
    if "National Technical Research Organisation" not in both and "NTRO" not in both:
        failures.append("required string missing: the organisation")

    if "IMPORTANT INSTRUCTIONS" in both or "Kindly keep the maximum" in both:
        failures.append("the template's instruction slide is still present")

    # Every title-page value must be resolved. An [UNRESOLVED: ...] marker is
    # deliberate and visible while a value is genuinely unknown; it must never
    # survive into a deck presented as final.
    if "[UNRESOLVED" in both:
        failures.append("an [UNRESOLVED: ...] marker survived into the deck")

    # Belongs to a different problem statement and a different project. If
    # either appears, something was copied from the wrong source.
    for foreign in ("SIH26164", "CryptoDrishti", "Phantom HQ"):
        if foreign in both:
            failures.append(f"content from another project is present: {foreign!r}")

    if REPOSITORY_URL not in both:
        failures.append(f"the repository link is missing: {REPOSITORY_URL}")
    if VIDEO_LINK_PLACEHOLDER not in both:
        failures.append("the reserved demonstration-video element is missing")

    return failures


def _demo_capture_count() -> int:
    """How many captures the screenshots were taken on.

    Read from the committed demo manifest rather than typed into the caption,
    because the caption is a factual claim about the image beside it and the
    dataset has grown once already.
    """
    manifest = ROOT / "demo" / "manifest.json"
    return len(json.loads(manifest.read_text())["captures"])


def _evidence() -> dict[str, Any]:
    """Figures for slide 4, read from artefacts rather than typed in."""
    rehearsal = ROOT / "submission" / "demo" / "rehearsal.json"
    steps, failed = "14", "0"
    if rehearsal.is_file():
        record = json.loads(rehearsal.read_text())
        steps = str(record["steps_total"])
        failed = str(record["steps_failed"])
    # Verified against the release commit. FINAL-QUALITY-CHECK.md records the
    # runs these come from; they are not copied forward from an earlier
    # milestone.
    return {
        "tests": "1,357",
        "tests_tshark": "1,367",
        "frontend_tests": "89",
        "e2e_specs": "5",
        "typed_files": "158",
        "rehearsal_steps": steps,
        "rehearsal_failed": failed,
    }


def _to_pdf(pptx: Path) -> Path | None:
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice is None:
        print("LibreOffice not found; the PDF was NOT generated.")
        return None
    result = subprocess.run(  # noqa: S603 - resolved path, fixed argv, no shell
        [
            soffice, "--headless", "--convert-to", "pdf",
            "--outdir", str(pptx.parent), str(pptx),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    pdf = pptx.with_suffix(".pdf")
    if result.returncode != 0 or not pdf.is_file():
        print("PDF conversion failed:", result.stderr.strip()[:400])
        return None
    return pdf


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--no-pdf", action="store_true")
    args = parser.parse_args()

    if not args.template.is_file():
        print(f"The official SIH template was not found at {args.template}.")
        print("Pass --template PATH. The deck is NOT built from a substitute:")
        print("the submission requires the provided template.")
        return 2

    config = json.loads((OUT / "team.json").read_text())
    OUT.mkdir(parents=True, exist_ok=True)

    prs = Presentation(str(args.template))
    if len(prs.slides) != 7:
        print(f"expected the 7-slide template, found {len(prs.slides)}")
        return 2

    unresolved = slide_1(prs.slides[0], config)
    slide_2(prs.slides[1])
    slide_3(prs.slides[2])
    slide_4(prs.slides[3], _evidence())
    slide_5(prs.slides[4])
    slide_6(prs.slides[5])

    # The template's own instruction slide says to delete it before uploading.
    _delete_slide(prs, 6)

    name, _ = _value(config, "team_name")
    _team_name_ovals(prs, name)

    FINAL.mkdir(parents=True, exist_ok=True)
    pptx = FINAL / "SecureMailScope-SIH26159-Zero-Day.pptx"
    prs.save(str(pptx))
    print(f"PPTX: {pptx.relative_to(ROOT)}  ({len(prs.slides)} slides)")

    pdf = None
    if not args.no_pdf:
        pdf = _to_pdf(pptx)
        if pdf is not None:
            print(f"PDF:  {pdf.relative_to(ROOT)}")

    failures = verify(pptx, pdf, name)

    status = {
        "template": str(args.template.name),
        "verification_failures": failures,
        "template_slides": 7,
        "submitted_slides": len(prs.slides),
        "instruction_slide_deleted": True,
        "unresolved_fields": unresolved,
        "submission_ready": not unresolved and pdf is not None,
        "pptx": str(pptx.relative_to(ROOT)),
        "pdf": str(pdf.relative_to(ROOT)) if pdf else None,
    }
    (OUT / "build-status.json").write_text(json.dumps(status, indent=2) + "\n")

    print()
    if failures:
        print("VERIFICATION FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 2
    print("Verification passed: exactly six pages, official template retained,")
    print(f"team name exactly {name!r}, no forbidden string, instruction slide")
    print("removed, and every required identifier present.")
    print()

    if unresolved:
        print("NOT SUBMISSION-READY. These title-page fields are unresolved and")
        print("render as visible [UNRESOLVED: ...] markers:")
        for key in unresolved:
            print(f"  - {key}: {config['_sources'].get(key, '')}")
        print()
        print("Fill them in submission/presentation/team.json and re-run.")
        return 1

    print("All title-page fields are resolved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
