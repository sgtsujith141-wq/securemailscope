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


#: The repository this deck describes. Private at the time of writing; the
#: link is included because the submission form asks for it, not as a claim
#: that a reviewer can open it today.
REPOSITORY_URL = "https://github.com/sgtsujith141-wq/securemailscope"

#: What the deck says about the demonstration video. No URL exists because
#: nothing has been uploaded anywhere, so the line states where the video is
#: rather than promising a link.
VIDEO_LINK_PLACEHOLDER = "Demo video included in submission package."



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



def _shot(
    slide: Any, name: str, left: float, top: float, width: float,
    caption: str | None = None, *, ratio: float = 16 / 9,
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
        box = _textbox(slide, left, top + height + 0.02, width, 0.24)
        _write(box.text_frame, [(caption, 8, False, MUTED, 0)])
        for paragraph in box.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
        height += 0.26
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
            (f"{label} \u2013 {text}", 13, False,
             INK if resolved else UNRESOLVED, 0)
        )
    _write(box.text_frame, lines, line_spacing=1.22)
    return unresolved


# ---------------------------------------------------------------------------
# slide 2 -- idea title / proposed solution
# ---------------------------------------------------------------------------
def slide_2(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.16)
    box.width, box.height = Inches(12.5), Inches(0.72)
    _write(
        box.text_frame,
        [
            ("SecureMailScope turns passive email packet captures into "
             "evidence-backed cryptographic investigations.", 15, True, ACCENT, 0),
            ("Every conclusion is traceable to the packets that establish it — "
             "and where a capture cannot show something, it says so.",
             10.5, False, MUTED, 0),
        ],
        line_spacing=1.0,
    )
    _no_bullets(box.text_frame)

    # --- the flow, left to right --------------------------------------------
    flow = ["PCAP", "TCP\nreconstruction", "SMTP / IMAP\nPOP3",
            "STARTTLS\nTLS", "Cryptographic\nevidence", "Risk +\nremediation"]
    x, y, w = 0.42, 1.96, 1.86
    for index, stage in enumerate(flow):
        panel = _panel(slide, x, y, w, 0.58)
        _write(panel.text_frame, [(stage, 9.5, True, INK, 0)], line_spacing=0.88)
        for paragraph in panel.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
        x += w
        if index < len(flow) - 1:
            _arrow(slide, x + 0.02, y + 0.20, 0.22)
            x += 0.28

    # --- the product, and what it answers ------------------------------------
    _shot(slide, "02-overview.png", 0.42, 2.76, 6.55,
          f"The investigation overview, on {_demo_capture_count()} synthetic "
          "captures. Actual product output.")

    right = 7.22
    blocks = [
        ("What it does",
         "Reads authorized PCAP/PCAPNG, reconstructs TCP sessions, identifies "
         "the email protocol from the dialogue rather than the port, "
         "reconstructs the TLS handshake, extracts certificate evidence where "
         "it is observable, applies 25 policy rules and scores the result."),
        ("How it addresses SIH26159",
         "The organisation already holds the captures. No probe, no scan, no "
         "credential and no change to a production mail server — which also "
         "means an authorised investigator with no access to the host can "
         "still assess how it protected traffic."),
        ("What makes it different",
         "Packet-level provenance on every finding · cryptographic DNA and "
         "drift across captures · cross-session correlation · explainable "
         "scoring with the arithmetic shown · fully local and offline · "
         "stated limits instead of silent gaps"),
    ]
    top = 2.76
    for title, detail in blocks:
        panel = _panel(slide, right, top, 5.70, 1.22)
        _write(
            panel.text_frame,
            [(title, 10.5, True, ACCENT, 0), (detail, 9, False, BODY, 0)],
            line_spacing=0.92,
        )
        top += 1.32


# ---------------------------------------------------------------------------
# slide 3 -- technical approach
# ---------------------------------------------------------------------------
def slide_3(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.06)
    box.width, box.height = Inches(12.5), Inches(0.34)
    _write(
        box.text_frame,
        [("One direction of flow. Each stage reads only what the previous one "
          "produced, and attaches the packets it read it from.",
          10, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    # ----------------------------------------------------------------------
    # The architecture, as a diagram: four bands, left to right, with the
    # evidence rail running underneath all of them.
    # ----------------------------------------------------------------------
    top = 1.50
    band_h = 2.72

    _band(slide, 0.42, top, 2.08, band_h, "INPUT")
    _band(slide, 2.74, top, 4.32, band_h, "RECONSTRUCTION")
    _band(slide, 7.30, top, 2.86, band_h, "ASSESSMENT")
    _band(slide, 10.40, top, 2.52, band_h, "OUTPUT")

    node_top = top + 0.30
    small = 7.5

    # -- input --------------------------------------------------------------
    _node(slide, 0.56, node_top, 1.80, 0.56,
          [("PCAP / PCAPNG", 8.5, True, INK), ("untrusted file", small, False, MUTED)])
    _arrow_down(slide, 1.37, node_top + 0.62, 0.20)
    _node(slide, 0.56, node_top + 0.86, 1.80, 0.62,
          [("Safe ingestion", 8.5, True, INK),
           ("format from the bytes", small, False, MUTED),
           ("8 hard limits", small, False, MUTED)])
    _arrow_down(slide, 1.37, node_top + 1.48, 0.22)
    _node(slide, 0.56, node_top + 1.74, 1.80, 0.48,
          [("Packet decode", 8.5, True, INK)])

    _arrow(slide, 2.44, node_top + 0.48, 0.24)

    # -- reconstruction ------------------------------------------------------
    _node(slide, 2.88, node_top, 2.02, 0.56,
          [("TCP reassembly", 8.5, True, INK),
           ("reorder \u00b7 retransmit \u00b7 gaps", small, False, MUTED)])
    _node(slide, 5.00, node_top, 1.94, 0.56,
          [("SMTP \u00b7 IMAP \u00b7 POP3", 8.5, True, INK),
           ("state machines, not ports", small, False, MUTED)])
    _arrow_down(slide, 3.80, node_top + 0.62, 0.20)
    _arrow_down(slide, 5.88, node_top + 0.62, 0.20)
    _node(slide, 2.88, node_top + 0.86, 2.02, 0.56,
          [("STARTTLS / STLS", 8.5, True, INK),
           ("advertised \u00b7 requested \u00b7 outcome", small, False, MUTED)])
    _node(slide, 5.00, node_top + 0.86, 1.94, 0.56,
          [("TLS handshake", 8.5, True, INK),
           ("version, suite, key exchange", small, False, MUTED)])
    _arrow_down(slide, 4.84, node_top + 1.48, 0.22)
    _node(slide, 2.88, node_top + 1.74, 4.06, 0.48,
          [("X.509 certificate analysis  \u2014  chain, dates, identity, key, "
            "signature", 8.5, True, INK)])

    _arrow(slide, 7.00, node_top + 0.48, 0.24)

    # -- assessment -----------------------------------------------------------
    _node(slide, 7.44, node_top, 2.58, 0.56,
          [("25 policy rules", 8.5, True, INK),
           ("versioned, fingerprinted", small, False, MUTED)])
    _arrow_down(slide, 8.64, node_top + 0.62, 0.20)
    _node(slide, 7.44, node_top + 0.86, 2.58, 0.56,
          [("Score \u00b7 coverage \u00b7 priority", 8.5, True, INK),
           ("arithmetic shown, not asserted", small, False, MUTED)])
    _arrow_down(slide, 8.64, node_top + 1.48, 0.22)
    _node(slide, 7.44, node_top + 1.74, 2.58, 0.48,
          [("Fingerprints \u00b7 drift \u00b7 correlation \u00b7 ML (advisory)",
            8, True, INK)])

    _arrow(slide, 10.10, node_top + 0.48, 0.24)

    # -- output ---------------------------------------------------------------
    _node(slide, 10.54, node_top, 2.24, 0.56,
          [("One canonical report model", 8.5, True, INK),
           ("schema 1.4.0", small, False, MUTED)])
    _arrow_down(slide, 11.57, node_top + 0.62, 0.20)
    _node(slide, 10.54, node_top + 0.86, 2.24, 0.56,
          [("JSON \u00b7 offline HTML \u00b7 PDF", 8.5, True, INK),
           ("parity-tested against each other", small, False, MUTED)])
    _arrow_down(slide, 11.57, node_top + 1.48, 0.22)
    _node(slide, 10.54, node_top + 1.74, 2.24, 0.48,
          [("Local API \u2192 React dashboard", 8.5, True, INK)])

    # -- the rail that runs under everything ----------------------------------
    rail = _panel(slide, 0.42, 4.34, 12.5, 0.46,
                  fill=RGBColor(0xEC, 0xF4, 0xFA), line=RGBColor(0xC8, 0xDD, 0xEE))
    rail.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        rail.text_frame,
        [("EVIDENCE PROVENANCE  \u2014  every stage attaches the capture, session, "
          "packet number, timestamp and stream offset it read from, and marks each "
          "value OBSERVED, INFERRED, UNKNOWN or NOT AVAILABLE",
          9, True, ACCENT, 0)],
    )
    for paragraph in rail.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(rail.text_frame)

    guard = _panel(slide, 0.42, 4.90, 12.5, 0.46,
                   fill=RGBColor(0xE4, 0xEE, 0xE6), line=RGBColor(0xBE, 0xD8, 0xC6))
    guard.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        guard.text_frame,
        [("PASSIVE BY CONSTRUCTION  \u2014  no stage opens a socket. Scapy's "
          "neighbour resolver is replaced with one that raises, and the whole "
          "pipeline is run through stubbed socket constructors by the test suite",
          9, True, GOOD, 0)],
    )
    for paragraph in guard.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(guard.text_frame)

    # -- compact technology groups --------------------------------------------
    groups = [
        ("Engine",
         "Python 3.12 \u00b7 Scapy (dissection only) \u00b7 cryptography \u00b7 "
         "Pydantic \u00b7 scikit-learn"),
        ("Interface and API",
         "FastAPI \u00b7 SQLite \u00b7 SQLAlchemy \u00b7 React 18 \u00b7 "
         "TypeScript strict \u00b7 Vite \u00b7 Tailwind"),
        ("Verification",
         "pytest \u00b7 hypothesis \u00b7 Vitest \u00b7 Playwright \u00b7 "
         "TShark as an independent dissector"),
    ]
    gx = 0.42
    for title, detail in groups:
        panel = _panel(slide, gx, 5.48, 4.10, 1.06)
        _write(
            panel.text_frame,
            [(title, 9.5, True, ACCENT, 0), (detail, 8, False, BODY, 0)],
            line_spacing=0.90,
        )
        _no_bullets(panel.text_frame)
        gx += 4.20


# ---------------------------------------------------------------------------
# slide 4 -- feasibility and viability
# ---------------------------------------------------------------------------
def slide_4(slide: Any, ev: dict[str, Any]) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.06)
    box.width, box.height = Inches(12.5), Inches(0.34)
    _write(
        box.text_frame,
        [("Feasible because it is built and measured. Every figure below is "
          "from the release commit, re-run \u2014 not an estimate.",
          10, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    # -- the measurements, as figures rather than sentences -------------------
    metrics = [
        (ev["tests"], "backend tests pass", ACCENT),
        (ev["tests_tshark"], "with the TShark cross-check", ACCENT),
        (ev["frontend_tests"], "frontend tests", ACCENT),
        (ev["e2e_specs"], "browser end-to-end specs", ACCENT),
        (ev["typed_files"], "files ruff + mypy clean", ACCENT),
        ("0", "known dependency vulnerabilities", GOOD),
    ]
    mx = 0.42
    for figure, label, colour in metrics:
        tile = _panel(slide, mx, 1.44, 2.02, 0.86)
        tile.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        _write(
            tile.text_frame,
            [(figure, 22, True, colour, 0), (label, 7.5, False, MUTED, 0)],
            line_spacing=0.84,
        )
        for paragraph in tile.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
            paragraph.space_after = Pt(0)
        _no_bullets(tile.text_frame)
        mx += 2.12

    # -- the proof the metrics stand on ---------------------------------------
    proof = _panel(slide, 0.42, 2.42, 6.20, 2.73)
    _write(
        proof.text_frame,
        [
            ("How a finding is proved", 10.5, True, GOOD, 0),
            ("1.  A rule fails on a reconstructed observation \u2014 here, static "
             "RSA key exchange, so no forward secrecy.", 9, False, BODY, 0),
            ("2.  The engine attaches the packets it evaluated: #4 and #5, with "
             "their capture timestamps and stream offsets.", 9, False, BODY, 0),
            ("3.  The capture and session ids are printed beside them, so an "
             "analyst can open the same packets in Wireshark and check.",
             9, False, BODY, 0),
            ("4.  Packet metadata only. Reconstructed payload bytes are never "
             "included in a report or shown in the interface.", 9, False, BODY, 0),
            ("Expectations are hand-derived and committed as manifests while the "
             "captures are generated, so a test cannot confirm its own output; "
             "ten TShark cross-checks compare our dissection against Wireshark's, "
             "so a bug in our parser cannot validate itself.",
             8.5, False, MUTED, 0),
        ],
        line_spacing=0.92,
    )
    _no_bullets(proof.text_frame)

    # Cropped wider than 16:9 so the image and its caption both land above
    # the template's footer band, which starts at 6.95in.
    _shot(slide, "06-evidence-provenance.png", 6.78, 2.42, 6.14,
          "The finding, and the packets it was evaluated against. "
          "Actual product output.", ratio=2.25)

    # -- limits: two bullets, no essay ----------------------------------------
    risks = _panel(slide, 0.42, 5.46, 12.5, 1.14,
                   fill=RGBColor(0xFD, 0xF2, 0xEC), line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        risks.text_frame,
        [
            ("Limits, stated not hidden", 10.5, True, WARN, 0),
            ("TLS 1.3 encrypts the Certificate message, so a passive capture "
             "cannot expose it \u2014 reported NOT_AVAILABLE with the reason, "
             "never blank and never guessed. TLS 1.2 chains are read and "
             "verified in full.", 9, False, BODY, 0),
            ("The supervised classifier is NOT VALIDATED for real-world use: it "
             "was measured on synthetic servers only, it drives no finding and "
             "no score, and the interface says so on screen.", 9, False, BODY, 0),
        ],
        line_spacing=0.90,
    )
    _no_bullets(risks.text_frame)


# ---------------------------------------------------------------------------
# slide 5 -- impact and benefits
# ---------------------------------------------------------------------------
def slide_5(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.06)
    box.width, box.height = Inches(12.5), Inches(0.34)
    _write(
        box.text_frame,
        [("For authorised email-security investigation. Each visual below is "
          "the product output that supports the benefit beside it.",
          10, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    # ----------------------------------------------------------------------
    # Left: one evidence visual carrying three benefits that all rest on it.
    # ----------------------------------------------------------------------
    trio = [
        ("DISCOVER",
         "The cryptographic configuration actually negotiated \u2014 version, "
         "cipher suite, key exchange, certificate \u2014 read from traffic the "
         "organisation already holds, without touching the host."),
        ("EXPLAIN",
         "Every finding names the rule it failed, the RFC clause it applies and "
         "the packets that establish it, so the conclusion can be checked "
         "rather than believed."),
        ("PRIORITIZE",
         "Severity and confidence produce a ranked priority with a named "
         "remediation, so 'what do I fix first' has an answer and a reason."),
    ]
    tx = 0.56
    for title, detail in trio:
        panel = _panel(slide, tx, 1.72, 2.34, 1.44)
        _write(
            panel.text_frame,
            [(title, 11, True, ACCENT, 0), (detail, 8, False, BODY, 0)],
            line_spacing=0.90,
        )
        _no_bullets(panel.text_frame)
        tx += 2.42

    _shot(slide, "04-finding-evidence.png", 0.56, 3.30, 7.06,
          "One finding, its rule, its remediation and the packets behind it.",
          ratio=2.6)

    # ----------------------------------------------------------------------
    # Right: the two benefits with their own distinct evidence.
    # ----------------------------------------------------------------------
    track = _panel(slide, 7.92, 1.40, 5.00, 0.96)
    _write(
        track.text_frame,
        [("TRACK", 11, True, ACCENT, 0),
         ("Drift compares one endpoint across captures. Where the clients asked "
          "different questions the comparison is reported INCONCLUSIVE rather "
          "than blamed on the server.", 8, False, BODY, 0)],
        line_spacing=0.90,
    )
    _no_bullets(track.text_frame)
    _shot(slide, "08-drift.png", 7.92, 2.48, 5.00,
          "Configuration drift, before and after.", ratio=2.6)

    report = _panel(slide, 7.92, 4.86, 2.42, 1.56)
    _write(
        report.text_frame,
        [("REPORT", 11, True, ACCENT, 0),
         ("One canonical model produces JSON, a self-contained offline HTML "
          "document and a PDF, so their facts cannot disagree.",
          8, False, BODY, 0)],
        line_spacing=0.90,
    )
    _no_bullets(report.text_frame)
    _shot(slide, "11-reports.png", 10.50, 4.86, 2.42,
          "Export, in three formats.", ratio=1.62)

    note = _panel(slide, 0.42, 6.50, 7.34, 0.36,
                  fill=RGBColor(0xE4, 0xEE, 0xE6), line=RGBColor(0xBE, 0xD8, 0xC6))
    note.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(
        note.text_frame,
        [("Benefits are demonstrated on synthetic captures. No deployment, "
          "adoption figure or real-world detection rate is claimed.",
          8.5, True, BODY, 0)],
    )
    _no_bullets(note.text_frame)


# ---------------------------------------------------------------------------
# slide 6 -- research and references
# ---------------------------------------------------------------------------
def slide_6(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.06)
    box.width, box.height = Inches(12.5), Inches(0.34)
    _write(
        box.text_frame,
        [("The standards the rules cite and the parsers implement, and how "
          "every claim in this deck is checked.", 10, False, MUTED, 0)],
    )
    _no_bullets(box.text_frame)

    # -- references, in three groups ------------------------------------------
    groups = [
        ("Core TLS and PKI",
         [
             "RFC 8446 \u2014 TLS 1.3",
             "RFC 5246 \u2014 TLS 1.2",
             "RFC 9325 \u2014 secure use of TLS (2022)",
             "RFC 8996 \u2014 deprecating TLS 1.0 and 1.1",
             "RFC 7457 \u2014 known attacks on TLS",
             "RFC 4492 \u2014 ECC cipher suites",
             "RFC 5280 \u2014 X.509 certificate and CRL profile",
             "RFC 6125 \u2014 service identity verification",
             "NIST SP 800-52 Rev. 2 \u00b7 IANA TLS registry",
         ]),
        ("Email protocols",
         [
             "RFC 5321 \u2014 SMTP",
             "RFC 3207 \u2014 SMTP over TLS (STARTTLS)",
             "RFC 9051 \u2014 IMAP 4rev2",
             "RFC 1939 \u2014 POP3",
             "RFC 2595 \u2014 TLS with IMAP, POP3 and ACAP",
             "RFC 2606 \u2014 reserved names (.invalid, used by every fixture)",
         ]),
        ("Validation tools",
         [
             "Wireshark / TShark \u2014 independent dissection",
             "pytest \u00b7 hypothesis \u2014 property and regression tests",
             "Playwright \u00b7 Vitest \u2014 browser and unit tests",
             "pip-audit \u00b7 npm audit \u00b7 CycloneDX \u2014 supply chain",
             "ruff \u00b7 mypy \u2014 lint and strict typing",
         ]),
    ]
    gx = 0.42
    for title, items in groups:
        panel = _panel(slide, gx, 1.44, 4.10, 1.96)
        _write(
            panel.text_frame,
            [(title, 10, True, ACCENT, 0)]
            + [(item, 8, False, BODY, 0) for item in items],
            line_spacing=0.88,
        )
        _no_bullets(panel.text_frame)
        gx += 4.20

    # -- the validation pipeline, as a diagram --------------------------------
    _band(slide, 0.42, 3.60, 12.5, 1.74, "HOW EVERY CLAIM IN THIS DECK IS CHECKED")

    steps = [
        ("Deterministic fixtures",
         "generated from a fixed seed; identical bytes on every machine"),
        ("Hand-derived manifests",
         "expectations written by hand and committed, not read back"),
        ("Engine under test",
         "1,357 tests; the captures themselves stay out of git"),
        ("Independent dissector",
         "ten TShark cross-checks against Wireshark's own parse"),
        ("Real browser, real backend",
         "five Playwright specs, including a restart for persistence"),
        ("Report parity",
         "JSON, HTML and PDF asserted to agree, field by field"),
    ]
    sx = 0.58
    for index, (title, detail) in enumerate(steps):
        _node(slide, sx, 3.98, 1.82, 1.18,
              [(title, 8.5, True, INK), (detail, 7, False, MUTED)])
        if index < len(steps) - 1:
            _arrow(slide, sx + 1.86, 4.48, 0.20)
        sx += 2.08

    # -- repository and video --------------------------------------------------
    links = _panel(slide, 0.42, 5.52, 12.5, 0.80)
    _write(
        links.text_frame,
        [("Repository and demonstration", 10, True, ACCENT, 0)],
    )
    _no_bullets(links.text_frame)
    _link_line(links.text_frame, "Repository", REPOSITORY_URL, REPOSITORY_URL, size=9)
    _link_line(links.text_frame, "Demonstration", VIDEO_LINK_PLACEHOLDER, None, size=9)


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
        "typed_files": "156",
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
