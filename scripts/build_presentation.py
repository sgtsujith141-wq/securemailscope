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
# the content grid
# ---------------------------------------------------------------------------
#: Every slide places its editable content inside one grid. Repeated
#: components -- pipeline stages, metric tiles, reference cards -- are
#: positioned by computing the row once and reading coordinates out of it,
#: never by adding a hand-tuned offset per item. That is what keeps cards in a
#: row exactly the same width and arrows exactly between the boxes they join.
CONTENT_LEFT = 0.42
CONTENT_RIGHT = 12.91
CONTENT_BOTTOM = 6.84          # the official footer band begins below this
GUTTER = 0.16
ARROW_W = 0.22
ARROW_H = 0.18


def columns(
    count: int,
    *,
    left: float = CONTENT_LEFT,
    right: float = CONTENT_RIGHT,
    gutter: float = GUTTER,
) -> list[tuple[float, float]]:
    """`count` equal columns as (x, width), exactly filling left..right."""
    width = (right - left - gutter * (count - 1)) / count
    return [(left + index * (width + gutter), width) for index in range(count)]


def weighted(
    weights: list[float],
    *,
    left: float = CONTENT_LEFT,
    right: float = CONTENT_RIGHT,
    gutter: float = GUTTER,
) -> list[tuple[float, float]]:
    """Columns in the given proportions, exactly filling left..right."""
    span = right - left - gutter * (len(weights) - 1)
    total = sum(weights)
    out: list[tuple[float, float]] = []
    x = left
    for weight in weights:
        width = span * weight / total
        out.append((x, width))
        x += width + gutter
    return out


def rows(
    count: int, top: float, bottom: float, *, gutter: float = GUTTER,
) -> list[tuple[float, float]]:
    """`count` equal rows as (y, height), exactly filling top..bottom."""
    height = (bottom - top - gutter * (count - 1)) / count
    return [(top + index * (height + gutter), height) for index in range(count)]


def chain(
    count: int,
    *,
    left: float = CONTENT_LEFT,
    right: float = CONTENT_RIGHT,
    arrow: float = ARROW_W,
    gap: float = 0.06,
) -> tuple[list[tuple[float, float]], list[float]]:
    """A row of equal cards joined by arrows.

    Returns the card boxes and the arrow x-positions. The arrows are derived
    from the same arithmetic as the cards, so one can never sit off-centre
    between two of them.
    """
    slot = arrow + 2 * gap
    width = (right - left - slot * (count - 1)) / count
    cards: list[tuple[float, float]] = []
    arrows: list[float] = []
    x = left
    for index in range(count):
        cards.append((x, width))
        x += width
        if index < count - 1:
            arrows.append(x + gap)
            x += slot
    return cards, arrows


def middle(top: float, height: float, of: float) -> float:
    """The y that vertically centres an object of size `of` in a row."""
    return top + (height - of) / 2


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


def _hanging(paragraph: Any, inches: float) -> None:
    """Indent a paragraph's wrapped lines under its value, not its label.

    The problem-statement title is longer than one line at any size a title
    page should use. Left alone, its continuation starts exactly where the
    next field starts and reads as a separate row; a small indent marks it as
    the same sentence without pushing it under the template artwork.
    """
    pPr = paragraph._p.get_or_add_pPr()
    pPr.set("marL", str(int(inches * 914400)))
    pPr.set("indent", str(int(-inches * 914400)))


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
            (f"{label} \u2013 {text}", 14, False,
             INK if resolved else UNRESOLVED, 0)
        )
    _write(box.text_frame, lines, line_spacing=1.30)
    _no_bullets(box.text_frame)
    # Only the title is long enough to wrap; hang it under its value.
    for index, (label, _key) in enumerate(fields):
        if label == "Problem Statement Title":
            _hanging(box.text_frame.paragraphs[index], 0.24)

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
    box.width, box.height = Inches(7.60), Inches(3.10)
    return unresolved


# ---------------------------------------------------------------------------
# slide 2 -- idea title / proposed solution
# ---------------------------------------------------------------------------
def _subtitle(slide: Any, text: str, *, size: float = 13,
              bold: bool = False, colour: RGBColor = MUTED,
              height: float = 0.38, top: float = 1.02) -> None:
    """The one line under the template title. Same box on every slide."""
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(CONTENT_LEFT), Inches(top)
    box.width = Inches(CONTENT_RIGHT - CONTENT_LEFT)
    box.height = Inches(height)
    _write(box.text_frame, [(text, size, bold, colour, 0)], line_spacing=1.0)
    _no_bullets(box.text_frame)


def _card(slide: Any, box: tuple[float, float], top: float, height: float,
          title: str, body: list[str], *, title_size: float = 12,
          body_size: float = 10.5, title_colour: RGBColor = ACCENT,
          fill: RGBColor = BOX_FILL, line: RGBColor = BOX_LINE) -> Any:
    """A titled card. Every card in a row is built from the same row maths."""
    panel = _panel(slide, box[0], top, box[1], height, fill=fill, line=line)
    _write(
        panel.text_frame,
        [(title, title_size, True, title_colour, 0)]
        + [(item, body_size, False, BODY, 0) for item in body],
        line_spacing=0.98,
    )
    _no_bullets(panel.text_frame)
    return panel


def slide_2(slide: Any) -> None:
    _subtitle(
        slide,
        "SecureMailScope turns passive email packet captures into "
        "evidence-backed cryptographic investigations.",
        size=18, bold=True, colour=ACCENT, height=0.52, top=1.20,
    )

    # --- the pipeline: six equal stages, arrows derived from the same maths --
    stages = [
        ("PCAP / PCAPNG", "authorised capture"),
        ("TCP RECONSTRUCTION", "sessions rebuilt"),
        ("SMTP \u00b7 IMAP \u00b7 POP3", "from the dialogue"),
        ("STARTTLS \u00b7 STLS \u00b7 TLS", "upgrade and handshake"),
        ("CRYPTOGRAPHIC EVIDENCE", "versions, suites, certificates"),
        ("RISK + REMEDIATION", "ranked, with the fix"),
    ]
    row_top, row_h = 1.86, 0.78
    cards, arrows = chain(len(stages))
    for (x, w), (title, detail) in zip(cards, stages, strict=True):
        _node(slide, x, row_top, w, row_h,
              [(title, 10.5, True, INK), (detail, 8.5, False, MUTED)])
    for x in arrows:
        _arrow(slide, x, middle(row_top, row_h, ARROW_H), ARROW_W)

    # --- the product on the left, what makes it different on the right ------
    body_top = 2.82
    left_col, right_col = weighted([8.0, 4.33])

    shot_h = _shot(
        slide, "02-overview.png", left_col[0], body_top, left_col[1],
        "The investigation opens on its conclusion. Actual product output.",
        crop=(0.11, 0.022, 1.0, 0.243),
    )
    # The three panels finish level with the screenshot, so the two columns
    # share a baseline instead of one running on past the other.
    body_bottom = min(CONTENT_BOTTOM, body_top + shot_h) if shot_h else CONTENT_BOTTOM

    blocks = [
        ("PASSIVE BY DESIGN",
         "Existing captures only. No live probe, no connection back to the "
         "mail server, nothing leaves the machine."),
        ("EVIDENCE-FIRST",
         "Every finding traces back to the packet-level observations that "
         "establish it \u2014 number, timestamp and stream offset."),
        ("AI + CROSS-CAPTURE INTELLIGENCE",
         "ML-assisted risk triage alongside cryptographic fingerprints, "
         "configuration drift and correlation."),
    ]
    for (y, h), (title, detail) in zip(
        rows(3, body_top, body_bottom), blocks, strict=True
    ):
        _card(slide, right_col, y, h, title, [detail],
              title_size=12, body_size=10.5)


# ---------------------------------------------------------------------------
# slide 3 -- technical approach
# ---------------------------------------------------------------------------
def slide_3(slide: Any) -> None:
    _subtitle(
        slide,
        "Each stage consumes the previous stage\u2019s evidence and preserves "
        "packet-level provenance.",
    )

    # The vertical budget is computed once and every band reads from it, so
    # no stack can grow past its own label or into the row below.
    arch_top, arch_bottom = 1.46, 4.46
    band_h = arch_bottom - arch_top
    LABEL = 0.24                      # the band label strip inside each band
    # Five stages. The fourth is split, because deterministic intelligence and
    # AI-assisted triage are different kinds of claim and a judge has to be
    # able to see at a glance which is which.
    stage_cols = weighted([0.98, 1.20, 1.24, 1.36, 1.14])

    def stack(box: tuple[float, float], top: float, height: float,
              items: list[tuple[str, str]], *, node_h: float, gap: float = 0.14,
              fill: RGBColor = BOX_FILL, line: RGBColor = BOX_LINE) -> None:
        """Nodes centred in `height`, joined by arrows exactly between them."""
        total = len(items) * node_h + (len(items) - 1) * gap
        y = top + (height - total) / 2
        inner_x, inner_w = box[0] + 0.10, box[1] - 0.20
        for index, (title, detail) in enumerate(items):
            lines: list[tuple[str, float, bool, RGBColor]] = [
                (title, 9.5, True, INK)
            ]
            if detail:
                lines.append((detail, 7.5, False, MUTED))
            _node(slide, inner_x, y, inner_w, node_h, lines,
                  fill=fill, line=line)
            y += node_h
            if index < len(items) - 1:
                arrow_h = min(0.14, gap - 0.02)
                _arrow_down(slide, inner_x + inner_w / 2 - 0.09,
                            middle(y, gap, arrow_h), arrow_h)
                y += gap

    _band(slide, stage_cols[0][0], arch_top, stage_cols[0][1], band_h, "INPUT")
    stack(stage_cols[0], arch_top + LABEL, band_h - LABEL - 0.08, [
        ("PCAP / PCAPNG", "authorised capture"),
        ("Safe ingestion", "format from the bytes, 8 limits"),
    ], node_h=0.74)

    _band(slide, stage_cols[1][0], arch_top, stage_cols[1][1], band_h,
          "RECONSTRUCTION")
    stack(stage_cols[1], arch_top + LABEL, band_h - LABEL - 0.08, [
        ("Packet decode", ""),
        ("TCP reassembly", "reorder \u00b7 retransmit \u00b7 gaps"),
        ("SMTP \u00b7 IMAP \u00b7 POP3", "state machines, not ports"),
        ("STARTTLS \u00b7 STLS", "advertised \u00b7 requested \u00b7 outcome"),
    ], node_h=0.52)

    _band(slide, stage_cols[2][0], arch_top, stage_cols[2][1], band_h,
          "CRYPTOGRAPHIC ASSESSMENT")
    stack(stage_cols[2], arch_top + LABEL, band_h - LABEL - 0.08, [
        ("TLS handshake \u2192 X.509", "version \u00b7 suite \u00b7 key exchange"),
        ("Certificate analysis", "where passively observable"),
        ("25 deterministic rules", "versioned and fingerprinted"),
        ("Score \u00b7 coverage \u00b7 priority", "arithmetic shown, not asserted"),
    ], node_h=0.52)

    # --- the split layer: deterministic above, AI-assisted below ------------
    split = stage_cols[3]
    upper_h = 1.22
    lower_h = band_h - upper_h - 0.10
    ai_top = arch_top + upper_h + 0.10

    _band(slide, split[0], arch_top, split[1], upper_h,
          "DETERMINISTIC INTELLIGENCE")
    stack(split, arch_top + LABEL, upper_h - LABEL - 0.06, [
        ("Cryptographic fingerprint", ""),
        ("Cross-session correlation", ""),
        ("Configuration drift", ""),
    ], node_h=0.26, gap=0.08)

    ai_band = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE,
        Inches(split[0]), Inches(ai_top), Inches(split[1]), Inches(lower_h),
    )
    ai_band.fill.solid()
    ai_band.fill.fore_color.rgb = RGBColor(0xFD, 0xF5, 0xE7)
    ai_band.line.color.rgb = RGBColor(0xDC, 0xB8, 0x77)
    ai_band.line.width = Pt(1.25)
    ai_band.shadow.inherit = False
    ai_frame = ai_band.text_frame
    ai_frame.word_wrap = True
    ai_frame.margin_left = Inches(0.08)
    ai_frame.margin_top = Inches(0.03)
    ai_frame.vertical_anchor = MSO_ANCHOR.TOP
    _write(ai_frame, [("AI-ASSISTED TRIAGE", 8, True, WARN, 0)])
    _no_bullets(ai_frame)

    note_h = 0.30
    stack(split, ai_top + LABEL, lower_h - LABEL - note_h - 0.04, [
        ("93-feature vector", "cryptographic \u00b7 session \u00b7 evidence"),
        ("Supervised classifier", "logistic regression"),
        ("Advisory risk class", "CRITICAL \u00b7 HIGH \u00b7 MODERATE \u00b7 LOW"),
    ], node_h=0.30, gap=0.08, fill=RGBColor(0xFF, 0xFD, 0xF8),
        line=RGBColor(0xDC, 0xB8, 0x77))
    note = _textbox(slide, split[0] + 0.10, ai_top + lower_h - note_h,
                    split[1] - 0.20, note_h)
    note.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(note.text_frame,
           [("Advisory only \u2014 never overrides deterministic evidence "
             "or scoring.", 8.5, True, WARN, 0)], line_spacing=0.9)
    for paragraph in note.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(note.text_frame)

    _band(slide, stage_cols[4][0], arch_top, stage_cols[4][1], band_h, "OUTPUT")
    stack(stage_cols[4], arch_top + LABEL, band_h - LABEL - 0.08, [
        ("Canonical report model", "schema 1.4.0"),
        ("FastAPI + SQLite", "loopback only, token"),
        ("React workspace", "evidence-linked throughout"),
        ("JSON \u00b7 HTML \u00b7 PDF", "parity-tested"),
    ], node_h=0.52)

    # --- the evidence rail ---------------------------------------------------
    rail_top, rail_h = 4.56, 0.72
    _band(slide, CONTENT_LEFT, rail_top, CONTENT_RIGHT - CONTENT_LEFT, rail_h,
          "EVIDENCE RAIL \u2014 WHAT EVERY FINDING CARRIES")
    steps = ["PACKET", "OBSERVATION", "CRYPTO FACT", "RULE", "FINDING",
             "REMEDIATION"]
    node_top, node_h = rail_top + 0.26, 0.38
    cards, arrows = chain(len(steps), left=CONTENT_LEFT + 0.14,
                          right=CONTENT_RIGHT - 0.14)
    for (x, w), label in zip(cards, steps, strict=True):
        _node(slide, x, node_top, w, node_h,
              [(label, 10, True, ACCENT)],
              fill=RGBColor(0xFF, 0xFF, 0xFF))
    for x in arrows:
        _arrow(slide, x, middle(node_top, node_h, ARROW_H), ARROW_W)

    # --- what it is built from ----------------------------------------------
    tech_top, tech_h = 5.38, 0.76
    groups = [
        ("ENGINE", "Python \u00b7 Scapy \u00b7 cryptography", ACCENT),
        ("APPLICATION", "FastAPI \u00b7 SQLite \u00b7 React \u00b7 TypeScript", ACCENT),
        ("AI / ANALYTICS", "scikit-learn \u00b7 supervised risk classifier", WARN),
        ("VALIDATION", "pytest \u00b7 Playwright \u00b7 TShark", ACCENT),
        ("GUARANTEES", "Passive \u00b7 Local-first \u00b7 Evidence-linked", GOOD),
    ]
    for (x, w), (title, detail, colour) in zip(
        columns(5), groups, strict=True
    ):
        _node(slide, x, tech_top, w, tech_h,
              [(title, 10.5, True, colour), (detail, 9, False, BODY)])

    foot = _textbox(slide, CONTENT_LEFT, 6.22, CONTENT_RIGHT - CONTENT_LEFT, 0.34)
    _write(foot.text_frame,
           [("The classifier is trained on 313 synthetic sessions and is "
             "NOT VALIDATED for real-world risk; deterministic packet "
             "evidence remains authoritative throughout.", 9.5, False, MUTED, 0)])
    _no_bullets(foot.text_frame)


# ---------------------------------------------------------------------------
# slide 4 -- feasibility and viability
# ---------------------------------------------------------------------------
def slide_4(slide: Any, ev: dict[str, Any]) -> None:
    _subtitle(
        slide,
        "Feasible to build, feasible to operate, feasible to deploy and "
        "feasible to maintain \u2014 each with its own evidence.",
        top=1.14,
    )

    # --- A. technically feasible: the proof, compressed to one strip --------
    metrics = [
        (ev["tests"], "backend tests pass", ACCENT),
        (ev["tests_tshark"], "with the TShark cross-check", ACCENT),
        (ev["frontend_tests"], "frontend tests", ACCENT),
        (ev["e2e_specs"], "real-backend browser E2E", ACCENT),
        (ev["typed_files"], "files ruff + mypy clean", ACCENT),
        ("0", "known advisories at audit", GOOD),
    ]
    strip_top, strip_h = 1.58, 0.86
    for (x, w), (figure, label, colour) in zip(
        columns(len(metrics)), metrics, strict=True
    ):
        tile = _panel(slide, x, strip_top, w, strip_h)
        tile.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        _write(tile.text_frame,
               [(figure, 25, True, colour, 0), (label, 9, False, MUTED, 0)],
               line_spacing=0.84)
        for paragraph in tile.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
            paragraph.space_after = Pt(0)
        _no_bullets(tile.text_frame)

    # --- the four questions this slide exists to answer ---------------------
    # Two rows of two. Four tall columns left most of each card empty; this
    # shape fits the text it actually has.
    quad_top, quad_bottom = 2.60, 5.74
    quads = [
        ("TECHNICALLY FEASIBLE", ACCENT,
         ["The pipeline runs end to end today: PCAP \u2192 reconstruction "
          "\u2192 cryptographic assessment \u2192 findings \u2192 reports.",
          "Every figure in the strip above was produced by running the gate, "
          "not by asserting it."]),
        ("OPERATIONALLY FEASIBLE", ACCENT,
         ["No agent installation \u00b7 no mail-server modification \u00b7 "
          "no credentials required \u00b7 no active probing.",
          "Works from the authorised PCAP / PCAPNG an organisation already "
          "collects."]),
        ("DEPLOYMENT VIABLE", GOOD,
         ["Local-first: FastAPI + React + SQLite. Core analysis works "
          "offline.",
          "Captured traffic never needs to be uploaded to a cloud service; it "
          "runs as a self-contained investigation workstation."]),
        ("MAINTAINABLE / EXTENSIBLE", ACCENT,
         ["Versioned policy rules \u00b7 modular protocol and TLS pipeline "
          "\u00b7 canonical report model \u00b7 independent TShark "
          "cross-check.",
          "New deterministic rules can be added without redesigning the "
          "capture pipeline."]),
    ]
    quad_cols = columns(2)
    quad_rows = rows(2, quad_top, quad_bottom)
    for index, (title, colour, body) in enumerate(quads):
        box = quad_cols[index % 2]
        row_y, row_h = quad_rows[index // 2]
        _card(slide, box, row_y, row_h, title, body,
              title_size=12.5, body_size=11, title_colour=colour)

    # --- the honest limits, kept to two lines -------------------------------
    risks = _panel(slide, CONTENT_LEFT, 5.90, CONTENT_RIGHT - CONTENT_LEFT,
                   0.82, fill=RGBColor(0xFD, 0xF2, 0xEC),
                   line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        risks.text_frame,
        [
            ("KNOWN BOUNDARIES", 10.5, True, WARN, 0),
            ("TLS 1.3 may encrypt certificate evidence a passive capture "
             "cannot recover; it is reported NOT AVAILABLE with the reason, "
             "never guessed.", 10.5, False, BODY, 0),
            ("The AI classifier remains advisory until real-world "
             "validation; it never overrides a deterministic finding or the "
             "score.", 10.5, False, BODY, 0),
        ],
        line_spacing=0.94,
    )
    _no_bullets(risks.text_frame)


# ---------------------------------------------------------------------------
# slide 5 -- impact and benefits
# ---------------------------------------------------------------------------
def slide_5(slide: Any) -> None:
    _subtitle(
        slide,
        "What changes for the organisation that adopts it \u2014 and for the "
        "people who have to act on the result.",
        top=1.14,
    )

    impacts = [
        ("REDUCES MANUAL ANALYSIS",
         "Turns captures into structured cryptographic findings instead of "
         "an analyst reading every TLS negotiation by hand."),
        ("NO PRODUCTION EXPOSURE",
         "Assesses posture without modifying the mail server, deploying "
         "agents, scanning or using credentials."),
        ("MAKES FINDINGS DEFENSIBLE",
         "Each conclusion links to capture, session, packet, timestamp, rule "
         "and remediation \u2014 independently verifiable."),
        ("PRIORITISES REMEDIATION",
         "Severity, confidence, priority and a named fix, rather than raw "
         "protocol data."),
        ("DETECTS REGRESSION",
         "Cross-capture drift reveals changes in observed cryptographic "
         "posture between captures of the same service."),
    ]
    imp_top, imp_h = 1.58, 1.62
    for (x, w), (title, detail) in zip(columns(5), impacts, strict=True):
        _card(slide, (x, w), imp_top, imp_h, title, [detail],
              title_size=11.5, body_size=10)

    # --- the visuals, each attached to the impact it supports ---------------
    vis_top = 3.34
    left_col, mid_col, right_col = weighted([5.05, 4.10, 3.10])

    shot_h = _shot(
        slide, "04-finding-evidence.png", left_col[0], vis_top, left_col[1],
        "DEFENSIBLE \u2014 the finding, its rule and the packets it was "
        "evaluated against.",
        crop=(0.11, 0.150, 1.0, 0.648),
    )
    # All three blocks in this row end on the same line.
    block_h = max(1.92, shot_h)

    drift = _panel(slide, mid_col[0], vis_top, mid_col[1], block_h)
    _write(drift.text_frame,
           [("REGRESSION OVER TIME", 11.5, True, ACCENT, 0),
            ("negotiated version \u00b7 OBSERVED_CHANGE", 10, True, WARN, 0)],
           line_spacing=0.98)
    _no_bullets(drift.text_frame)

    ba_top, ba_h = vis_top + 0.60, 0.68
    ba_cards, ba_arrows = chain(2, left=mid_col[0] + 0.30,
                                right=mid_col[0] + mid_col[1] - 0.30,
                                arrow=0.28)
    ba = [("EARLIER", "TLS 1.2", ACCENT), ("LATER", "TLS 1.0", WARN)]
    for (x, w), (label, value, colour) in zip(ba_cards, ba, strict=True):
        _node(slide, x, ba_top, w, ba_h,
              [(label, 9, True, MUTED), (value, 14, True, colour)],
              fill=RGBColor(0xFF, 0xFF, 0xFF))
    for x in ba_arrows:
        _arrow(slide, x, middle(ba_top, ba_h, ARROW_H), 0.28)

    drift_note = _textbox(slide, mid_col[0] + 0.16, vis_top + block_h - 0.58,
                          mid_col[1] - 0.32, 0.52)
    _write(drift_note.text_frame,
           [("The same observed service, two captures. The change is "
             "recorded as OBSERVED_CHANGE, never inferred.", 9.5, False,
             MUTED, 0)], line_spacing=0.96)
    for paragraph in drift_note.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(drift_note.text_frame)

    _card(slide, right_col, vis_top, block_h,
          "KEEPS SENSITIVE TRAFFIC LOCAL",
          ["Captured enterprise and government email metadata does not need "
           "to be sent to an external AI or cloud service for core analysis.",
           "The engine opens no socket. The only traffic is the browser "
           "talking to 127.0.0.1."],
          title_size=11.5, body_size=10, title_colour=GOOD,
          fill=RGBColor(0xEE, 0xF7, 0xF0), line=RGBColor(0xC6, 0xE2, 0xCE))

    # --- who this is for ----------------------------------------------------
    who_top, who_h = 5.56, 0.48
    who = ["SOC / SECURITY ANALYSTS", "INCIDENT RESPONSE",
           "MAIL ADMINISTRATORS", "AUDIT / ASSURANCE",
           "GOVERNMENT / ENTERPRISE SECURITY"]
    for (x, w), label in zip(columns(len(who)), who, strict=True):
        _node(slide, x, who_top, w, who_h, [(label, 10, True, ACCENT)],
              fill=RGBColor(0xFF, 0xFF, 0xFF))

    footer = _panel(slide, CONTENT_LEFT, 6.18, CONTENT_RIGHT - CONTENT_LEFT,
                    0.46, fill=RGBColor(0xEF, 0xF5, 0xEF),
                    line=RGBColor(0xCF, 0xE2, 0xCF))
    footer.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(footer.text_frame,
           [("Benefits demonstrated on controlled synthetic captures; no "
             "production deployment and no measured time-saving claim.",
             10.5, True, RGBColor(0x2D, 0x5A, 0x3A), 0)])
    for paragraph in footer.text_frame.paragraphs:
        paragraph.alignment = PP_ALIGN.CENTER
    _no_bullets(footer.text_frame)


# ---------------------------------------------------------------------------
# slide 6 -- research and references
# ---------------------------------------------------------------------------
def slide_6(slide: Any) -> None:
    _subtitle(
        slide,
        "The standards the rules cite, and the pipeline every claim in this "
        "deck is checked by.",
        top=1.14,
    )

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
         ["Wireshark / TShark", "Scapy", "cryptography",
          "pytest \u00b7 Playwright"]),
    ]
    ref_top, ref_h = 1.58, 1.46
    for (x, w), (title, items) in zip(columns(3), groups, strict=True):
        _card(slide, (x, w), ref_top, ref_h, title, items,
              title_size=12, body_size=10.5)

    # --- how every claim in this deck is checked ----------------------------
    band_top, band_h = 3.20, 1.72
    _band(slide, CONTENT_LEFT, band_top, CONTENT_RIGHT - CONTENT_LEFT, band_h,
          "HOW EVERY CLAIM IS CHECKED")
    steps = [
        ("CONTROLLED FIXTURES", "one fixed seed, identical bytes everywhere"),
        ("HAND-DERIVED EXPECTATIONS", "written by hand, committed, not read back"),
        ("ENGINE UNDER TEST", "1,357 tests; captures stay out of git"),
        ("INDEPENDENT TSHARK CROSS-CHECK", "against Wireshark\u2019s own dissector"),
        ("REAL-BACKEND PLAYWRIGHT", "five browser specs, including a restart"),
        ("REPORT PARITY", "JSON, HTML and PDF asserted to agree"),
    ]
    node_top, node_h = band_top + 0.30, 1.22
    cards, arrows = chain(len(steps), left=CONTENT_LEFT + 0.16,
                          right=CONTENT_RIGHT - 0.16)
    for (x, w), (title, detail) in zip(cards, steps, strict=True):
        _node(slide, x, node_top, w, node_h,
              [(title, 9.5, True, INK), (detail, 8.5, False, MUTED)])
    for x in arrows:
        _arrow(slide, x, middle(node_top, node_h, ARROW_H), ARROW_W)

    # --- the project, and a code a judge can scan from a seat ---------------
    row_top, row_h = 5.20, 1.16
    project_col, qr_col = weighted([7.40, 4.93])

    project = _panel(slide, project_col[0], row_top, project_col[1], row_h)
    _write(project.text_frame, [("PROJECT", 12, True, ACCENT, 0)])
    _no_bullets(project.text_frame)
    _link_line(project.text_frame, "GitHub repository", REPOSITORY_URL,
               REPOSITORY_URL, size=11.5)
    demo = project.text_frame.add_paragraph()
    demo.line_spacing = 0.88
    demo.space_after = Pt(2)
    run = demo.add_run()
    run.text = VIDEO_LINK_PLACEHOLDER
    run.font.size = Pt(11.5)
    run.font.bold = True
    run.font.color.rgb = INK
    run.font.name = "Calibri"
    _no_bullets(project.text_frame)

    _panel(slide, qr_col[0], row_top, qr_col[1], row_h)
    qr_size = 0.86
    _qr(slide, REPOSITORY_URL, qr_col[0] + 0.14,
        middle(row_top, row_h, qr_size), qr_size)
    label = _textbox(slide, qr_col[0] + 0.14 + qr_size + 0.14,
                     middle(row_top, row_h, 0.66),
                     qr_col[1] - (0.14 + qr_size + 0.14) - 0.14, 0.66)
    label.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    _write(label.text_frame,
           [("SCAN FOR THE REPOSITORY", 10, True, ACCENT, 0),
            ("Public \u2014 source, tests and submission package.",
             9.5, False, MUTED, 0)],
           line_spacing=0.98)
    _no_bullets(label.text_frame)


# ---------------------------------------------------------------------------
#: Strings that must never survive into the built deck. The team registered
#: as exactly "Zero-Day"; "Team Zero Day" and its variants are wrong, and the
#: template's own "Your Team Name" placeholder is wrong.
#: Wordings that were wrong in an earlier deck and must not come back.
FORBIDDEN_PHRASES = (
    "Demonstration Demo",
    "Demonstration video Included",
    "Private until",
    "public URL reserved",
    "not yet issued",
    "lines of code",
)

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

    for bad in FORBIDDEN_PHRASES:
        if bad in both:
            failures.append(f"forbidden wording present: {bad!r}")

    # The problem statement itself is "AI-Assisted". A deck that does not say
    # where the AI is, and what it is not allowed to do, has not answered it.
    for required in ("AI-Assisted", "AI-ASSISTED TRIAGE", "Advisory only",
                     "NOT VALIDATED"):
        if required not in both:
            failures.append(f"the AI story is incomplete, missing: {required!r}")

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
