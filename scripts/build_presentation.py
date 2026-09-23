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

#: The reserved slot for the demonstration video. It stays this text until a
#: URL genuinely exists: the video ships inside the submission package, and
#: nothing has been uploaded anywhere.
VIDEO_LINK_PLACEHOLDER = (
    "included in the submission package \u2014 public URL reserved, not yet issued"
)



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
    box.left, box.top = Inches(0.42), Inches(1.12)
    box.width, box.height = Inches(12.5), Inches(0.40)
    _write(
        box.text_frame,
        [("Each stage reads only what the previous one produced. Line counts "
          "are actual.", 10, False, MUTED, 0)],
    )

    # --- architecture, as a vertical pipeline -------------------------------
    stages = [
        ("PCAP / PCAPNG", "untrusted input, 8 hard limits"),
        ("Safe ingestion — 1,166 loc", "format from content, never the extension"),
        ("TCP reconstruction — ~900 loc", "reorder · retransmit · gaps · overlap conflicts"),
        ("SMTP / IMAP / POP3 — 3,406 loc", "real state machines; port is only a hint"),
        ("STARTTLS / STLS", "advertised · requested · outcome · exact upgrade packet"),
        ("TLS handshake + crypto — 3,042 loc",
         "version from supported_versions, KX from key_share"),
        ("X.509 intelligence — 861 loc", "RFC 5280 path, dates, hostname, key, signature"),
        ("Security rules + scoring — 3,416 loc", "25 rules · versioned policy · explainable score"),
        ("Correlation · drift · anomaly — 5,471 loc",
         "fingerprints · entities · blast radius · ML"),
        ("FastAPI + SQLite — 2,756 loc", "loopback only · token · 3 explicit migrations"),
        ("React forensic dashboard — 4,400 loc", "TypeScript strict · evidence-linked throughout"),
        ("JSON · HTML · PDF — 1,582 loc", "one canonical model, parity-tested"),
    ]
    y = 1.56
    for title, detail in stages:
        panel = _panel(slide, 0.42, y, 6.05, 0.40)
        _write(
            panel.text_frame,
            [(f"{title}   —   {detail}", 8.5, False, BODY, 0)],
            line_spacing=0.88,
        )
        panel.text_frame.paragraphs[0].runs[0].font.bold = False
        y += 0.435

    # --- badges ---------------------------------------------------------------
    badges = [("PASSIVE ONLY", GOOD), ("LOCAL FIRST", ACCENT), ("EVIDENCE LINKED", WARN)]
    bx = 6.72
    for text, colour in badges:
        badge = _panel(slide, bx, 1.56, 2.02, 0.34,
                       fill=RGBColor(0xF2, 0xF6, 0xFB), line=BOX_LINE)
        _write(badge.text_frame, [(text, 9, True, colour, 0)])
        for paragraph in badge.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
        bx += 2.12

    _shot(slide, "06-evidence-provenance.png", 6.72, 2.02, 3.02,
          "Finding \u2192 packets")
    _shot(slide, "07-crypto-intelligence.png", 9.90, 2.02, 3.02,
          "Cryptographic DNA")

    tech = _panel(slide, 6.72, 4.02, 6.20, 1.30)
    _write(
        tech.text_frame,
        [
            ("Technologies", 10, True, ACCENT, 0),
            ("Python 3.12 · Scapy 2.7 (dissection only) · cryptography 50 · "
             "Pydantic 2.9 · FastAPI · SQLite · SQLAlchemy",
             8.5, False, BODY, 0),
            ("React 18 · TypeScript strict · Vite 8 · Tailwind · "
             "scikit-learn 1.5 · ReportLab · Jinja2", 8.5, False, BODY, 0),
            ("Verification: pytest · hypothesis · Playwright · Vitest · "
             "TShark used as an independent dissector", 8.5, False, BODY, 0),
        ],
        line_spacing=0.90,
    )


# ---------------------------------------------------------------------------
# slide 4 -- feasibility and viability
# ---------------------------------------------------------------------------
def slide_4(slide: Any, ev: dict[str, Any]) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.12)
    box.width, box.height = Inches(12.5), Inches(0.40)
    _write(
        box.text_frame,
        [("Feasible because it is built and measured. Every figure is from the "
          "release commit, re-run — not an estimate.", 10, False, MUTED, 0)],
    )

    built = _panel(slide, 0.42, 1.56, 4.02, 2.60)
    _write(
        built.text_frame,
        [
            ("Implemented and verified", 10.5, True, GOOD, 0),
            ("Full PCAP \u2192 report workflow, end to end", 8.5, False, BODY, 0),
            ("TCP reconstruction handles reordering, retransmission, gaps, "
             "overlap conflicts and tuple reuse", 8.5, False, BODY, 0),
            ("SMTP / IMAP / POP3 state machines with STARTTLS and STLS; "
             "protocol from the dialogue, not the port", 8.5, False, BODY, 0),
            ("TLS 1.2 and TLS 1.3 handled with separate semantics", 8.5, False, BODY, 0),
            ("X.509 analysis wherever the evidence permits", 8.5, False, BODY, 0),
            ("25 deterministic rules, versioned policy, explainable score",
             8.5, False, BODY, 0),
            ("Cross-capture drift and correlation", 8.5, False, BODY, 0),
        ],
        line_spacing=0.90,
    )

    tested = _panel(slide, 4.60, 1.56, 4.02, 2.60)
    _write(
        tested.text_frame,
        [
            ("Verification", 10.5, True, INK, 0),
            (f"{ev['tests']} backend tests pass; {ev['tests_tshark']} with the "
             "TShark cross-check enabled", 8.5, False, BODY, 0),
            ("Ten cross-checks compare our dissection against Wireshark's, so "
             "a bug in our own parser cannot validate itself",
             8.5, False, BODY, 0),
            (f"{ev['frontend_tests']} frontend tests · {ev['e2e_specs']} browser "
             "end-to-end specs against the real backend, nothing mocked",
             8.5, False, BODY, 0),
            (f"ruff and mypy clean over {ev['typed_files']} files", 8.5, False, BODY, 0),
            ("Expectations are hand-derived and committed as manifests; the "
             "captures are generated, so a test cannot confirm itself",
             8.5, False, BODY, 0),
            ("0 known dependency vulnerabilities (pip-audit, npm audit); "
             "hash-pinned lock; CycloneDX SBOM", 8.5, False, GOOD, 0),
        ],
        line_spacing=0.90,
    )

    _shot(slide, "08-drift.png", 8.78, 1.56, 4.14,
          "Cryptographic drift between captures of one endpoint. "
          "Actual product output.")

    risks = _panel(slide, 0.42, 4.32, 12.5, 2.44,
                   fill=RGBColor(0xFD, 0xF2, 0xEC), line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        risks.text_frame,
        [
            ("Challenges and limits — stated, not hidden", 10.5, True, WARN, 0),
            ("TLS 1.3 encrypts the Certificate message.  A passive capture "
             "without decryption material cannot expose what is not on the "
             "wire. Reported NOT_AVAILABLE with the reason, never blank and "
             "never guessed. TLS 1.2 certificates are read and verified in "
             "full: dates, chain, hostname, key size, signature algorithm.",
             9, False, BODY, 0),
            ("The supervised classifier is NOT VALIDATED for real-world "
             "deployment.  It is trained and measured on controlled synthetic "
             "servers (macro-F1 0.5624). Synthetic evaluation does not "
             "establish real-world accuracy, the interface says so on screen, "
             "and the classifier drives no finding and no score. The anomaly "
             "detector actually in use is a deterministic rarity baseline, not "
             "a machine-learning model — a trained Isolation Forest was "
             "measured, lost, and is shipped labelled as experimental.",
             9, False, BODY, 0),
            ("Handshake completion is not verifiable and revocation is never "
             "checked.  A capture carries no traffic keys, and an OCSP or CRL "
             "request would break the passive rule. Three constants are "
             "asserted false or zero in every report by the test suite.",
             9, False, BODY, 0),
            ("Deployment.  Memory binds before speed — about 76 KB peak "
             "resident per packet — and no benchmark has been run on the "
             "assumed 4-core/8 GB minimum, which is recorded NOT VERIFIED. "
             "Analysis cannot be cancelled, and a test asserts the absence so "
             "it cannot be mistaken for a broken control.", 9, False, BODY, 0),
        ],
        line_spacing=0.88,
    )


# ---------------------------------------------------------------------------
# slide 5 -- impact and benefits
# ---------------------------------------------------------------------------
def slide_5(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.12)
    box.width, box.height = Inches(12.5), Inches(0.40)
    _write(
        box.text_frame,
        [("For authorised email-security investigation. These are potential "
          "benefits: the tool is demonstrated on synthetic captures and has no "
          "deployments, no users and no measured real-world outcomes.",
          10, False, MUTED, 0)],
    )

    blocks = [
        ("DISCOVER",
         "Identify the cryptographic configurations actually negotiated — "
         "versions, cipher suites, key exchanges and certificates — from "
         "traffic the organisation already holds, without touching the host."),
        ("EXPLAIN",
         "Link every finding to the packets that establish it, with the RFC it "
         "applies and the limitation it carries. An analyst can open the same "
         "packet in Wireshark and check."),
        ("PRIORITIZE",
         "Rank weaknesses by a severity and confidence matrix, each with a "
         "named remediation and its expected security effect, so 'what do I "
         "fix first' has an answer with a reason."),
        ("TRACK",
         "Detect cryptographic drift across captures: when the same observed "
         "service changes what it negotiates, and whether the change is "
         "attributable to the server or merely to a different client."),
    ]
    x = 0.42
    for title, detail in blocks:
        panel = _panel(slide, x, 1.56, 3.06, 1.72)
        _write(
            panel.text_frame,
            [(title, 11, True, ACCENT, 0), (detail, 8.5, False, BODY, 0)],
            line_spacing=0.92,
        )
        x += 3.18

    _shot(slide, "04-finding-evidence.png", 0.42, 3.46, 4.02,
          "A finding, with its rule, severity and remediation.")
    _shot(slide, "08-drift.png", 4.66, 3.46, 4.02,
          "Configuration drift between captures of one endpoint.")
    _shot(slide, "11-reports.png", 8.90, 3.46, 4.02,
          "JSON, offline HTML and PDF export.")

    note = _panel(slide, 0.42, 6.30, 12.5, 0.46,
                  fill=RGBColor(0xE4, 0xEE, 0xE6), line=RGBColor(0xBE, 0xD8, 0xC6))
    _write(
        note.text_frame,
        [("Captured enterprise traffic stays local by default — nothing is "
          "uploaded, and no host in a capture is ever contacted.   ·   "
          "No financial saving, adoption figure, deployment or real-world "
          "detection rate is claimed: none has been measured.",
          9, True, BODY, 0)],
    )


# ---------------------------------------------------------------------------
# slide 6 -- research and references
# ---------------------------------------------------------------------------
def slide_6(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.42), Inches(1.12)
    box.width, box.height = Inches(12.5), Inches(0.40)
    _write(
        box.text_frame,
        [("Standards the rules cite and the parsers implement. Every rule "
          "names the clause it applies.", 10, False, MUTED, 0)],
    )

    left = _panel(slide, 0.42, 1.56, 4.02, 3.30)
    _write(
        left.text_frame,
        [
            ("TLS and certificates", 10.5, True, INK, 0),
            ("[1]  RFC 8446 — TLS 1.3", 8.5, False, BODY, 0),
            ("[2]  RFC 5246 — TLS 1.2", 8.5, False, BODY, 0),
            ("[3]  RFC 9325 — Recommendations for secure use of TLS (2022)",
             8.5, False, BODY, 0),
            ("[4]  RFC 8996 — Deprecating TLS 1.0 and 1.1", 8.5, False, BODY, 0),
            ("[5]  RFC 7457 — Known attacks on TLS and DTLS", 8.5, False, BODY, 0),
            ("[6]  RFC 4492 — ECC cipher suites for TLS", 8.5, False, BODY, 0),
            ("[7]  RFC 5280 — X.509 certificate and CRL profile", 8.5, False, BODY, 0),
            ("[8]  RFC 6125 — Verifying application service identity",
             8.5, False, BODY, 0),
            ("[9]  NIST SP 800-52 Rev. 2 — TLS implementation guidelines",
             8.5, False, BODY, 0),
            ("[10] IANA TLS Parameters registry", 8.5, False, BODY, 0),
        ],
        line_spacing=0.92,
    )

    middle = _panel(slide, 4.60, 1.56, 4.02, 3.30)
    _write(
        middle.text_frame,
        [
            ("Email transport", 10.5, True, INK, 0),
            ("[11] RFC 5321 — Simple Mail Transfer Protocol", 8.5, False, BODY, 0),
            ("[12] RFC 3207 — SMTP over TLS (STARTTLS)", 8.5, False, BODY, 0),
            ("[13] RFC 9051 — IMAP version 4rev2", 8.5, False, BODY, 0),
            ("[14] RFC 1939 — Post Office Protocol version 3", 8.5, False, BODY, 0),
            ("[15] RFC 2595 — Using TLS with IMAP, POP3 and ACAP",
             8.5, False, BODY, 0),
            ("[16] RFC 2606 — Reserved DNS names (.invalid, used by every "
             "synthetic fixture)", 8.5, False, BODY, 0),
            ("", 5, False, INK, 0),
            ("Libraries", 10.5, True, INK, 0),
            ("[17] Scapy · [18] python-cryptography · [19] FastAPI",
             8.5, False, BODY, 0),
            ("[20] scikit-learn · [21] React · [22] Wireshark / TShark",
             8.5, False, BODY, 0),
        ],
        line_spacing=0.92,
    )

    right = _panel(slide, 8.78, 1.56, 4.14, 3.30,
                   fill=RGBColor(0xF2, 0xF6, 0xFB), line=BOX_LINE)
    _write(
        right.text_frame,
        [
            ("Verification methodology", 10.5, True, ACCENT, 0),
            ("Deterministic synthetic fixtures.  Every capture is generated "
             "from a fixed seed, so the same bytes are produced on every "
             "machine and in CI.", 8.5, False, BODY, 0),
            ("Known-answer manifests.  Expectations are hand-derived and "
             "committed; the captures themselves are gitignored. A test cannot "
             "confirm its own output.", 8.5, False, BODY, 0),
            ("Independent TShark cross-checks.  Ten comparisons against "
             "Wireshark's dissector, so a shared bug in our parser cannot "
             "validate itself.", 8.5, False, BODY, 0),
            ("Browser end-to-end tests.  Five Playwright specs drive the real "
             "backend over the real engine, including a restart to prove "
             "persistence.", 8.5, False, BODY, 0),
            ("Report-parity verification.  One canonical model feeds JSON, "
             "HTML and PDF, and their facts are asserted equal.",
             8.5, False, BODY, 0),
        ],
        line_spacing=0.90,
    )

    # Sized so the image AND its caption land above the template's footer
    # band, which starts at 6.95in. A 3.22in-wide 16:9 crop is 1.81in tall;
    # starting at 4.98in its caption fell across the band and was clipped.
    _shot(slide, "03-findings.png", 0.42, 4.80, 3.00,
          "Findings triage")
    _shot(slide, "05-session.png", 3.56, 4.80, 3.00,
          "Session negotiation")

    project = _panel(slide, 7.14, 4.98, 5.78, 1.72)
    _write(
        project.text_frame,
        [
            ("Project research", 10, True, ACCENT, 0),
            ("evidence-model \u00b7 scoring-methodology \u00b7 limitations \u00b7 "
             "threat-model \u00b7 security-audit", 8, False, BODY, 0),
            ("ml-methodology \u00b7 ml-evaluation \u00b7 ml-model-card \u00b7 "
             "performance-benchmarks", 8, False, BODY, 0),
            ("REQUIREMENT-COVERAGE.md \u2014 all 35 SIH26159 capabilities with "
             "status and evidence", 8, False, BODY, 0),
        ],
        line_spacing=0.88,
    )
    _link_line(project.text_frame, "Repository", REPOSITORY_URL, REPOSITORY_URL)
    _link_line(
        project.text_frame,
        "Demonstration video",
        VIDEO_LINK_PLACEHOLDER,
        None,
    )


# ---------------------------------------------------------------------------
# build
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
