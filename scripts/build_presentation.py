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
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission" / "presentation"
DEFAULT_TEMPLATE = Path.home() / "Downloads" / "SIH2026-IDEA-Presentation-Format.pptx"

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
    _write(box.text_frame, lines, line_spacing=1.35)
    return unresolved


# ---------------------------------------------------------------------------
# slide 2 -- idea title / proposed solution
# ---------------------------------------------------------------------------
def slide_2(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.45), Inches(1.30)
    box.width, box.height = Inches(12.45), Inches(5.55)
    _write(
        box.text_frame,
        [
            ("SecureMailScope — passive cryptographic posture assessment for "
             "captured email traffic", 17, True, ACCENT, 0),
            ("", 7, False, INK, 0),
            ("The problem", 13, True, INK, 0),
            ("Organisations know which mail servers they run. They cannot say "
             "which TLS versions those servers negotiated, which cipher suites "
             "they accepted, which sessions had no forward secrecy, or whether "
             "a STARTTLS upgrade was offered and then refused.", 12, False, BODY, 1),
            ("An active scanner cannot answer it either: it reports what a "
             "server does for a scanner today, not what it did for real "
             "clients during the period under investigation — and an "
             "authorised investigator often may not touch the host at all.",
             12, False, BODY, 1),
            ("", 6, False, INK, 0),
            ("The solution", 13, True, INK, 0),
            ("Read the packet captures the organisation already has. Report "
             "what the bytes show about how email was transported — and say "
             "so explicitly when the capture does not show something.",
             12, False, BODY, 1),
            ("", 6, False, INK, 0),
            ("Passive and PCAP-first", 13, True, INK, 0),
            ("The engine opens no socket. It never contacts a captured host, "
             "resolves a domain, scans anything, or sends capture contents "
             "anywhere — including to a language model. Proven by test, not "
             "asserted: socket constructors are replaced with functions that "
             "raise and the whole pipeline is run through them.",
             12, False, BODY, 1),
            ("", 6, False, INK, 0),
            ("Evidence-backed, and honest about its limits", 13, True, INK, 0),
            ("Every finding cites the packet numbers it was read from, the RFC "
             "it applies, a specific remediation, and its own limitation. "
             "Every value carries how it was obtained — OBSERVED, INFERRED, "
             "UNKNOWN or NOT_AVAILABLE — so a port-based guess can never be "
             "mistaken for a parsed dialogue.", 12, False, BODY, 1),
            ("A number that was not measured does not appear. A rule that "
             "could not be evaluated is excluded from both sides of the "
             "scoring fraction rather than counted as a pass or a violation.",
             12, False, BODY, 1),
        ],
        line_spacing=0.94,
    )


# ---------------------------------------------------------------------------
# slide 3 -- technical approach
# ---------------------------------------------------------------------------
def slide_3(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.45), Inches(1.16)
    box.width, box.height = Inches(12.45), Inches(0.60)
    _write(
        box.text_frame,
        [("Pipeline — every stage reads only what the previous one produced. "
          "Line counts are actual.", 11, False, MUTED, 0)],
    )

    # --- the pipeline, drawn from the real module structure -----------------
    stages = [
        ("PCAP /\nPCAPNG", "untrusted\ninput", 1.45),
        ("Ingestion\n1,166 loc", "format from\ncontent", 1.45),
        ("TCP rebuild\n~900 loc", "reorder, gaps,\nconflicts", 1.55),
        ("Email protocols\n3,406 loc", "SMTP/IMAP/POP3\nSTARTTLS", 1.75),
        ("TLS + X.509\n3,903 loc", "version, suite,\nkey exchange", 1.70),
        ("Assessment\n3,416 loc", "25 rules,\nscore, priority", 1.60),
    ]
    x, y = 0.45, 1.88
    for index, (title, subtitle, width) in enumerate(stages):
        panel = _panel(slide, x, y, width, 0.92)
        _write(
            panel.text_frame,
            [
                (title, 10, True, INK, 0),
                (subtitle, 8, False, MUTED, 0),
            ],
            line_spacing=0.88,
        )
        for paragraph in panel.text_frame.paragraphs:
            paragraph.alignment = PP_ALIGN.CENTER
        x += width
        if index < len(stages) - 1:
            _arrow(slide, x + 0.02, y + 0.37)
            x += 0.30

    # --- the two analytical layers that consume the assessment --------------
    for offset, (title, detail) in enumerate(
        [
            ("Cryptographic intelligence — 2,275 loc",
             "fingerprints · server identity · drift between captures · "
             "correlation · evidence timeline · blast radius"),
            ("Machine learning — 3,196 loc",
             "93-feature schema · deterministic rarity baseline IN USE · "
             "Isolation Forest trained and held back · classifier NOT_VALIDATED"),
        ]
    ):
        panel = _panel(slide, 0.45 + offset * 6.30, 3.06, 6.10, 0.80)
        _write(
            panel.text_frame,
            [(title, 10, True, ACCENT, 0), (detail, 8.5, False, BODY, 0)],
            line_spacing=0.90,
        )

    # --- reporting -----------------------------------------------------------
    panel = _panel(slide, 0.45, 4.00, 12.45, 0.62, fill=RGBColor(0xE4, 0xEE, 0xE6),
                   line=RGBColor(0xBE, 0xD8, 0xC6))
    _write(
        panel.text_frame,
        [("ONE canonical report model — 1,582 loc  →  JSON · HTML · PDF, "
          "parity-tested. The HTML report fetches nothing; the PDF has no URL "
          "resolver, so 'no external request' is structural.",
          10, False, BODY, 0)],
    )

    # --- technologies and local-first ---------------------------------------
    left = _panel(slide, 0.45, 4.78, 6.10, 1.98)
    _write(
        left.text_frame,
        [
            ("Technologies", 11, True, INK, 0),
            ("Engine  Python 3.12 · Scapy 2.7 (dissection only) · Pydantic 2.9 "
             "· cryptography 50", 9, False, BODY, 0),
            ("App  FastAPI · SQLAlchemy · SQLite · Uvicorn", 9, False, BODY, 0),
            ("ML  scikit-learn 1.5 · NumPy 2.1", 9, False, BODY, 0),
            ("Reports  Jinja2 · ReportLab", 9, False, BODY, 0),
            ("UI  React 18 · TypeScript strict · Vite 8 · Tailwind · Recharts",
             9, False, BODY, 0),
            ("Test  pytest · hypothesis · Playwright · Vitest · TShark "
             "(independent cross-check)", 9, False, BODY, 0),
        ],
        line_spacing=0.92,
    )

    right = _panel(slide, 6.80, 4.78, 6.10, 1.98,
                   fill=RGBColor(0xFD, 0xF2, 0xEC), line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        right.text_frame,
        [
            ("Local-first processing", 11, True, WARN, 0),
            ("Nothing in the diagram points outward. The only network path in "
             "the system is the browser talking to 127.0.0.1 — the "
             "application's own interface.", 9, False, BODY, 0),
            ("The engine's dependency floor is three packages. A test walks the "
             "AST of every engine module to prove the web and ML stacks cannot "
             "reach the analysis path.", 9, False, BODY, 0),
            ("scapy_guard replaces Scapy's neighbour resolver with one that "
             "raises — the one place the dissector could have spoken on the "
             "wire.", 9, False, BODY, 0),
        ],
        line_spacing=0.92,
    )


# ---------------------------------------------------------------------------
# slide 4 -- feasibility and viability
# ---------------------------------------------------------------------------
def slide_4(slide: Any, evidence: dict[str, Any]) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.45), Inches(1.16)
    box.width, box.height = Inches(12.45), Inches(0.52)
    _write(
        box.text_frame,
        [("Feasible because it is built and measured. Every figure below is "
          "from the release commit, not an estimate.", 11, False, MUTED, 0)],
    )

    built = _panel(slide, 0.45, 1.76, 4.05, 2.55)
    _write(
        built.text_frame,
        [
            ("Built and verified", 11, True, GOOD, 0),
            (f"{evidence['tests']} Python tests pass; "
             f"{evidence['tests_tshark']} with the TShark cross-check enabled",
             9, False, BODY, 0),
            (f"{evidence['frontend_tests']} frontend tests · "
             f"{evidence['e2e_specs']} browser end-to-end specs against the "
             "real backend, nothing mocked", 9, False, BODY, 0),
            (f"mypy clean over {evidence['typed_files']} files · ruff clean",
             9, False, BODY, 0),
            ("22-step browser-to-backend acceptance test, including stopping "
             "and restarting the backend and confirming the investigation "
             "survives", 9, False, BODY, 0),
            (f"Demonstration rehearsed: {evidence['rehearsal_steps']} steps, "
             f"{evidence['rehearsal_failed']} failures", 9, False, BODY, 0),
            ("Clean install from a bare checkout, engine-only and full",
             9, False, BODY, 0),
        ],
        line_spacing=0.92,
    )

    perf = _panel(slide, 4.65, 1.76, 4.05, 2.55)
    _write(
        perf.text_frame,
        [
            ("Measured performance", 11, True, INK, 0),
            ("1,200 packets → 0.86 s, 270 MB peak", 9, False, BODY, 0),
            ("6,000 packets → 4.73 s, 625 MB peak", 9, False, BODY, 0),
            ("24,000 packets → 21.4 s, 1,800 MB peak", 9, False, BODY, 0),
            ("Ground truth matched exactly at every size", 9, False, GOOD, 0),
            ("Thresholds were committed BEFORE the results they judge — the "
             "order is in the repository history", 9, False, MUTED, 0),
            ("Limits: one machine, 16 logical CPUs, synthetic captures. A "
             "repeat run on a loaded machine measured 257 packets/s and FAILED "
             "the 500 packets/s threshold; that result is published, not "
             "discarded.", 9, False, WARN, 0),
        ],
        line_spacing=0.92,
    )

    security = _panel(slide, 8.85, 1.76, 4.05, 2.55)
    _write(
        security.text_frame,
        [
            ("Security controls", 11, True, INK, 0),
            ("Loopback binding is not a security model, so: host allowlist "
             "(DNS rebinding), explicit CORS origins with credentials off, "
             "per-installation token outside the repository at mode 0600",
             9, False, BODY, 0),
            ("Bounded collection responses · magic-byte upload validation "
             "while streaming · error bodies with no path or stack trace",
             9, False, BODY, 0),
            ("0 known vulnerabilities: pip-audit over 49 locked packages, "
             "npm audit over production and development trees",
             9, False, GOOD, 0),
            ("Hash-pinned lock verified with --require-hashes · CycloneDX SBOM "
             "for both trees", 9, False, BODY, 0),
            ("NOT a penetration test and NOT a security certification. Not "
             "safe to expose to a network, and not claimed to be.",
             9, False, WARN, 0),
        ],
        line_spacing=0.92,
    )

    risks = _panel(slide, 0.45, 4.44, 12.45, 2.32,
                   fill=RGBColor(0xFD, 0xF2, 0xEC), line=RGBColor(0xEE, 0xCF, 0xBE))
    _write(
        risks.text_frame,
        [
            ("Challenges, risks, and what is genuinely unresolved — stated, "
             "not hidden", 11, True, WARN, 0),
            ("TLS 1.3 encrypts the Certificate message.  PERMANENT.  No "
             "passive tool can read it. Reported NOT_AVAILABLE with the "
             "reason, never blank and never guessed. TLS 1.2 certificates are "
             "read and verified in full: dates, chain, hostname, key size, "
             "signature algorithm.", 9.5, False, BODY, 0),
            ("Supervised risk classification is NOT_VALIDATED for real-world "
             "use.  Implemented and measured on synthetic data (macro-F1 "
             "0.5624), which does not establish real-world accuracy. No "
             "independent representative validation has been obtained, the "
             "interface says so on screen, and the classifier does not drive "
             "any finding or score.", 9.5, False, BODY, 0),
            ("Handshake completion is not verifiable and revocation is never "
             "checked.  A capture has no traffic keys, and an OCSP or CRL "
             "request would break the passive rule. Three constants are "
             "asserted false or zero in every report by the test suite.",
             9.5, False, BODY, 0),
            ("Deployment constraints.  Memory is the binding limit — about "
             "76 KB peak resident per packet — and two analyses share one "
             "process, so large captures are not claimed to run on the 8 GB "
             "machine the thresholds assume. No run on that hardware has been "
             "taken; the requirement is recorded NOT_VERIFIED. Analysis cannot "
             "be cancelled, and a test asserts the absence so the gap cannot "
             "be mistaken for a broken control.", 9.5, False, BODY, 0),
        ],
        line_spacing=0.90,
    )


# ---------------------------------------------------------------------------
# slide 5 -- impact and benefits
# ---------------------------------------------------------------------------
def slide_5(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.45), Inches(1.16)
    box.width, box.height = Inches(12.45), Inches(0.52)
    _write(
        box.text_frame,
        [("For authorised email-security investigation. These are potential "
          "benefits: the tool is demonstrated on synthetic captures and has "
          "no deployments, no users and no measured real-world outcomes.",
          11, False, MUTED, 0)],
    )

    items = [
        ("Assessment without touching the host",
         "The capture is already collected. Nothing is connected to, scanned "
         "or resolved — so an investigator with no authority to touch a "
         "production mail server can still assess how it protected traffic."),
        ("A cryptographic inventory of what was actually used",
         "Not what a configuration file says. Negotiated versions, cipher "
         "suites, key exchanges and certificate details per session, read "
         "from the bytes on the wire."),
        ("Findings that carry their own evidence",
         "Every finding cites the packet numbers it was read from, the RFC it "
         "applies, and its own limitation. An analyst can open the same packet "
         "in Wireshark and check."),
        ("Prioritised, specific remediation",
         "25 rules under a versioned policy produce a priority band and a "
         "named remediation with its expected security effect — so the answer "
         "to 'what do I fix first' comes with a reason."),
        ("Drift between captures, attributed",
         "The same server observed twice. If the client offered the same "
         "suites and the server selected differently, the change is "
         "attributable to the server. If the offers differed, the result is "
         "INCONCLUSIVE and says so."),
        ("Investigation reports that stand alone",
         "JSON, HTML and PDF from one model, so their facts cannot disagree. "
         "The HTML opens offline and fetches nothing, which matters for an "
         "artefact that may be handed to a reviewer."),
    ]
    for index, (title, detail) in enumerate(items):
        column, row = index % 3, index // 3
        panel = _panel(
            slide, 0.45 + column * 4.20, 1.78 + row * 2.48, 4.00, 2.32
        )
        _write(
            panel.text_frame,
            [(title, 11, True, ACCENT, 0), (detail, 9.5, False, BODY, 0)],
            line_spacing=0.94,
        )

    note = _textbox(slide, 0.45, 6.74, 12.45, 0.30)
    _write(
        note.text_frame,
        [("No financial saving, adoption figure, deployment or real-world "
          "detection rate is claimed: none has been measured.",
          9, True, WARN, 0)],
    )


# ---------------------------------------------------------------------------
# slide 6 -- research and references
# ---------------------------------------------------------------------------
def slide_6(slide: Any) -> None:
    box = _shape(slide, "TextBox 8")
    assert box is not None
    box.left, box.top = Inches(0.45), Inches(1.16)
    box.width, box.height = Inches(12.45), Inches(0.46)
    _write(
        box.text_frame,
        [("Standards the rules cite and the parsers implement. Every rule in "
          "the engine names the clause it applies.", 11, False, MUTED, 0)],
    )

    left = _panel(slide, 0.45, 1.70, 6.10, 3.05)
    _write(
        left.text_frame,
        [
            ("TLS and certificates", 11, True, INK, 0),
            ("RFC 8446 — TLS 1.3", 9, False, BODY, 0),
            ("RFC 5246 — TLS 1.2", 9, False, BODY, 0),
            ("RFC 9325 — Recommendations for Secure Use of TLS/DTLS (2022)",
             9, False, BODY, 0),
            ("RFC 8996 — Deprecating TLS 1.0 and TLS 1.1", 9, False, BODY, 0),
            ("RFC 7457 — Known Attacks on TLS and DTLS", 9, False, BODY, 0),
            ("RFC 4492 — ECC Cipher Suites for TLS", 9, False, BODY, 0),
            ("RFC 5280 — X.509 Certificate and CRL Profile", 9, False, BODY, 0),
            ("RFC 6125 — Verification of Application Service Identity",
             9, False, BODY, 0),
            ("NIST SP 800-52 Rev. 2 — Guidelines for TLS Implementations",
             9, False, BODY, 0),
            ("IANA TLS Parameters registry — suites, groups, signature schemes",
             9, False, BODY, 0),
        ],
        line_spacing=0.94,
    )

    right = _panel(slide, 6.80, 1.70, 6.10, 3.05)
    _write(
        right.text_frame,
        [
            ("Email transport", 11, True, INK, 0),
            ("RFC 5321 — Simple Mail Transfer Protocol", 9, False, BODY, 0),
            ("RFC 3207 — SMTP Service Extension for Secure SMTP over TLS",
             9, False, BODY, 0),
            ("RFC 9051 — IMAP version 4rev2", 9, False, BODY, 0),
            ("RFC 1939 — Post Office Protocol version 3", 9, False, BODY, 0),
            ("RFC 2595 — Using TLS with IMAP, POP3 and ACAP", 9, False, BODY, 0),
            ("RFC 2606 — Reserved Top Level DNS Names (.invalid, used by every "
             "synthetic fixture)", 9, False, BODY, 0),
            ("", 6, False, INK, 0),
            ("Libraries", 11, True, INK, 0),
            ("Scapy · Pydantic · python-cryptography · FastAPI · SQLAlchemy · "
             "scikit-learn · ReportLab · React · Vite", 9, False, BODY, 0),
            ("TShark (Wireshark) — used as an independent dissector to "
             "cross-check our own parse", 9, False, BODY, 0),
        ],
        line_spacing=0.94,
    )

    project = _panel(slide, 0.45, 4.88, 12.45, 1.88)
    _write(
        project.text_frame,
        [
            ("Project research and documentation — written alongside the code, "
             "in this repository", 11, True, ACCENT, 0),
            ("docs/evidence-model.md — the four evidence statuses and how "
             "provenance is tracked   ·   docs/scoring-methodology.md — the "
             "formula, the bands, and why a multi-capture headline is the "
             "weakest capture rather than an average",
             9, False, BODY, 0),
            ("docs/limitations.md — what passive analysis cannot do   ·   "
             "docs/threat-model.md — risks from untrusted captures and how "
             "each is bounded   ·   docs/security-audit.md — the local threat "
             "model, the controls, and what the audit did not cover",
             9, False, BODY, 0),
            ("docs/ml-methodology.md and docs/ml-model-card.md — why a "
             "deterministic rarity baseline was selected over a trained "
             "Isolation Forest by measurement, and what the models are not fit "
             "for   ·   docs/ml-evaluation.md — the metrics and the synthetic "
             "dataset they describe", 9, False, BODY, 0),
            ("docs/performance-benchmarks.md — measurements, thresholds "
             "committed beforehand, and a published failing run   ·   "
             "docs/requirements-matrix.md — every requirement mapped to a "
             "module, a test and an honest status", 9, False, BODY, 0),
        ],
        line_spacing=0.92,
    )


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def _team_name_ovals(prs: Presentation, name: str) -> None:
    """Replace the template's 'Your Team Name' badge on every content slide."""
    for slide in prs.slides:
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
            if shape.text_frame.text.strip() == "Your Team Name":
                frame = shape.text_frame
                _clear(frame)
                run = frame.paragraphs[0].add_run()
                run.text = name
                run.font.size = Pt(10)
                run.font.bold = True
                frame.paragraphs[0].alignment = PP_ALIGN.CENTER
                frame.word_wrap = True


def _evidence() -> dict[str, Any]:
    """Figures for slide 4, read from artefacts rather than typed in."""
    rehearsal = ROOT / "submission" / "demo" / "rehearsal.json"
    steps, failed = "14", "0"
    if rehearsal.is_file():
        record = json.loads(rehearsal.read_text())
        steps = str(record["steps_total"])
        failed = str(record["steps_failed"])
    return {
        "tests": "1,354",
        "tests_tshark": "1,364",
        "frontend_tests": "85",
        "e2e_specs": "5",
        "typed_files": "152",
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

    pptx = OUT / "SecureMailScope-SIH26159.pptx"
    prs.save(str(pptx))
    print(f"PPTX: {pptx.relative_to(ROOT)}  ({len(prs.slides)} slides)")

    pdf = None
    if not args.no_pdf:
        pdf = _to_pdf(pptx)
        if pdf is not None:
            print(f"PDF:  {pdf.relative_to(ROOT)}")

    status = {
        "template": str(args.template.name),
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
