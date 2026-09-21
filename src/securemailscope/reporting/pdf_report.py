"""PDF report rendering (M7).

Built with ReportLab's Platypus directly from the canonical
:class:`~securemailscope.reporting.report_model.ReportModel`, **not** by
converting the HTML.

That choice is deliberate and is a security decision. An HTML-to-PDF renderer
resolves whatever the document references: stylesheets, fonts, images, and with
some engines `file://` URLs. Report content derives from captures, which are
untrusted, so a renderer that fetches would be a way to turn a malicious
certificate subject into a local file read or an outbound request. Platypus
cannot fetch anything — it has no URL resolver at all. The guarantee is
structural rather than a filter that has to be kept correct.

Parity with HTML comes from the shared model, not from shared markup. Both
formats read the same fields, so a number cannot differ between them; only the
presentation does, which is what §20 asks for.

Typography uses the fonts ReportLab bundles (Helvetica and Courier), so nothing
is loaded from the system or the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from .report_model import ReportModel

__all__ = ["render_pdf", "write_pdf_report", "PAGE_SIZE_NAME"]

PAGE_SIZE_NAME: Final = "A4"

_SEVERITY_COLOURS: Final = {
    "CRITICAL": "#b3261e",
    "HIGH": "#b35309",
    "MEDIUM": "#8a6a00",
    "LOW": "#1f6f5c",
    "INFO": "#1a4f8a",
}


def _styles() -> dict[str, Any]:
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SmsTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=19, leading=23, spaceAfter=2, alignment=TA_LEFT,
            textColor="#11223a",
        ),
        "subtitle": ParagraphStyle(
            "SmsSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11.5, textColor="#5a6b82", spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "SmsH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=12.5, leading=15, spaceBefore=15, spaceAfter=5,
            textColor="#11223a",
        ),
        "h3": ParagraphStyle(
            "SmsH3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=9.5, leading=12, spaceBefore=8, spaceAfter=3,
            textColor="#33445c",
        ),
        "body": ParagraphStyle(
            "SmsBody", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.8, leading=12, spaceAfter=4,
        ),
        "muted": ParagraphStyle(
            "SmsMuted", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor="#5a6b82", spaceAfter=3,
        ),
        "cell": ParagraphStyle(
            "SmsCell", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.4, leading=9.4,
        ),
        "cellmono": ParagraphStyle(
            "SmsCellMono", parent=base["Normal"], fontName="Courier",
            fontSize=6.8, leading=9.0,
        ),
        "cellhead": ParagraphStyle(
            "SmsCellHead", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=7.2, leading=9.2, textColor="#33445c",
        ),
        "note": ParagraphStyle(
            "SmsNote", parent=base["Normal"], fontName="Helvetica-Oblique",
            fontSize=8, leading=11, textColor="#33445c",
            leftIndent=8, borderPadding=2, spaceBefore=4, spaceAfter=6,
        ),
    }


def _escape(value: object) -> str:
    """Escape for ReportLab's mini-markup.

    Necessary for the same reason HTML autoescaping is: a certificate subject
    is attacker-controlled text, and Platypus paragraphs accept a small set of
    tags. Unescaped input could otherwise break layout or inject markup.
    """
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _wrap(text: object, style: Any) -> Any:
    """Every cell is a Paragraph, so long values wrap instead of clipping.

    Fingerprints, capture ids and certificate subjects are routinely longer
    than a column. A bare string in a ReportLab table is clipped at the cell
    boundary with no warning, which is exactly the silent failure §19 asks to
    be tested for.
    """
    from reportlab.platypus import Paragraph

    return Paragraph(_escape(text), style)


def _table(rows: list[list[Any]], widths: list[float], styles: dict[str, Any]) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#8fa2bb")),
                ("LINEBELOW", (0, 1), (-1, -2), 0.25, colors.HexColor("#dde4ee")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f6f8fb")]),
            ]
        )
    )
    return table


class _Numbering:
    """Draws the footer: page numbers and generation metadata on every page."""

    def __init__(self, model: ReportModel) -> None:
        self.stamp = model.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        self.tool = f"{model.tool_name} {model.tool_version}"
        self.investigation = model.investigation_id or ""

    def __call__(self, canvas: Any, document: Any) -> None:
        from reportlab.lib.units import mm

        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColorRGB(0.42, 0.48, 0.56)
        left = f"{self.tool} · generated {self.stamp}"
        if self.investigation:
            left += f" · {self.investigation}"
        canvas.drawString(18 * mm, 12 * mm, left[:120])
        canvas.drawRightString(
            document.pagesize[0] - 18 * mm, 12 * mm, f"Page {canvas.getPageNumber()}"
        )
        canvas.setStrokeColorRGB(0.86, 0.89, 0.93)
        canvas.setLineWidth(0.4)
        canvas.line(
            18 * mm, 15.5 * mm, document.pagesize[0] - 18 * mm, 15.5 * mm
        )
        canvas.restoreState()


def _build_story(model: ReportModel, styles: dict[str, Any], width: float) -> list[Any]:
    from reportlab.platypus import KeepTogether, PageBreak, Paragraph, Spacer

    story: list[Any] = []
    p, cell, head, mono = (
        styles["body"], styles["cell"], styles["cellhead"], styles["cellmono"]
    )

    story.append(Paragraph(_escape(model.title), styles["title"]))
    meta = (
        f"{model.tool_name} {model.tool_version} &middot; schema {model.schema_version} "
        f"&middot; report model {model.report_model_version} &middot; generated "
        f"{model.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    if model.investigation_id:
        meta += f" &middot; investigation {_escape(model.investigation_id)}"
    story.append(Paragraph(meta, styles["subtitle"]))
    story.append(
        Paragraph(f"<b>Scope.</b> {_escape(model.scope_statement)}", styles["note"])
    )

    # -- executive summary ------------------------------------------------
    story.append(Paragraph("Executive summary", styles["h2"]))
    if model.posture and model.posture.score is not None:
        score_text = (
            f"{model.posture.score}/100 ({model.posture.band}), coverage "
            f"{(model.posture.coverage_ratio or 0) * 100:.0f}%"
        )
    elif model.posture:
        score_text = f"unavailable — {model.posture.status}"
    else:
        score_text = "not assessed"
    severities = (
        ", ".join(f"{count} {name}" for name, count in model.severity_distribution.items())
        or "no findings"
    )
    summary = [
        [_wrap("Captures analysed", head), _wrap(len(model.analysed_captures), cell),
         _wrap("Sessions observed", head), _wrap(len(model.sessions), cell)],
        [_wrap("Security findings", head), _wrap(f"{len(model.findings)} ({severities})", cell),
         _wrap("Posture score", head), _wrap(score_text, cell)],
    ]
    story.append(_table(summary, [width * 0.20, width * 0.30, width * 0.20, width * 0.30], styles))
    if model.failed_captures:
        story.append(Paragraph(
            f"<b>{len(model.failed_captures)} capture(s) failed to analyse</b> and are "
            "listed in the inventory below. Results here do not cover them.",
            styles["note"]))
    if model.posture and model.posture.score is None and model.posture.explanation:
        story.append(Paragraph(
            f"<b>Why there is no score.</b> {_escape(model.posture.explanation)}",
            styles["note"]))
    if model.findings:
        story.append(Paragraph(
            "A numeric score summarises weighted control coverage across the analysed "
            "evidence. It does not supersede an individual finding: the findings below "
            "are the substance.", styles["note"]))

    # -- capture inventory ------------------------------------------------
    story.append(Paragraph("Investigation scope and capture inventory", styles["h2"]))
    rows: list[list[Any]] = [[
        _wrap("Capture", head), _wrap("Status", head), _wrap("Packets", head),
        _wrap("Sessions", head), _wrap("Policy", head),
    ]]
    for capture in model.captures:
        status = capture.status
        if capture.failure_reason:
            status += f" — {capture.failure_reason}"
        if capture.duplicate_of_source:
            status += f" — same bytes as {capture.duplicate_of_source}"
        rows.append([
            _wrap(f"{capture.source_name}\n{capture.capture_id}", mono),
            _wrap(status, cell), _wrap(capture.packet_count, cell),
            _wrap(capture.session_count, cell),
            _wrap(f"{capture.policy_id or '—'} {capture.policy_version or ''}", cell),
        ])
    story.append(_table(rows, [width * 0.34, width * 0.26, width * 0.11,
                               width * 0.11, width * 0.18], styles))

    # -- methodology ------------------------------------------------------
    story.append(Paragraph("Methodology", styles["h2"]))
    story.append(Paragraph(
        "Analysis is entirely passive. No host observed in a capture was contacted, no "
        "domain was scanned, and no capture content left this machine. Findings are "
        "produced by deterministic rules evaluated against reconstructed observations, "
        f"under policy {_escape(model.policy_id or 'n/a')} "
        f"version {_escape(model.policy_version or 'n/a')}"
        + (f", fingerprint {_escape(model.policy_fingerprint)}."
           if model.policy_fingerprint else "."), p))
    if model.posture and model.posture.formula:
        story.append(Paragraph(
            f"Posture score: <font face='Courier'>{_escape(model.posture.formula)}</font>. "
            "Controls whose evidence was unavailable are excluded from both sides of the "
            "fraction and reported separately as coverage.", p))

    # -- TLS intelligence -------------------------------------------------
    if model.sessions:
        story.append(Paragraph("TLS and certificate intelligence", styles["h2"]))
        rows = [[_wrap(x, head) for x in
                 ("Session", "Server", "TLS", "Cipher suite", "Key exch.", "Certificate")]]
        for session in model.sessions[:60]:
            rows.append([
                _wrap(session.session_id, mono), _wrap(session.server, mono),
                _wrap(session.tls_version or "UNKNOWN", cell),
                _wrap(session.cipher_suite or "UNKNOWN", mono),
                _wrap(session.key_exchange or "UNKNOWN", cell),
                _wrap(session.certificate_visibility or "UNKNOWN", cell),
            ])
        story.append(_table(rows, [width * 0.17, width * 0.17, width * 0.09,
                                   width * 0.29, width * 0.13, width * 0.15], styles))
        if len(model.sessions) > 60:
            story.append(Paragraph(
                f"{len(model.sessions) - 60} further sessions are in the JSON export.",
                styles["muted"]))

    # -- findings ---------------------------------------------------------
    story.append(Paragraph("Security findings", styles["h2"]))
    if not model.findings:
        story.append(Paragraph(
            "No findings were raised. This means no rule failed on the evidence "
            "available — it is not a statement that the analysed systems are secure, "
            "and it does not cover anything outside the captures listed above.", p))
    for finding in model.findings:
        colour = _SEVERITY_COLOURS.get(finding.severity, "#33445c")
        block = [
            Paragraph(
                f'<font color="{colour}"><b>{finding.severity}</b></font> · '
                f"<b>{_escape(finding.title)}</b> · "
                f"<font face='Courier' size='7.5'>{_escape(finding.rule_id)}</font>"
                + (f" · {_escape(finding.priority)}" if finding.priority else "")
                + f" · confidence {_escape(finding.confidence)}",
                styles["h3"]),
            Paragraph(_escape(finding.description), p),
            Paragraph(f"<b>Impact.</b> {_escape(finding.technical_impact)}", styles["muted"]),
        ]
        packets = ", ".join(str(e.packet_number) for e in finding.evidence) or "—"
        first = finding.evidence[0].timestamp if finding.evidence else None
        evidence = (
            f"<b>Evidence.</b> session {_escape(finding.session_id)}, "
            f"capture {_escape(finding.capture_id)}, packets {packets}"
        )
        if first:
            evidence += f", first observed {first.strftime('%Y-%m-%d %H:%M:%S.%f')}"
        block.append(Paragraph(evidence, styles["muted"]))
        if finding.standards_references:
            block.append(Paragraph(
                f"<b>References.</b> {_escape('; '.join(finding.standards_references))}",
                styles["muted"]))
        for limitation in finding.limitations:
            block.append(Paragraph(f"• {_escape(limitation)}", styles["muted"]))
        block.append(Spacer(1, 4))
        story.append(KeepTogether(block))

    # -- remediation ------------------------------------------------------
    if model.remediations:
        story.append(Paragraph("Prioritised remediations", styles["h2"]))
        for remediation in model.remediations:
            block = [
                Paragraph(
                    f"<b>{_escape(remediation.title)}</b> · "
                    "<font face='Courier' size='7.5'>"
                    f"{_escape(remediation.remediation_id)}</font> · "
                    f"addresses {_escape(', '.join(remediation.related_rule_ids))}",
                    styles["h3"]),
                Paragraph(_escape(remediation.recommended_action), p),
                Paragraph("<b>Expected effect.</b> "
                          f"{_escape(remediation.expected_security_effect)}",
                          styles["muted"]),
                Paragraph("<b>Operational considerations.</b> "
                          f"{_escape(remediation.operational_considerations)}",
                          styles["muted"]),
            ]
            for step in remediation.validation_steps:
                block.append(Paragraph(f"• {_escape(step)}", styles["muted"]))
            block.append(Spacer(1, 4))
            story.append(KeepTogether(block))

    # -- cryptographic intelligence ---------------------------------------
    if model.fingerprints:
        story.append(Paragraph("Cryptographic fingerprints", styles["h2"]))
        story.append(Paragraph(
            "A fingerprint groups configurations. It does <b>not</b> establish a unique "
            "server identity: two unrelated servers running the same defaults produce "
            "the same value.", styles["note"]))
        rows = [[_wrap(x, head) for x in
                 ("Fingerprint", "Completeness", "Endpoint", "Missing components")]]
        for fingerprint in model.fingerprints[:40]:
            rows.append([
                _wrap(fingerprint.fingerprint_id, mono),
                _wrap(fingerprint.completeness, cell),
                _wrap(fingerprint.endpoint, mono),
                _wrap(", ".join(fingerprint.missing_components) or "—", cell),
            ])
        story.append(_table(rows, [width * 0.28, width * 0.17, width * 0.20,
                                   width * 0.35], styles))

    if model.drift:
        story.append(Paragraph("Cryptographic drift", styles["h2"]))
        rows = [[_wrap(x, head) for x in
                 ("Property", "Status", "Before", "After", "Explanation")]]
        for event in model.drift:
            rows.append([
                _wrap(event.kind, cell), _wrap(event.status, cell),
                _wrap(event.before_value if event.before_observed else "not observed",
                      mono),
                _wrap(event.after_value if event.after_observed else "not observed",
                      mono),
                _wrap(event.explanation, cell),
            ])
        story.append(_table(rows, [width * 0.18, width * 0.16, width * 0.16,
                                   width * 0.16, width * 0.34], styles))

    if model.correlations:
        story.append(Paragraph("Cross-session correlations", styles["h2"]))
        rows = [[_wrap(x, head) for x in
                 ("Type", "Basis", "Sessions", "Captures", "Findings")]]
        for correlation in model.correlations:
            rows.append([
                _wrap(correlation.correlation_type, cell),
                _wrap(correlation.relationship_basis, mono),
                _wrap(correlation.session_count, cell),
                _wrap(correlation.capture_count, cell),
                _wrap(correlation.finding_count, cell),
            ])
        story.append(_table(rows, [width * 0.28, width * 0.36, width * 0.12,
                                   width * 0.12, width * 0.12], styles))
        story.append(Paragraph(
            "A correlation groups shared observations. It establishes no common "
            "ownership, administration, cause, actor or intent.", styles["note"]))

    if model.blast_radius:
        story.append(Paragraph("Observed blast radius", styles["h2"]))
        rows = [[_wrap(x, head) for x in
                 ("Subject", "Sessions", "Endpoints", "Captures", "Findings")]]
        for radius in model.blast_radius:
            rows.append([
                _wrap(radius.subject, mono), _wrap(radius.session_count, cell),
                _wrap(radius.entity_count, cell), _wrap(radius.capture_count, cell),
                _wrap(radius.finding_count, cell),
            ])
        story.append(_table(rows, [width * 0.36, width * 0.16, width * 0.16,
                                   width * 0.16, width * 0.16], styles))
        story.append(Paragraph(
            f"<b>{_escape(model.blast_radius[0].scope_statement)}</b> "
            f"{_escape(model.blast_radius[0].counting_method)}", styles["note"]))

    # -- ML ---------------------------------------------------------------
    if model.ml:
        story.append(Paragraph("Machine-learning analysis", styles["h2"]))
        story.append(Paragraph(f"<b>Status.</b> {_escape(model.ml.ml_status)}", p))
        if model.ml.anomaly_algorithm:
            note = (
                f"<b>Anomaly detection.</b> The selected detector is "
                f"<font face='Courier'>{_escape(model.ml.anomaly_algorithm)}</font>"
            )
            if model.ml.anomaly_algorithm == "rarity_baseline":
                note += (
                    " — a deterministic frequency table, <b>not</b> a machine-learning "
                    "model. It was selected over the Isolation Forest candidate because "
                    "it performed better on held-out evaluation"
                )
            note += "."
            if model.ml.anomaly_training_samples:
                note += (f" Reference population: {model.ml.anomaly_training_samples} "
                         "sessions.")
            story.append(Paragraph(note, p))
            story.append(Paragraph(
                f"{model.ml.anomalous_session_count} session(s) flagged as unusual; "
                f"{model.ml.not_evaluable_session_count} not evaluable.", p))
        if model.ml.classifier_model_id:
            story.append(Paragraph(
                "<b>Supervised risk classifier.</b> "
                f"<font face='Courier'>{_escape(model.ml.classifier_model_id)}</font> "
                f"({_escape(model.ml.classifier_algorithm)}) — status "
                f"<b>{_escape(model.ml.classification_validation_status)}</b>. Its "
                "predictions are not confirmed threats and are not calibrated "
                "probabilities.", p))
        if model.ml.disclosure:
            story.append(Paragraph(_escape(model.ml.disclosure), styles["note"]))
        for limitation in model.ml.evaluation_limitations:
            story.append(Paragraph(f"• {_escape(limitation)}", styles["muted"]))

    # -- evidence appendix -------------------------------------------------
    if model.timeline:
        story.append(PageBreak())
        story.append(Paragraph("Evidence appendix — timeline", styles["h2"]))
        rows = [[_wrap(x, head) for x in
                 ("#", "Time", "Event", "Session", "Packets", "Status")]]
        for entry in model.timeline[:90]:
            rows.append([
                _wrap(entry.order_index, cell),
                _wrap(entry.timestamp.strftime("%H:%M:%S.%f")[:12]
                      if entry.timestamp else "unknown", mono),
                _wrap(f"{entry.event_type}\n{entry.description}", cell),
                _wrap(entry.session_id or "—", mono),
                _wrap(", ".join(str(n) for n in entry.packet_numbers) or "—", mono),
                _wrap(entry.evidence_status, cell),
            ])
        story.append(_table(rows, [width * 0.05, width * 0.13, width * 0.40,
                                   width * 0.18, width * 0.12, width * 0.12], styles))
        if len(model.timeline) > 90:
            story.append(Paragraph(
                f"{len(model.timeline) - 90} further events are in the JSON export.",
                styles["muted"]))

    # -- limitations -------------------------------------------------------
    story.append(Paragraph("Limitations", styles["h2"]))
    for limitation in model.limitations:
        story.append(Paragraph(f"• {_escape(limitation)}", p))
    story.append(Paragraph(
        "• This report covers only the captures listed above. Absence of a finding is "
        "not evidence that a condition does not exist elsewhere.", p))
    story.append(Paragraph(
        "• Findings describe observed configuration. They are not evidence of "
        "exploitation, compromise or attacker activity.", p))

    if model.warnings:
        story.append(Paragraph("Analysis warnings", styles["h2"]))
        for warning in model.warnings:
            story.append(Paragraph(f"• {_escape(warning)}", styles["muted"]))

    return story


def render_pdf(model: ReportModel) -> bytes:
    """Render the canonical report as an A4 PDF."""
    import io

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate

    buffer = io.BytesIO()
    margin = 18 * mm
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=margin,
        rightMargin=margin,
        topMargin=16 * mm,
        bottomMargin=20 * mm,
        title=model.title,
        author=f"{model.tool_name} {model.tool_version}",
        subject="Passive cryptographic security posture assessment",
        creator=f"{model.tool_name} {model.tool_version}",
    )
    styles = _styles()
    width = A4[0] - 2 * margin
    numbering = _Numbering(model)
    document.build(
        _build_story(model, styles, width),
        onFirstPage=numbering,
        onLaterPages=numbering,
    )
    return buffer.getvalue()


def write_pdf_report(model: ReportModel, destination: Path | str) -> Path:
    path = Path(destination)
    path.write_bytes(render_pdf(model))
    return path
