"""M8: report security and reliability under hostile and awkward input.

A report is the artefact that leaves the machine: it is opened in a browser,
attached to an email, handed to a reviewer. Three things must hold no matter
what the capture or the investigation name contained.

*It must not execute anything.* Everything in a report is derived from an
untrusted packet capture. Server names, cipher suite labels, certificate
subjects and SNI values are all attacker-influenced, and the HTML report is
opened with the user's browser.

*It must not fetch anything.* An offline forensic report that loads a font from
a CDN both breaks offline and tells a third party when it was opened.

*It must not quietly lose a finding.* A HIGH severity result has to appear in
every format, whatever the aggregate score looks like.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from securemailscope.backend.app import AppState, create_app
from securemailscope.backend.security import TOKEN_HEADER
from securemailscope.models.assessment import FindingSeverity
from securemailscope.pipeline import analyze_capture
from securemailscope.reporting.html_report import find_external_references, render_html
from securemailscope.reporting.pdf_report import render_pdf
from securemailscope.reporting.report_model import build_report

FIXTURES = Path(__file__).parent / "fixtures" / "generated"

#: Strings that must survive a round trip through all three renderers without
#: becoming markup, a script, a template expression or a broken document.
HOSTILE_NAMES = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<!--[if IE]><script>bad()</script><![endif]-->",
    "</td></tr></table><h1>injected</h1>",
    "javascript:alert(1)",
    "{{ model.__class__.__mro__ }}",
    "{% raw %}{% endraw %}",
    "\"'`;--",
    "&lt;already escaped&gt;",
    "line\nbreak\ttab\r\n",
    "🔐 Investigation ✉️ névé 中文 العربية עברית हिन्दी",
    "‮RIGHT-TO-LEFT OVERRIDE‭",
    "A" * 4000,
]


@pytest.fixture(scope="module")
def model():
    """One real analysis, reused: building it is the expensive part."""
    results = [
        analyze_capture(FIXTURES / name)
        for name in (
            "aa_tls10_static_rsa.pcap",
            "ab_null_cipher.pcap",
            "t_a_tls12_complete_handshake.pcap",
        )
    ]
    return build_report(results)


@pytest.fixture
def state(tmp_path: Path):
    app_state = AppState(tmp_path / "app")
    yield app_state
    app_state.shutdown()


# ---------------------------------------------------------------------------
# No execution, no fetching
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("hostile", HOSTILE_NAMES)
def test_a_hostile_title_cannot_become_markup(hostile: str) -> None:
    results = [analyze_capture(FIXTURES / "aa_tls10_static_rsa.pcap")]
    html = render_html(build_report(results, title=hostile))

    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror" not in html
    assert "<h1>injected</h1>" not in html
    # The text is still present, escaped -- escaping must not mean discarding.
    if hostile.strip() and "\n" not in hostile:
        needle = hostile.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        needle = needle.replace('"', "&#34;").replace("'", "&#39;")
        assert needle in html or hostile in html, "the title vanished from the report"


def test_capture_derived_strings_are_escaped(model) -> None:
    """Server names and cipher labels come from the wire and are not trusted."""
    html = render_html(model)
    # A well-formed document: no stray unescaped angle bracket in a data cell.
    assert html.count("<html") == 1
    assert html.count("</html>") == 1
    assert "<script" not in html.lower()
    assert "onerror=" not in html.lower()
    assert "javascript:" not in html.lower()


def test_the_html_report_fetches_nothing(model) -> None:
    html = render_html(model)
    assert find_external_references(html) == []
    for construct in ("http://", "https://", "//cdn", "<iframe", "<object", "<embed"):
        if construct in ("http://", "https://"):
            # Standards URLs may appear as *text*; what matters is that they are
            # not in a src/href that a browser would fetch.
            continue
        assert construct not in html.lower(), construct


def test_the_html_report_is_a_single_self_contained_file(model, tmp_path: Path) -> None:
    path = tmp_path / "report.html"
    path.write_text(render_html(model), encoding="utf-8")
    assert path.stat().st_size > 0
    # Nothing beside it is required to open it.
    assert list(tmp_path.iterdir()) == [path]


def test_the_pdf_has_no_javascript_or_launch_actions(model) -> None:
    """Checked structurally, not by substring.

    Searching the raw bytes for ``/JS`` gives false positives from compressed
    streams, which makes the test flaky and its passes meaningless. This walks
    the document catalogue and the annotations instead, which is where an
    action would actually have to live to run.
    """
    import io

    from pypdf import PdfReader

    pdf = render_pdf(model)
    assert pdf.startswith(b"%PDF-")
    reader = PdfReader(io.BytesIO(pdf))

    dangerous = {"/JavaScript", "/JS", "/Launch", "/SubmitForm", "/ImportData", "/GoToR"}
    catalog = reader.trailer["/Root"]
    assert "/OpenAction" not in catalog, "the PDF runs something when it is opened"
    assert "/AA" not in catalog, "the PDF carries additional-actions triggers"
    assert "/Names" not in catalog or "/JavaScript" not in catalog["/Names"]
    assert "/AcroForm" not in catalog, "the PDF carries a form"
    assert "/EmbeddedFiles" not in str(catalog.get("/Names", ""))

    for page in reader.pages:
        assert "/AA" not in page
        for annotation in page.get("/Annots", []) or []:
            obj = annotation.get_object()
            action = obj.get("/A", {})
            subtype = action.get("/S") if hasattr(action, "get") else None
            assert subtype not in dangerous, f"annotation action {subtype}"
            assert "/URI" not in (action or {}), "the PDF links out to a URL"


# ---------------------------------------------------------------------------
# Awkward but legitimate input
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("hostile", HOSTILE_NAMES)
def test_every_format_renders_a_hostile_title_without_crashing(hostile: str) -> None:
    results = [analyze_capture(FIXTURES / "aa_tls10_static_rsa.pcap")]
    built = build_report(results, title=hostile)

    document = json.loads(json.dumps(built.model_dump(mode="json"), default=str))
    assert document["title"] == hostile, "JSON must carry the value verbatim"

    html = render_html(built)
    assert len(html) > 1000

    pdf = render_pdf(built)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_a_very_long_identifier_does_not_truncate_silently(model) -> None:
    """Long values must wrap, not be cut short: a truncated hash is not evidence."""
    html = render_html(model)
    document = model.model_dump(mode="json")
    for session in document["sessions"][:10]:
        assert session["session_id"] in html, (
            f"{session['session_id']} was altered or truncated in the HTML report"
        )


def test_unicode_survives_the_json_and_html_round_trip() -> None:
    title = "névé ✉️ 中文 العربية"
    results = [analyze_capture(FIXTURES / "aa_tls10_static_rsa.pcap")]
    built = build_report(results, title=title)
    assert json.loads(json.dumps(built.model_dump(mode="json"), default=str))["title"] == title
    html = render_html(built)
    assert title in html
    assert 'charset="utf-8"' in html.lower() or "charset=utf-8" in html.lower()
    # And it is really UTF-8 on disk, not escapes.
    assert title.encode("utf-8") in html.encode("utf-8")


# ---------------------------------------------------------------------------
# Nothing is hidden
# ---------------------------------------------------------------------------
def test_no_high_severity_finding_is_omitted_from_any_format(model) -> None:
    """The aggregate score must never suppress an individual result."""
    document = model.model_dump(mode="json")
    high = [
        finding
        for finding in document["findings"]
        if finding["severity"] in (FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value)
    ]
    assert high, "the fixture set must contain a high-severity finding for this test"

    html = render_html(model)
    pdf_text = _pdf_text(render_pdf(model))
    for finding in high:
        assert finding["finding_id"] in html, finding["finding_id"]
        assert finding["finding_id"] in pdf_text, finding["finding_id"]
        assert finding["title"] in html


def test_the_three_formats_agree_on_what_was_found(model) -> None:
    document = model.model_dump(mode="json")
    html = render_html(model)
    pdf_text = _pdf_text(render_pdf(model))

    assert f"{len(document['findings'])}" in html
    for finding in document["findings"]:
        assert finding["finding_id"] in html
        assert finding["finding_id"] in pdf_text


def _pdf_text(pdf: bytes) -> str:
    """Whitespace-normalised PDF text: long identifiers wrap across lines."""
    import io

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(pdf))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    return "".join(text.split())


# ---------------------------------------------------------------------------
# Size
# ---------------------------------------------------------------------------
def test_a_large_investigation_still_reports(state: AppState) -> None:
    """Every fixture at once: the biggest investigation the fixtures allow."""
    captures = sorted(FIXTURES.glob("*.pcap"))
    assert len(captures) >= 20
    with TestClient(create_app(state), base_url="http://127.0.0.1") as client:
        client.headers.update({TOKEN_HEADER: state.token.value})
        capture_ids = []
        rejected = []
        for path in captures:
            response = client.post(
                "/api/captures",
                files={
                    "file": (path.name, path.read_bytes(), "application/octet-stream")
                },
            )
            if response.status_code == 200:
                capture_ids.append(response.json()["capture_id"])
            else:
                # Some fixtures are deliberately not valid captures. Being
                # refused at upload is the correct outcome for those.
                rejected.append((path.name, response.status_code))
        assert len(capture_ids) >= 20, f"only {len(capture_ids)} accepted; {rejected}"
        assert all(code in (400, 413, 422) for _, code in rejected), rejected

        identifier = client.post(
            "/api/investigations",
            json={"name": "every fixture", "capture_ids": capture_ids},
        ).json()["investigation_id"]
        client.post(f"/api/investigations/{identifier}/analyze")
        state.service.wait(identifier)

        detail = client.get(f"/api/investigations/{identifier}").json()
        assert detail["investigation"]["status"] == "COMPLETED"
        assert detail["investigation"]["finding_count"] > 0

        sizes = {}
        for fmt in ("json", "html", "pdf"):
            response = client.get(f"/api/investigations/{identifier}/export/{fmt}")
            assert response.status_code == 200, fmt
            sizes[fmt] = len(response.content)
        assert all(size > 1000 for size in sizes.values()), sizes
        # Openable: see benchmarks/thresholds.json T5.
        assert max(sizes.values()) <= 32 * 1024 * 1024, sizes
