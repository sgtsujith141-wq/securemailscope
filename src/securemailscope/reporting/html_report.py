"""Standalone HTML report rendering (M7).

Three properties are enforced here rather than left to the template author:

**Autoescaping is on, everywhere.** Every value in a report ultimately derives
from a capture, and a capture is untrusted input. A certificate subject, an SNI
value or a protocol banner can contain anything at all, including markup. Jinja
autoescaping is enabled and no value is ever marked safe.

**The document is self-contained.** No external font, script, stylesheet or
image, and no network request of any kind. A forensic report that phoned home
when opened would leak the fact of an investigation, and possibly its contents,
to whoever served the asset. A test asserts the rendered HTML contains no
external reference.

**No payload bytes.** The report carries packet numbers, timestamps and stream
offsets, never reconstructed application data.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from .report_model import ReportModel

__all__ = ["render_html", "write_html_report", "TEMPLATE_DIR", "find_external_references"]

TEMPLATE_DIR: Final = Path(__file__).resolve().parent / "templates"

#: Patterns that would make the document depend on something outside itself.
#: Checked after rendering, so a template change cannot quietly reintroduce
#: one.
_EXTERNAL: Final = (
    re.compile(r"""<script[^>]*\bsrc\s*=""", re.I),
    re.compile(r"""<link[^>]*\bhref\s*=\s*["']?https?:""", re.I),
    re.compile(r"""<img[^>]*\bsrc\s*=\s*["']?(?!data:)""", re.I),
    re.compile(r"""@import\s""", re.I),
    re.compile(r"""url\(\s*["']?https?:""", re.I),
    re.compile(r"""\bsrcset\s*=""", re.I),
)


def _environment():  # type: ignore[no-untyped-def]
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "j2", "xml"), default_for_string=True
        ),
        trim_blocks=True,
        lstrip_blocks=True,
        auto_reload=False,
    )


def find_external_references(html: str) -> list[str]:
    """Any construct that would fetch something when the report is opened."""
    found: list[str] = []
    for pattern in _EXTERNAL:
        for match in pattern.finditer(html):
            found.append(match.group(0))
    return found


def render_html(model: ReportModel) -> str:
    """Render the canonical report as a standalone HTML document."""
    template = _environment().get_template("report.html.j2")
    html = template.render(model=model)
    leaked = find_external_references(html)
    if leaked:
        # A rendering bug, not a user error: fail loudly rather than ship a
        # report that reaches out to the network when someone opens it.
        raise RuntimeError(
            "the rendered report references external resources, which would "
            f"break offline use and leak that it was opened: {leaked[:3]}"
        )
    return html


def write_html_report(model: ReportModel, destination: Path | str) -> Path:
    path = Path(destination)
    path.write_text(render_html(model), encoding="utf-8")
    return path
