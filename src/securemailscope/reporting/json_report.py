"""JSON serialisation of an :class:`~securemailscope.models.analysis.AnalysisResult`.

Two properties are enforced here rather than left to the caller:

* **No payload bytes.**  Reports carry counts, offsets, digests and packet
  references, never reconstructed application data.  A report can therefore be
  attached to a ticket or a submission without leaking mail contents.
* **Deterministic ordering.**  Keys follow model declaration order and
  collections keep engine order, so two runs over the same capture produce
  byte-identical output apart from the analysis timestamps.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models.analysis import AnalysisResult

__all__ = ["result_to_dict", "result_to_json", "write_json_report"]


def result_to_dict(
    result: AnalysisResult,
    *,
    include_segments: bool = True,
    include_protocol_events: bool = True,
    include_tls_records: bool = True,
    include_rule_results: bool = True,
) -> dict[str, Any]:
    """Convert a result to plain Python objects.

    ``include_segments=False`` drops the per-packet segment provenance lists
    and ``include_protocol_events=False`` drops the per-line protocol event
    lists; both dominate report size on large captures. Everything needed to
    judge reconstruction quality and upgrade outcomes -- runs, gaps,
    conflicts, detection, the upgrade attempt and authentication observations
    -- is always kept.
    """
    data = result.model_dump(mode="json", exclude_none=True)
    if not include_segments:
        for session in data.get("sessions", []):
            for key in ("client_to_server", "server_to_client"):
                session[key].pop("segments", None)
    if not include_protocol_events:
        for analysis in data.get("protocols", []):
            analysis.pop("events", None)
    if not include_tls_records:
        for analysis in data.get("tls", []):
            analysis.pop("records", None)
    if not include_rule_results:
        assessment = data.get("assessment")
        if assessment:
            for session in assessment.get("sessions", []):
                session.pop("rule_results", None)
    return data


def result_to_json(
    result: AnalysisResult,
    *,
    indent: int | None = 2,
    include_segments: bool = True,
    include_protocol_events: bool = True,
    include_tls_records: bool = True,
    include_rule_results: bool = True,
) -> str:
    return json.dumps(
        result_to_dict(
            result,
            include_segments=include_segments,
            include_protocol_events=include_protocol_events,
            include_tls_records=include_tls_records,
            include_rule_results=include_rule_results,
        ),
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
    )


def write_json_report(
    result: AnalysisResult,
    destination: Path | str,
    *,
    indent: int | None = 2,
    include_segments: bool = True,
    include_protocol_events: bool = True,
    include_tls_records: bool = True,
    include_rule_results: bool = True,
) -> Path:
    """Write the report to ``destination`` and return the resolved path."""
    path = Path(destination).expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = result_to_json(
        result,
        indent=indent,
        include_segments=include_segments,
        include_protocol_events=include_protocol_events,
        include_tls_records=include_tls_records,
        include_rule_results=include_rule_results,
    )
    path.write_text(payload + "\n", encoding="utf-8")
    return path
