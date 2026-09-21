"""Benchmark harness (M8).

Measures the real pipeline over real captures. Three properties:

**Reproducible.** Captures are generated from fixed seeds, the environment is
recorded with every result, and the raw measurements are written as JSON.

**Honest about variation.** Each configuration runs several times and the
result carries the minimum, median and maximum. A single run presented as a
throughput figure would be a guess dressed as a measurement.

**Correctness-checked.** Every run compares the engine's session and TLS counts
against the ground truth the generator recorded. A benchmark that times a
pipeline producing wrong answers is measuring nothing worth knowing.
"""

from __future__ import annotations

import json
import platform
import resource
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Final

from ..config import AnalysisConfig
from .corpus import PROFILES, CaptureProfile, build_capture

__all__ = [
    "BenchmarkResult",
    "CaptureProfile",
    "environment",
    "run_suite",
    "write_results",
]

#: Repeats per configuration. Enough to report a spread without making the
#: suite too slow to run honestly before every release.
DEFAULT_REPEATS: Final = 3


def environment() -> dict[str, str]:
    """Everything needed to interpret a number on this page."""
    versions: dict[str, str] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
    }
    for name in ("scapy", "pydantic", "sklearn", "numpy", "reportlab", "sqlalchemy"):
        try:
            module = __import__(name)
        except ImportError:
            continue
        versions[name] = getattr(module, "__version__", "unknown")
    import os

    versions["cpu_count"] = str(os.cpu_count())
    return versions


def _peak_rss_mb() -> float:
    """Peak resident memory for this process.

    ``ru_maxrss`` is bytes on macOS and kilobytes on Linux; normalised here so
    a reported figure means the same thing on both.
    """
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value / (1024 * 1024) if sys.platform == "darwin" else value / 1024


@dataclass
class StageTiming:
    """What one configuration of the pipeline costs.

    ``seconds`` is the median wall time of the whole pipeline with the layers
    up to and including this one enabled; ``added_seconds`` is the increment
    over the previous configuration. The increment is reported exactly as
    measured, including when it comes out negative -- a negative value means
    the effect is smaller than this machine's run-to-run variation, and saying
    so is more useful than clamping it to zero and implying the layer is free.
    ``within_noise`` marks that case.
    """

    name: str
    seconds: float
    added_seconds: float
    within_noise: bool


@dataclass
class BenchmarkResult:
    profile: str
    label: str
    capture_bytes: int
    packets: int
    sessions_expected: int
    sessions_observed: int
    tls_sessions_expected: int
    tls_sessions_observed: int
    findings: int
    repeats: int
    seconds_min: float
    seconds_median: float
    seconds_max: float
    packets_per_second: float
    bytes_per_second: float
    peak_rss_mb: float
    report_bytes: dict[str, int] = field(default_factory=dict)
    stages: list[StageTiming] = field(default_factory=list)
    correct: bool = True
    notes: list[str] = field(default_factory=list)


def _stage_timings(
    path: Path, config: AnalysisConfig, *, repeats: int = DEFAULT_REPEATS
) -> list[StageTiming]:
    """Time the pipeline in pieces, by progressively enabling layers.

    Each configuration is run ``repeats`` times and summarised by its median,
    because a single run of the full pipeline can differ from a single run of
    the forensic-only pipeline by more than the layer under test costs. The
    per-configuration spread is used as the noise floor: an increment smaller
    than that spread is reported but flagged, never presented as a measurement
    of the layer.

    This is not a profiler. It answers one question -- how much does turning
    this layer off save -- and nothing finer.
    """
    from dataclasses import replace

    from ..pipeline import analyze_capture

    def timed(**overrides: Any) -> tuple[float, float]:
        local = replace(config, **overrides)
        samples = []
        for _ in range(repeats):
            start = time.perf_counter()
            analyze_capture(path, config=local)
            samples.append(time.perf_counter() - start)
        return statistics.median(samples), max(samples) - min(samples)

    forensic, forensic_spread = timed(assess_security=False, enable_ml=False)
    assessed, assessed_spread = timed(assess_security=True, enable_ml=False)
    full, full_spread = timed(assess_security=True, enable_ml=True)

    def stage(name: str, total: float, previous: float, noise: float) -> StageTiming:
        added = total - previous
        return StageTiming(
            name=name,
            seconds=round(total, 4),
            added_seconds=round(added, 4),
            within_noise=added < noise,
        )

    return [
        StageTiming(
            name="ingestion, TCP, protocol, TLS",
            seconds=round(forensic, 4),
            added_seconds=round(forensic, 4),
            within_noise=False,
        ),
        stage(
            "+ security assessment",
            assessed,
            forensic,
            max(forensic_spread, assessed_spread),
        ),
        stage(
            "+ machine learning",
            full,
            assessed,
            max(assessed_spread, full_spread),
        ),
    ]


def run_profile(
    profile: CaptureProfile,
    directory: Path,
    *,
    repeats: int = DEFAULT_REPEATS,
    with_reports: bool = True,
) -> BenchmarkResult:
    """Measure one capture size end to end."""
    from ..intelligence import analyze_batch
    from ..pipeline import analyze_capture
    from ..reporting.html_report import render_html
    from ..reporting.pdf_report import render_pdf
    from ..reporting.report_model import build_report

    path, truth = build_capture(profile, directory)
    config = AnalysisConfig()

    # One warm run: the first analysis in a process pays for imports, the
    # registry build and the ML model load, none of which is per-capture work.
    warm = analyze_capture(path, config=config)

    durations: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        analyze_capture(path, config=config)
        durations.append(time.perf_counter() - start)

    notes: list[str] = []
    sessions_observed = len(warm.sessions)
    tls_observed = len(warm.tls)
    correct = (
        sessions_observed == truth["sessions"] and tls_observed == truth["tls_sessions"]
    )
    if not correct:
        notes.append(
            f"correctness: expected {truth['sessions']} sessions and "
            f"{truth['tls_sessions']} TLS sessions, observed {sessions_observed} "
            f"and {tls_observed}"
        )
    if warm.capture.truncated:
        notes.append("the capture was truncated by a configured limit")

    report_bytes: dict[str, int] = {}
    if with_reports:
        outcome = analyze_batch([path], config=config)
        model = build_report(outcome.results, outcome.investigation)
        report_bytes = {
            "json": len(
                json.dumps(model.model_dump(mode="json"), default=str).encode("utf-8")
            ),
            "html": len(render_html(model).encode("utf-8")),
            "pdf": len(render_pdf(model)),
        }

    median = statistics.median(durations)
    return BenchmarkResult(
        profile=profile.name,
        label=profile.label,
        capture_bytes=truth["bytes"],
        packets=truth["packets"],
        sessions_expected=truth["sessions"],
        sessions_observed=sessions_observed,
        tls_sessions_expected=truth["tls_sessions"],
        tls_sessions_observed=tls_observed,
        findings=len(warm.assessment.findings) if warm.assessment else 0,
        repeats=repeats,
        seconds_min=round(min(durations), 4),
        seconds_median=round(median, 4),
        seconds_max=round(max(durations), 4),
        packets_per_second=round(truth["packets"] / median, 1) if median else 0.0,
        bytes_per_second=round(truth["bytes"] / median, 1) if median else 0.0,
        peak_rss_mb=round(_peak_rss_mb(), 1),
        report_bytes=report_bytes,
        stages=_stage_timings(path, config, repeats=repeats),
        correct=correct,
        notes=notes,
    )


def run_suite(
    profiles: tuple[CaptureProfile, ...] = PROFILES,
    *,
    repeats: int = DEFAULT_REPEATS,
    with_reports: bool = True,
) -> dict[str, Any]:
    """Run every profile and return a machine-readable record."""
    results: list[BenchmarkResult] = []
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for profile in profiles:
            results.append(
                run_profile(profile, root, repeats=repeats, with_reports=with_reports)
            )
    return {
        "environment": environment(),
        "repeats": repeats,
        "results": [asdict(result) for result in results],
        "measurement_context": (
            "Locally generated synthetic captures on one machine. These are "
            "measurements of this configuration, not a claim about throughput "
            "on other hardware or on real traffic."
        ),
    }


def write_results(record: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
