"""Reproducible performance measurement (M8).

Benchmarks generate their own captures from fixed seeds, so a number produced
on one machine can be reproduced on another. Nothing here is estimated: every
figure is a measurement of a real run over a real capture.
"""

from .harness import BenchmarkResult, CaptureProfile, run_suite

__all__ = ["BenchmarkResult", "CaptureProfile", "run_suite"]
