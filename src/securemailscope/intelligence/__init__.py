"""Forensic intelligence across sessions, endpoints and captures (M5).

STATUS: IMPLEMENTED.

Consumes completed forensic and assessment results and correlates them. It
never reparses packets, never opens a socket and needs no model: every
statement it makes is traceable to a packet reference produced by an earlier
layer.
"""

from .engine import INVESTIGATION_SCHEMA_VERSION, BatchOutcome, analyze_batch

__all__ = ["analyze_batch", "BatchOutcome", "INVESTIGATION_SCHEMA_VERSION"]
