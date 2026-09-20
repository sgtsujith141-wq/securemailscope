"""SecureMailScope -- passive cryptographic security posture assessment.

Analyses locally provided packet captures of email traffic.  The engine is
strictly passive: it never contacts a captured host, never resolves a domain,
and never transmits capture contents anywhere.

Public entry points:

>>> from securemailscope import analyze_capture, AnalysisConfig
>>> result = analyze_capture("capture.pcap", config=AnalysisConfig())
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import AnalysisConfig
from .errors import (
    CaptureNotFoundError,
    CaptureTooLargeError,
    MalformedCaptureError,
    SecureMailScopeError,
    UnsupportedCaptureFormatError,
)
from .pipeline import analyze_capture
from .scapy_guard import PassiveModeViolation, install_passive_guard

install_passive_guard()

__all__ = [
    "AnalysisConfig",
    "CaptureNotFoundError",
    "CaptureTooLargeError",
    "MalformedCaptureError",
    "PassiveModeViolation",
    "SecureMailScopeError",
    "UnsupportedCaptureFormatError",
    "__version__",
    "analyze_capture",
    "install_passive_guard",
]
