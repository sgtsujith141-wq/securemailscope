"""Exception hierarchy.

Errors are narrow and typed: the engine never wraps analysis in a bare
``except Exception``.  A malformed *capture* is expected input and produces a
structured diagnostic; only genuinely unusable input raises.
"""

from __future__ import annotations

__all__ = [
    "SecureMailScopeError",
    "InputError",
    "CaptureNotFoundError",
    "CaptureTooLargeError",
    "UnsupportedCaptureFormatError",
    "MalformedCaptureError",
    "ConfigurationError",
]


class SecureMailScopeError(Exception):
    """Base class for every error raised by this package."""


class InputError(SecureMailScopeError):
    """The user-supplied input could not be accepted."""


class CaptureNotFoundError(InputError):
    """Path does not exist, is not a regular file, or is not readable."""


class CaptureTooLargeError(InputError):
    """Capture exceeds the configured maximum file size."""


class UnsupportedCaptureFormatError(InputError):
    """File contents do not match any supported capture container format."""


class MalformedCaptureError(InputError):
    """The capture container is damaged beyond the point of useful parsing.

    Raised only when *no* packet could be read.  A file that parses partially
    yields a truncated result plus diagnostics instead.
    """


class ConfigurationError(SecureMailScopeError):
    """Invalid analysis configuration (e.g. a non-positive limit)."""
