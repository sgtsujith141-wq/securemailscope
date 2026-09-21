"""Small builders used by tests to exercise message-level bounds directly."""

from __future__ import annotations

__all__ = ["two_certificate_message"]


def two_certificate_message(size: int = 32) -> bytes:
    """A TLS 1.2 Certificate message body carrying two placeholder entries.

    The entries are not valid DER; the point is the *framing*, so that the
    certificate-count bound can be tested without depending on a real chain.
    """
    entry = bytes(size)
    entries = b"".join(len(entry).to_bytes(3, "big") + entry for _ in range(2))
    return len(entries).to_bytes(3, "big") + entries
