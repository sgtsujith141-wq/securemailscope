"""X.509 certificate parsing and assessment.

STATUS: NOT IMPLEMENTED (planned for M3/M4).

Depends on the TLS layer providing Certificate messages, which is only
possible for TLS 1.2 and earlier in a passive capture.  Will use the
``cryptography`` package (declared as the ``certs`` extra in pyproject.toml).
"""
