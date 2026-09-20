"""TLS record and handshake reconstruction.

STATUS: NOT IMPLEMENTED (planned for M3).

This package is intentionally empty.  No TLS parsing, cipher-suite extraction
or handshake reconstruction exists yet, and the engine never emits TLS
findings -- a report that contains no TLS section means the analysis was not
performed, not that the traffic was unencrypted.

Planned scope: TLS record layer framing over reconstructed TCP streams,
ClientHello/ServerHello parsing, negotiated version and cipher suite,
extensions (SNI, ALPN, supported_groups, signature_algorithms), and STARTTLS /
STLS upgrade correlation with the M2 email-protocol layer.

Known hard limit: in TLS 1.3 the Certificate message is encrypted, so
certificate details cannot be recovered from a passive capture without key
material.  See ``docs/limitations.md``.
"""
