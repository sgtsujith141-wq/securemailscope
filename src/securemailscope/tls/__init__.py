"""TLS record, handshake and cryptographic parameter analysis (M3).

STATUS: IMPLEMENTED for the observable, plaintext portion of a handshake.

What this package does: frames TLS records over reconstructed TCP payload,
reassembles handshake messages across records, identifies the negotiated
version and cipher suite, describes key exchange, and assesses forward
secrecy -- all from bytes that were actually visible.

What it deliberately does not do: decrypt anything, accept key material, or
claim a handshake completed. In TLS 1.3 everything after the ServerHello is
encrypted, so that is where plaintext analysis stops.
"""
