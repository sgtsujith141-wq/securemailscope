# Limitations of passive analysis

Read this before trusting any SecureMailScope result.

This document is deliberately blunt. A security tool that overstates what it
knows is worse than no tool, because it converts uncertainty into false
confidence. Everything below is a real constraint, not a to-do list — the items
marked **permanent** will still be true when every milestone is finished.

---

## 1. Cryptographic limits — permanent

### TLS 1.3 encrypts the certificate

In TLS 1.3 everything after `ServerHello` — including the `Certificate` and
`CertificateVerify` messages — is encrypted under handshake traffic keys. A
passive observer with no key material **cannot** recover the server
certificate, its issuer, its validity dates, its key size, its signature
algorithm, or its SAN list.

For a TLS 1.3 session, certificate-derived properties are reported as
`NOT_AVAILABLE`, never `UNKNOWN` and never omitted. A longer or cleaner capture
will not change this.

In TLS 1.2 and earlier the `Certificate` message is sent in the clear and can
be recovered. Any future report must therefore make the negotiated version
prominent, because it determines what the certificate section can possibly
mean.

### Private keys cannot be recovered

There is nothing in a capture from which a private key can be derived. The
engine will never attempt it.

### Application data cannot be decrypted

Encrypted records are opaque. Without `SSLKEYLOGFILE` material or a private key
plus a non-forward-secret cipher suite, message contents are unrecoverable. The
project does not plan to accept key material.

### What remains observable under TLS 1.3

Passive analysis still sees: the `ClientHello` in plaintext (offered versions,
cipher suites, supported groups, signature algorithms, ALPN, and SNI unless
Encrypted Client Hello is in use), the `ServerHello` (selected version, cipher
suite, chosen group), record sizes and timings, and the TCP-level facts.
That is a genuine and useful security posture signal — it is simply not the
same thing as inspecting a certificate.

### Encrypted Client Hello

Where ECH is deployed, the inner `ClientHello` — including the real SNI — is
encrypted. The outer name will be observed; the real one will be
`NOT_AVAILABLE`.

---

## 2. What the capture itself determines

### A capture is a sample, not the truth

Analysis can only describe what was captured. Traffic that was not captured
cannot be reasoned about, and **the absence of a finding is never evidence of
the absence of the condition**. A capture with no plaintext SMTP does not mean
an organisation has no plaintext SMTP.

### Partial and midstream captures

If a capture starts after a connection was established, there is no SYN, so:

- Client and server roles are `INFERRED`, not observed. The engine prefers a
  recognised service port and falls back to "whoever sent the first packet".
  Both can be wrong.
- Stream offset 0 is anchored on the lowest observed sequence number, so
  offsets are relative to the capture, not to the connection.
- The session is labelled `MIDSTREAM` and says so in `completeness_notes`.

### Snapshot length truncation

Captures taken with a short snaplen store only the first N bytes of each frame.
The engine detects this by comparing the IP header's declared length against
the bytes present, keeps the genuine prefix, and reports the shortfall as a
`NOT_CAPTURED` gap. It never treats a truncated segment as a complete one.

### Gaps are holes, not delays

A gap means those bytes are absent from this file. The engine does not know
whether they were dropped by the capture point, lost on the network, or sent
outside the capture window. When the peer acknowledged data we never saw, an
`ACKED_DATA_NOT_CAPTURED` diagnostic says so — that is the one case where
absence is positively confirmed.

### Clock accuracy

Timestamps come from the capture file and are only as accurate as the capture
host's clock. The engine preserves them exactly (to nanoseconds where the
container supports it) but cannot validate them. Timestamps from different
capture points are not necessarily comparable.

---

## 3. TCP reassembly limits

### Overlapping segments have no single correct answer

When two segments claim the same offsets with different bytes, different
operating systems resolve it differently — that is exactly why the technique is
used for IDS evasion. The engine applies `FIRST_OBSERVED_WINS`, reports every
conflict with both SHA-256 digests and both packet numbers, and marks the
session `PARTIAL`. **The reconstructed stream in that case is one possible
interpretation, not necessarily the one the real endpoint saw.** Per-OS policy
emulation is not implemented.

### Duplicate versus retransmission is an inference

A frame captured twice and a genuine retransmission can be byte-identical. The
engine classifies a repeat as `DUPLICATE` only when the entire frame is
byte-identical to an earlier one, and as `RETRANSMISSION` otherwise. Where the
two are genuinely indistinguishable from the capture, the classification may be
wrong; the byte counts are unaffected either way.

### Sequence wraparound

Sequence numbers are projected into 64-bit space using the standard
"shorter arc wins" rule, which is exact for any value within 2³¹ of the
high-water mark. A capture with a gap larger than 2 GiB in one direction could
in principle be misprojected. This is documented rather than defended against.

### Not implemented in the TCP layer

- **IP fragment reassembly.** Fragments are detected, reported as
  `IP_FRAGMENT_NOT_REASSEMBLED`, and their data is absent from the streams.
- **TCP checksum validation.** Checksums are not verified. Hardware offload
  makes them unreliable on captures taken at an endpoint anyway.
- **TCP option semantics.** SACK, window scaling and timestamps are not
  interpreted.
- **Per-OS reassembly policies.**

---

## 4. Protocol identification limits

M1 identifies nothing. It emits **hints** derived from the server port, marked
`INFERRED`, prefixed `HINT:`, and carrying explicit limitations. A service on
port 25 is probably SMTP; a port number is not proof, and email protocols run
on non-standard ports routinely.

Payload-based confirmation is M2. Until then, **no claim of email-protocol
detection is made anywhere in this repository.**

---

## 5. Link layer and encapsulation limits

Supported: Ethernet (with up to three VLAN tags), raw IPv4/IPv6, BSD and
OpenBSD loopback, Linux cooked v1 and v2.

Not supported, and reported as `UNSUPPORTED_LINK_TYPE` rather than guessed:
802.11, radiotap, and everything else. Tunnelled traffic (GRE, VXLAN, IP-in-IP,
IPsec, PPPoE) is not decapsulated — the outer flow is analysed and the inner
one is invisible.

---

## 6. Not implemented yet

These are milestones, not permanent limits:

| Capability | Milestone |
|---|---|
| SMTP / IMAP / POP3 command and response parsing | M2 |
| STARTTLS / STLS upgrade detection and correlation | M2–M3 |
| TLS record framing and handshake reconstruction | M3 |
| Certificate parsing and assessment (TLS ≤ 1.2 only) | M3–M4 |
| Risk scoring and explainable findings | M4 |
| Cross-session evidence correlation | M5 |
| ML-assisted analysis | M6 |
| REST API and web interface | M7–M8 |

Every report embeds `stage_status`, so a reader can always tell "not found"
from "not looked for".

---

## 7. Things this tool will never do

- Connect to a host observed in a capture.
- Perform a live scan of any domain or address.
- Send capture contents to any external service, including an LLM.
- Attempt to break, downgrade or decrypt cryptography.
- Report a certificate for a TLS 1.3 session.
- Present an inference as an observation.
