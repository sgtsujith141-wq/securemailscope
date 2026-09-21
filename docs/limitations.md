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

### TLS 1.2 versus TLS 1.3 visibility

This is the single most consequential difference for passive analysis:

| Evidence | TLS 1.2 | TLS 1.3 |
|---|---|---|
| ClientHello (offers, SNI, groups) | plaintext | plaintext |
| ServerHello (version, suite, key_share) | plaintext | plaintext |
| Certificate | **plaintext — extractable** | **encrypted — NOT_AVAILABLE** |
| ServerKeyExchange (ephemeral group + public key) | plaintext | n/a (in key_share) |
| EncryptedExtensions, CertificateVerify, Finished | after CCS: encrypted | encrypted |
| Application data | encrypted | encrypted |

The encryption boundary differs too: in TLS 1.2 a direction goes dark at its
own ChangeCipherSpec (RFC 5246 §7.1); in TLS 1.3 everything after the
ServerHello is encrypted (RFC 8446 §2). A TLS 1.3 session may still emit a
ChangeCipherSpec purely for middlebox compatibility (RFC 8446 §D.4); it is
recognised as such and never read as a TLS 1.2 signal.

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

## 4. Protocol identification and STARTTLS limits

M2 parses SMTP, IMAP and POP3 from payload. What it still cannot tell you:

### A port number is never proof

Detection reaches `CONFIRMED` only from application-level syntax. A session
with no parseable dialogue on port 993 is reported `PORT_HINT`, never
confirmed IMAP. Where payload and port disagree, the payload wins and the
disagreement is stated.

### An accepted upgrade is not an encrypted connection

`UPGRADE_ACCEPTED` means the server replied that it would begin TLS.
`TLS_BYTES_OBSERVED` additionally means bytes with valid TLS record framing
followed. **Neither means a handshake completed, that the parameters were
sound, or that the peer's certificate was acceptable.** Those are M3 and M4
questions, and `handshake_analyzed` is a constant `False` throughout M2.

### Record framing is a weak signal on its own

A single well-formed TLS record header is graded `SINGLE_RECORD_HEADER` with
`INFERRED` status because arbitrary binary payload can match it by chance.
Only an identifiable handshake message or a chain of length-consistent records
is treated as observed.

### What is inside an implicit-TLS session is unknowable

On ports 465, 993 and 995 the session is TLS from its first byte. The framing
may be observed; the email protocol inside it is encrypted and cannot be
identified passively. It stays a port hint.

### A gap during negotiation voids the conclusion

If data is missing while an upgrade command is outstanding, the state becomes
`INCOMPLETE` even if TLS-looking bytes appear afterwards. The engine will not
claim a successful negotiation it did not observe end to end.

### A midstream capture loses capability context

If the `EHLO` was not captured, the `250` multiline reply answering it is not
treated as a capability advertisement -- there is no way to know which command
it answers. `UPGRADE_ADVERTISED` will be absent even though the bytes
containing `STARTTLS` are present. This is deliberate conservatism.

### Absence of STARTTLS is not a downgrade attack

The engine records that an upgrade was absent, rejected or unused. It does not
conclude anything about intent or attack. Turning those observations into
findings is M4.

### TLS and certificate analysis limits

**Handshake completion is never verified.** Confirming a Finished message
needs the handshake traffic keys. No session is reported as a
cryptographically completed handshake; what is reported is what was
negotiated and what key material was visible.

**Record alignment is lost at a hole.** TLS records are self-delimiting only
if every preceding byte was read. After missing data, framing stops
(`ALIGNMENT_LOST_AT_GAP`) rather than resynchronising on a guess. Records
split across *TCP segments* are unaffected.

**Ambiguous bytes are not parsed.** A record overlapping an unresolved TCP
overlap conflict is framed and reported but never interpreted.

**No trust store is assumed.** Without an explicitly configured PEM anchor
set, chain verification reports `NOT_AVAILABLE`. The engine never falls back
to a system bundle, because a report must be able to name the anchors it used.
Intermediates are never fetched from the network, so a chain missing its
intermediate is reported as incomplete rather than as verified-invalid.

**No reference identity is assumed.** Hostname verification requires an
expected identity supplied by the analyst. The destination IP address is never
used as one. An observed SNI value is recorded as evidence of what the client
asked for; it becomes a reference identity only if the operator explicitly
elects to trust it.

**Revocation is never checked.** No OCSP and no CRL retrieval exist, because
the engine makes no network requests at all. A successful chain verification
is not evidence of non-revocation.

**Validity is judged at capture time.** Substituting the analysis clock would
answer a different question. A current-time assessment is available but is
always labelled as a separate statement.

**Forward secrecy is a property of the negotiated method**, not a guarantee
about an implementation's key handling or its reuse of ephemeral keys. TLS 1.3
is not assumed forward secret: a PSK-only resumption is classified `PSK_ONLY`.

**Key sizes are not invented.** Ed25519 and Ed448 report no bit length,
because a variable key length is not a meaningful description of them.

### Not implemented in the TLS layer

- **Decryption of anything.** No key material is accepted, no `SSLKEYLOGFILE`
  is read, and no private key is loaded. This is deliberate and permanent.
- **Certificate transparency, OCSP stapling, CAA, DANE/TLSA.**
- **Session ticket contents** (they are opaque server state).
- **QUIC and DTLS.**
- **Renegotiation and post-handshake authentication.**
- **Compression, early data (0-RTT) payload.**
- **Per-OS or per-library policy emulation** for what "acceptable" means; M3
  reports facts, M4 will judge them.

### Not implemented in the protocol layer

- SMTP `BDAT` / CHUNKING bodies (only dot-terminated `DATA` is skipped).
- IMAP `COMPRESS=DEFLATE`; a compressed stream is not decompressed.
- SASL mechanism-specific semantics. Mechanism names are recorded when
  recognised; nothing about the exchange is interpreted.
- Message headers, envelopes, addresses and bodies. Deliberately never parsed.
- NNTP, Sieve, ManageSieve, Submission-over-QUIC.

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
| ~~SMTP / IMAP / POP3 command and response parsing~~ | done in M2 |
| ~~STARTTLS / STLS upgrade detection and state~~ | done in M2 |
| ~~TLS handshake reconstruction and negotiated parameters~~ | done in M3 |
| ~~Certificate extraction and independent validation~~ | done in M3 (TLS ≤ 1.2) |
| ~~Certificate parsing and assessment (TLS ≤ 1.2 only)~~ | done in M3–M4 |
| ~~Risk scoring and explainable findings~~ | done in M4 |
| ~~Threat prioritisation and remediation guidance~~ | done in M4 |
| ~~Cross-session evidence correlation~~ | done in M5 |
| ~~Cryptographic fingerprinting, drift and blast radius~~ | done in M5 |
| ~~ML-assisted analysis~~ | done in M6 |
| REST API and web interface | M7–M8 |

Every report embeds `stage_status`, so a reader can always tell "not found"
from "not looked for".

---

## 8. Limits of the assessment layer (M4)

The assessment layer inherits every limit above — it can only judge what the
forensic layers observed — and adds some of its own.

### What the posture score is not

It is **a transparent, project-defined analytical metric over one capture under
one named policy version.** It is not an independently validated measure of
enterprise-wide security, is not benchmarked against any industry data set, and
carries no accreditation. The weights and band boundaries are ordering
judgements chosen by this project, documented with their rationale, and fully
configurable.

A score does not tell you how secure an organisation is, how it compares with
peers, whether it is compliant with anything, or what the score would become
after a fix. The **findings are the substance; the score is a reading aid**, and
where they seem to disagree the findings are what to act on. See
[scoring-methodology.md](scoring-methodology.md), which works through a fixture
that scores `ADEQUATE` while negotiating RC4.

### Coverage bounds every conclusion

Coverage — the weighted fraction of applicable controls the evidence actually
let us evaluate — is reported alongside every score, because a score of 100
over 4% coverage is a statement about very little. Below the configured floor
(default 50%) no score is produced at all.

### What the rules cannot conclude

- **Nothing about a configuration that was not exercised.** A server that
  negotiated TLS 1.2 in this capture may also accept TLS 1.0; passive capture
  cannot enumerate what was *available*, only what was *chosen*. No rule claims
  otherwise.
- **Nothing about intent.** A refused `STARTTLS` is reported as configuration.
  It is equally what a server with no TLS configured does, and the finding says
  so explicitly. This tool does not detect attacks.
- **Nothing about scope beyond the capture.** `observed_session_count` counts
  sessions in this capture only. No cross-capture or cross-session correlation
  exists; that is M5.
- **Nothing from an unrecognised code point.** A cipher suite absent from this
  build's registry is `UNKNOWN`, not weak. Our registry's gaps are ours.
- **Nothing about a chain without a trust store, or an identity without an
  expected name.** Both are `UNKNOWN` by default. Supplying `--trust-store` and
  `--expected-server-identity` is what turns them into real checks.

### The score depends on the policy, and says so

Two reports produced under different thresholds are not comparable, even at the
same policy version. Finding identifiers therefore incorporate a **policy
fingerprint** covering the version and every applied override, so a diff
between reports evaluated under different criteria cannot silently compare
unlike things.

---

## 9. Limits of the intelligence layer (M5)

The intelligence layer inherits every limit above -- it can only correlate what
the forensic layers observed -- and adds some of its own.

### A fingerprint is not an identity

Two servers installed from the same distribution package produce the same
cryptographic fingerprint on day one. A match means *configured alike*, and
nothing more. A TLS 1.3 session can never produce a complete fingerprint at
all, because its Certificate message is encrypted.

### An entity is an endpoint, not a machine

A `ServerEntity` is one observed `(ip, port)`. Whether that is a single host, a
load-balanced pool or a virtual host is **not observable from a capture**, so
entity counts are counts of observed network endpoints. Nothing is merged on a
shared certificate, key, name or configuration; those are reported as typed
relationships instead.

### Drift only sees what was captured

A server may have changed and changed back between two captures. A difference
in a negotiated value is attributed to the server only when the two clients
offered the same thing; otherwise it is `INCONCLUSIVE`, which is a statement
about the evidence rather than about the server.

### Clocks are not synchronised

Timestamps come from the capturing host's clock. Within one capture their order
is meaningful. **Across captures taken on different hosts the clocks are
independent**, and no synchronisation is assumed, measured or corrected for, so
cross-capture ordering may not reflect real-world chronology. A packet's
capture timestamp is when the capturing host saw it, not when it was sent.

### Counts are observations, not coverage of an estate

Every blast-radius number covers the analysed captures only. Absence from a
count is absence of observation -- it is not evidence that a host, user or
session is unaffected. No business criticality is represented or inferred.

### No intent, ever

A correlation groups shared observations. It establishes no attacker, campaign,
ownership, administration or common cause, and this tool does not detect
attacks. A weak configuration is a weak configuration.

---

## 10. Limits of the machine-learning layer (M6)

Everything the ML layer says is weaker than everything else in a report, and
this section says how much weaker.

### The models are trained on synthetic data

Every sample is generated by this repository. Nothing measured on it transfers
to real traffic without independent evaluation on representative data, and none
has been performed. Metrics in [ml-evaluation.md](ml-evaluation.md) are
controlled-environment measurements and say so on the page.

### An anomaly is relative, and rarity is not risk

"Unusual" means unusual against the recorded training reference population.
Change the population and the answer changes. A rare configuration is often the
strongest one present -- the `hardened_uncommon` negative-control family exists
to keep that testable, and none of its held-out sessions was flagged.

An anomaly is **not** a vulnerability, **not** an attack, and **not** evidence
of intent.

### Supervised classification is NOT_VALIDATED

Implemented, trained properly and well clear of its baseline (macro-F1 0.562
against 0.123) -- and still not fit to act on. Its label is a rubric this
project authored, over synthetic servers, measured across 31 independent test
groups. Predicting it well shows the rubric's verdict can be recovered from
partial observations; it does not show that compromise can be predicted. See
[ml-model-card.md](ml-model-card.md).

### Scores are not probabilities

No calibration was fitted or validated. A class score of 0.54 does not mean a
54% chance of anything, and no code converts one into a probability. An
Isolation Forest `decision_function` value is an ordering statistic, never a
probability of malicious activity.

### The sample is small

152 servers, 512 eligible sessions, 31 independent groups in the test split,
10 CRITICAL test samples, 8 injected anomalies. Perfect precision over 8
positives is a far weaker claim than the same figure over 800, and every
denominator is stated for that reason. No confidence intervals are quoted,
because an interval over 10 samples would mislead more than its absence does.

### The dataset is generator-shaped

The configuration families are ones we designed. A pattern we did not think of
is not represented in any measurement on this page.

### What the layer never does

- Modify an observation, a finding or a posture score.
- Enter a `SecurityFinding`.
- Guess when evidence is insufficient -- it abstains.
- Download a model, contact a service, or use a GPU.
- Deserialise an artifact whose digest, version or feature schema does not
  match what this build expects.

---

## 7. Things this tool will never do

- Connect to a host observed in a capture.
- Perform a live scan of any domain or address.
- Send capture contents to any external service, including an LLM.
- Attempt to break, downgrade or decrypt cryptography.
- Report a certificate for a TLS 1.3 session.
- Present an inference as an observation.
- Record a username, a password, a SASL payload, an email address or a message
  body -- from any protocol, in any field, at any milestone.
- Accept a TLS key log, a private key, or any other decryption material.
- Fetch a certificate, an intermediate, an OCSP response or a CRL.
- Report a handshake as cryptographically verified.
- Apply a remediation, change a configuration, or act on a finding.
- Predict what a score would become after a fix.
- Present a project-defined weight or band as a validated industry benchmark.
- Infer attack intent from a weak configuration.
- Merge two observed endpoints into one because they share a certificate, a
  key, a name or a configuration.
- Report a parameter missing from a capture as having changed.
- Invent a timestamp, or substitute a file modification time for a capture one.
- Claim that unobserved sessions, hosts or users are affected -- or unaffected.
- Let a model's output modify an observation, a finding or a score.
- Present a model score as a calibrated probability.
- Report a rare configuration as dangerous because it is rare.
- Produce a prediction for a session whose evidence is insufficient.
- Treat an unavailable observation as either a pass or a finding.
