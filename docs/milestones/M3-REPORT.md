# M3 milestone report

- **Project:** SecureMailScope — SIH26159
- **Date:** 2026-09-21
- **Milestone:** M3 — TLS reconstruction, cryptographic extraction and X.509 intelligence
- **Baseline (M2):** `d217c29a339b7cac6dedd291300430a6800067ca`
- **Result:** **COMPLETE** — all 14 acceptance gates pass. Gate 14's TShark
  cross-check is written but **NOT_VERIFIED** in this environment; see §10.2.

---

## 1. Pre-implementation verification

### The reported Git discrepancy: there is none

The directive listed two SHAs and asked them to be reconciled. They are both
correct and describe two different things:

| SHA | What it is | Contents |
|---|---|---|
| `49bdb12b764e2a1d3f0aef8faf4fe407b0105c30` | The M2 **implementation** commit | 72 files, +9,376/−112 |
| `d217c29a339b7cac6dedd291300430a6800067ca` | The M2 **report** commit, HEAD | `docs/milestones/M2-REPORT.md` only, +5/−3 |

`git show --stat d217c29` confirms it touches exactly one file and exists to
record the implementation commit's SHA and the push verification inside the
report — a report cannot contain its own hash, so the SHA it documents had to
be written afterwards. Local HEAD and remote HEAD were both `d217c29` before
any M3 work began, and the working tree was clean with zero untracked files.
No history was rewritten and no force-push was performed.

### Baseline verified

| Claim | Actual |
|---|---|
| Branch | `main` |
| Local HEAD == remote HEAD | both `d217c29a339b7cac6dedd291300430a6800067ca` |
| Working tree | clean, 0 untracked |
| Test suite | `351 passed, 20 skipped` |
| Lint / types | ruff clean; mypy clean over 53 files |

### Environment findings

| Tool | Status | Consequence |
|---|---|---|
| `cryptography` | **not installed** | Installed and promoted from an optional extra to a runtime dependency |
| `tshark` | **not installed** | Cross-check tests written but never observed passing (§10.2) |
| OpenSSL 3.6.4 | available | Used to produce real handshakes for fixtures, entirely in memory |

---

## 2. Files created and modified

110 files changed, +10,961 / −106 (50 added, 60 modified).

### New engine modules

| Module | Purpose |
|---|---|
| `models/tls.py` | Record/handshake/version/cipher/key-exchange/forward-secrecy contracts |
| `models/certificates.py` | Certificate observation, the five validation checks, trust-store identity |
| `tls/wire.py` | Bounded reader: every length in TLS is attacker-controlled |
| `tls/registry.py` | Cipher suites, named groups, signature schemes, versions, GREASE |
| `tls/records.py` | Record framing over reconstructed TCP payload |
| `tls/extensions.py` | Hello extensions, context-sensitive per RFC 8446 §4.2 |
| `tls/handshake.py` | Message reassembly across records; hello/certificate/SKE/alert parsing |
| `tls/keyexchange.py` | TLS 1.2 (from the suite) vs TLS 1.3 (from key_share) |
| `tls/forward_secrecy.py` | Classification with criteria and RFC citations |
| `tls/analyzer.py` | Orchestration and the encryption boundary |
| `certificates/parse.py` | DER decoding into provenanced observations |
| `certificates/policy.py` | Documented, RFC-cited algorithm notes (no scores) |
| `certificates/truststore.py` | Explicitly configured anchors, identified by digest |
| `certificates/validate.py` | The five independent checks |

### New test-support modules

`testing/certs.py` (synthetic CA), `testing/live_tls.py` (in-memory OpenSSL
handshakes), `testing/tls_messages.py` (byte-exact RFC message builders),
`testing/tls_fixtures.py` and `testing/tls_fixtures_synthetic.py` (the 27 M3
fixtures), `tls/messages_helper.py`.

### New tests

`tests/test_tls.py` (270), `tests/test_tls_validation.py` (27),
`tests/test_tls_wire.py` (25), plus 4 CLI cases and 4 TShark cross-checks.

### Modified

`models/analysis.py` (schema 1.2.0, 6 new stages, 2 new result fields),
`models/protocol.py` (4 optional fields on `TLSRecordObservation`),
`models/evidence.py` (+21 warning codes), `config.py` (+11 settings),
`pipeline.py`, `cli.py`, `reporting/json_report.py`,
`protocols/framing.py` (classifiers made public and shared),
`testing/{fixtures,manifest,dialogue}.py`, `pyproject.toml`, five docs, and
the M1/M2 test files noted in §11.

No file outside this project directory was created or modified.

---

## 3. Features implemented

### TLS record layer

Framed directly over the M1 reassembly output, so it inherits that layer's gap
and ambiguity handling rather than re-implementing it. Handles records split
across TCP segments, several records in one segment, partial headers, partial
bodies, retransmitted data and truncated captures.

**The governing rule: after a hole, record alignment is unknowable.** A TLS
record stream is self-delimiting only if every preceding byte was read, so
framing stops at the gap (`ALIGNMENT_LOST_AT_GAP`) instead of resynchronising
on a guess. Records overlapping an unresolved TCP overlap conflict are framed
and reported but never parsed.

All four content types are handled, per direction, with configurable record
count and size ceilings. Every record observation carries the packets that
carried it.

### Handshake reassembly

Records and handshake messages are independent framings: one message may span
several records and one record may carry several messages. Both work, and the
buffer is re-parsed as each record arrives so a message that was incomplete
becomes complete when the rest lands. Every message records which records
carried it and which packets those were.

`ClientHello`, `ServerHello`, `HelloRetryRequest`, `Certificate`,
`ServerKeyExchange`, `ServerHelloDone`, `ClientKeyExchange`,
`NewSessionTicket` and alerts are parsed where plaintext; unknown types are
reported numerically with a limitation.

### The encryption boundary

| Protocol | Boundary | Reference |
|---|---|---|
| TLS 1.2 | The ChangeCipherSpec sent by that direction | RFC 5246 §7.1 |
| TLS 1.3 | Immediately after the ServerHello, both directions | RFC 8446 §2 |

A TLS 1.3 compatibility ChangeCipherSpec (RFC 8446 §D.4) is recognised as such
and **never** read as evidence of a TLS 1.2 handshake. `application_data`
records in a TLS 1.3 session carry encrypted handshake messages and are never
parsed as plaintext. Nothing is decrypted, and no key log or private key is
loaded — there is no code path that accepts one.

### Version identification

TLS 1.3 is identified from the ServerHello `supported_versions` extension
(RFC 8446 §4.2.1), never from `legacy_version` (which reads 0x0303 by design)
and never from the record-layer version. `selected_source` records which was
used. A ClientHello without a ServerHello yields offered versions and
`selected_version: null` — the highest offered version is never promoted.
GREASE values (RFC 8701) are marked, and malformed extensions are recorded and
skipped rather than raising.

### Cipher suites

Offered and selected are separate fields. The registry names its source and
revision in every report. Unknown code points are reported by their exact
numeric value with `known: false`; nothing is inferred from a name's shape.

For TLS 1.2 the suite is decomposed into key exchange, authentication, cipher
and MAC. For TLS 1.3 `decomposition_applicable` is `false` and those fields
stay empty, because RFC 8446 §B.4 suites encode only an AEAD and a hash.

### Key exchange

TLS 1.2: family from the negotiated suite; group and ephemeral public-key
length from the observed ServerKeyExchange. When no ServerKeyExchange was
captured, the group is **not** inferred from the client's offered groups.

TLS 1.3: `supported_groups`, `key_share` and the pre-shared-key extensions.
The server's selected group comes from its `key_share`. PSK-only and PSK+DHE
are distinguished. HelloRetryRequest is recognised by its special random
(RFC 8446 §4.1.3) and is not treated as a completed negotiation.

### Forward secrecy

A dedicated module producing seven statuses, each with a `criteria` sentence
naming the rule and the evidence. `EPHEMERAL_OBSERVED` requires the ephemeral
key material to have been *seen*; `CAPABLE_NEGOTIATED` is the weaker claim.
TLS 1.3 is not assumed forward secret: a PSK-only resumption is `PSK_ONLY`.

### Certificates

Extracted from plaintext Certificate messages (both TLS 1.2 and TLS 1.3
framings are supported, though only the former is observable). Fingerprint,
subject, issuer, serial, validity window, public key algorithm and size,
curve, signature algorithm and hash, SANs, BasicConstraints, KeyUsage,
ExtendedKeyUsage and chain position are all extracted. RSA, EC, Ed25519,
Ed448 and DSA are described; **Ed25519 and Ed448 report no bit length**,
because a variable key size is not a meaningful description of them.
Certificate count and size are bounded, and a malformed length fails safely
without allocating.

### Certificate validation — five independent checks

| Check | Behaviour |
|---|---|
| `certificate_observed` | Was one visible at all |
| `validity_dates_checked` | Against the **capture timestamp**; optional labelled current-time assessment |
| `chain_verified` | Against an explicitly configured PEM trust store only |
| `hostname_verified` | Against an explicitly supplied identity only |
| `revocation_checked` | Always `NOT_AVAILABLE`, with the reason |

Chain and hostname are isolated from each other because the installed library
exposes them together: the chain check uses the leaf's own first DNS SAN as
the subject so the name always matches, and the hostname check trusts the
presented chain so the path always succeeds. This deviation from a single API
call is documented in the module; the alternative — a hand-written RFC 6125
matcher — would be a second unverified implementation of the rule that matters
most.

There is **no default trust store** and **no default reference identity**. The
destination IP is never used as one. An observed SNI is recorded as evidence
and becomes a reference identity only on explicit opt-in. A missing
intermediate is distinguished from a chain built and found invalid. The trust
store is identified by a digest of its anchors' fingerprints, not by a path.

---

## 4. Test results

Every command was executed; output is verbatim.

```
$ .venv/bin/python -m pytest -q
677 passed, 24 skipped in 22.25s

$ .venv/bin/python -m pytest -q -m "not integration"
635 passed, 24 skipped, 17 deselected in 3.76s

$ .venv/bin/python -m pytest -q -m integration
17 passed, 659 deselected in 19.00s

$ .venv/bin/ruff check src tests scripts
All checks passed!

$ .venv/bin/mypy
Success: no issues found in 73 source files

$ .venv/bin/python scripts/generate_fixtures.py
64 fixtures -> tests/fixtures/generated
64 manifests -> tests/fixtures/manifests
```

**677 passed, 0 failed.** The 24 skips are all intentional:

| Skips | Reason |
|---|---|
| 15 | Credential-absence test on protocol fixtures that carry no credentials |
| 9 | TShark cross-checks — opt-in, and TShark is not installed here |

### Coverage by file

| File | Tests | Scope |
|---|---|---|
| `test_tls.py` | 270 | M3 manifest-driven: records, messages, version, cipher, key exchange, forward secrecy, certificates, validation |
| `test_protocols.py` | 140 | M2 manifest-driven |
| `test_ingestion.py` | 66 | M1 ingestion and limits |
| `test_reassembly.py` | 47 | M1 reconstruction |
| `test_protocol_reader.py` | 37 | M2 reader, redaction, framing |
| `test_tls_validation.py` | 27 | Chain/hostname under different configs, capture-time dates, TLS 1.3 limits, bounds, no-socket |
| `test_tls_wire.py` | 25 | Bounded reader, registry, extensions, message round-trips, X.509 decoding |
| `test_cli.py` | 17 | End-to-end subprocess, including 4 new M3 cases |
| `test_protocol_behaviour.py` | 16 | M2 targeted behaviour |
| `test_formats.py` | 13 | Magic-number detection |
| `test_sessions.py` / `test_seqspace.py` | 10 / 10 | M1 flows and wraparound |
| `test_tshark_crosscheck.py` | 9 | Opt-in cross-validation (all skipped) |
| `test_report.py` | 8 | JSON contract and honesty |
| `test_passive.py` | 6 | No socket, no subprocess, ARP/NDP blocked |

### Directive §16 coverage

| Required area | Where |
|---|---|
| Record reconstruction | `test_tls.py` (T_I), `test_records_carry_provenance` |
| Handshake fragmentation | `test_tls.py` (T_J, T_K) |
| Version negotiation | `test_version_negotiation_matches_manifest` |
| TLS 1.3 legacy-version handling | `test_tls13_version_comes_from_the_extension_not_legacy_version` |
| Cipher-suite extraction | `test_cipher_suite_matches_manifest`, `test_tls_wire.py` |
| Key-exchange interpretation | `test_key_exchange_and_forward_secrecy_match_manifest` |
| Certificate extraction | `test_certificates_match_manifest` |
| Capture-time validation | 4 date tests in `test_tls_validation.py` |
| Chain-verification outcomes | 5 chain tests (none / configured / self-signed / incomplete / missing file) |
| Hostname-verification outcomes | 4 hostname tests (none / match / wildcard / mismatch) + independence |
| Missing evidence | T_G, T_H, T_L, T_M, T_X |
| TLS 1.3 encrypted certificate | `test_tls13_certificate_is_unavailable_not_missing` |
| Provenance correctness | `test_handshake_messages_match_manifest`, `test_records_carry_provenance` |
| Malformed input | T_N, T_Y, `test_tls_wire.py` (5 tests) |
| Memory limits | 4 bound tests in `test_tls_validation.py` |
| No external network access | `test_tls_analysis_opens_no_socket` |

---

## 5. Fixture inventory

64 total: 17 (M1) + 20 (M2) + **27 new (M3)**.

### Locally negotiated — real OpenSSL, in memory (6)

Produced through `ssl.MemoryBIO` pairs: no socket, no capture privilege, and
the analyzer is never involved. Not byte-reproducible, so their manifests
record **no capture hash** and assert negotiated parameters instead.

| Fixture | Scenario |
|---|---|
| T_A | Complete TLS 1.2 handshake, certificate extracted |
| T_B | TLS 1.2 ECDHE on the SMTPS port |
| T_C | TLS 1.2 **static RSA** (`kRSA` at `@SECLEVEL=0`), no forward secrecy |
| T_D | TLS 1.3 negotiation |
| T_E | TLS 1.3 encrypted Certificate message |
| T_F | TLS 1.3 PSK resumption (two handshakes sharing one context) |

### Synthetically constructed — byte-exact RFC structures (21)

The only way to produce a record split at a chosen boundary, a truncated
record, a hole mid-handshake, or bytes two segments disagree about.

| Fixture | Scenario |
|---|---|
| T_G | ClientHello without ServerHello |
| T_H | ServerHello without ClientHello |
| T_I | One record across three TCP segments |
| T_J | One handshake message across several records |
| T_K | Four messages in one record |
| T_L | Truncated record |
| T_M | Missing TCP segment during the handshake |
| T_N | Conflicting overlapping bytes |
| T_O | Expired at capture time |
| T_P | Not yet valid at capture time |
| T_Q | Self-signed certificate |
| T_R | Valid chain to the synthetic root |
| T_S | Incomplete chain (intermediate omitted) |
| T_T | Hostname match, wildcard and mismatch |
| T_U | SNI present but not an authorised expectation |
| T_V | Implicit TLS on the POP3S port |
| T_W | STARTTLS then an observable handshake |
| T_X | Upgrade accepted, ClientHello never captured |
| T_Y | Malformed certificate lengths |
| T_Z | Fatal alert, aborted negotiation |
| T_HRR | HelloRetryRequest + TLS 1.3 compatibility ChangeCipherSpec |

### Certificates and keys are never committed

The synthetic CA generates a fresh key pair in-process at build time.
Certificates and keys are written only into temporary directories; the public
root is emitted next to the generated captures (also gitignored) so chain
verification can be demonstrated. **No private key material exists anywhere in
the repository** — only the code that generates it. A staged-content scan for
`BEGIN * PRIVATE KEY` returns zero matches.

---

## 6. TLS 1.2 analysis example

```
$ securemailscope analyze tests/fixtures/generated/t_a_tls12_complete_handshake.pcap \
    --trust-store tests/fixtures/generated/synthetic-root.pem \
    --expected-server-identity mail.example.invalid -o out/m3-tls12.json

capture id   : sha256:4bb44fb32659bebbd932eee59731d44731fef7f0ee325f825f632d3ac6b2d667
packets      : 7 (7 TCP, 0 non-IP, 0 non-TCP, 0 malformed)
sessions     : 1 (complete 0, partial 1, midstream 0, truncated 0)
reconstructed: 1208 bytes, 0 gap(s), 0 overlap conflict(s)
implicit tls : 1 session(s) TLS-framed from the first byte (inner protocol not determinable)
tls sessions : 1 (1 implicit, 0 via STARTTLS); TLS 1.3 0, TLS 1.2 1, legacy 0
certificates : 1 observed, 0 encrypted under TLS 1.3; 1 chain-verified, 1 hostname-verified
forward sec. : 1 with an ephemeral exchange, 0 with static RSA
not verified : handshake completion (needs key material) and revocation (no OCSP/CRL fetching by design)
  sess-45dea38eae8ea360  192.0.2.10:49152 -> 198.51.100.25:993  PARTIAL *  c2s=259B s2c=950B  [IMAP/PORT_HINT]
      TLS: TLS 1.2  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  kx=ECDHE  fs=EPHEMERAL_OBSERVED  cert=OBSERVED
```

Note the protocol label: the session is `IMAP/PORT_HINT`, not confirmed IMAP.
It is TLS from the first byte, so the email protocol inside is not observable —
port 993 is a convention, not evidence.

## 7. TLS 1.3 analysis example

```
$ securemailscope analyze tests/fixtures/generated/t_d_tls13_negotiation.pcap \
    --trust-store tests/fixtures/generated/synthetic-root.pem \
    --expected-server-identity mail.example.invalid -o out/m3-tls13.json

tls sessions : 1 (1 implicit, 0 via STARTTLS); TLS 1.3 1, TLS 1.2 0, legacy 0
certificates : 0 observed, 1 encrypted under TLS 1.3; 0 chain-verified, 0 hostname-verified
forward sec. : 1 with an ephemeral exchange, 0 with static RSA
  sess-184b877521f7eb82  192.0.2.10:49152 -> 198.51.100.25:993  PARTIAL *  c2s=1558B s2c=2464B  [IMAP/PORT_HINT]
      TLS: TLS 1.3  TLS_AES_256_GCM_SHA384  kx=EPHEMERAL  fs=EPHEMERAL_OBSERVED  cert=ENCRYPTED_TLS13
```

Three things this demonstrates:

1. **The version came from the extension.** `legacy_version` reads 0x0303 in
   that ServerHello; the report records `selected_source:
   SUPPORTED_VERSIONS_EXTENSION` and says so in its limitations.
2. **The key exchange did not come from the suite.** `TLS_AES_256_GCM_SHA384`
   encodes no key exchange, so `decomposition_applicable` is `false` and the
   method comes from `key_share`. The local OpenSSL selected
   **X25519MLKEM768**, a post-quantum hybrid that is neither ECDHE nor FFDHE,
   so the method is the honest generic `EPHEMERAL` rather than being forced
   into a classical family.
3. **The certificate is unavailable, not missing.** Even with a trust store
   configured, `chain_verified` stays `NOT_AVAILABLE` — there is nothing to
   verify.

## 8. Certificate validation example

With a trust store and an expected identity supplied:

```json
"validation": {
  "certificate_observed":   {"status": "PASSED",
     "explanation": "1 certificate(s) were observed in a plaintext Certificate message and decoded."},
  "validity_dates_checked": {"status": "PASSED", "assessment_mode": "CAPTURE_TIME",
     "reference_time": "2026-06-01T12:00:00.004000Z",
     "explanation": "The end-entity certificate was within its validity window at the capture timestamp (2026-06-01T12:00:00.004000+00:00)."},
  "chain_verified":         {"status": "PASSED", "assessment_mode": "CAPTURE_TIME",
     "explanation": "The certificate chains to a configured trust anchor at the capture timestamp ...; the validated path is 2 certificate(s) long.",
     "limitations": ["No revocation check was performed. ... A successful chain verification is not evidence that a certificate has not been revoked."]},
  "hostname_verified":      {"status": "PASSED",
     "explanation": "The certificate names the expected identity 'mail.example.invalid'.",
     "limitations": ["This check isolates the name question by trusting the presented chain; it says nothing about whether that chain is trustworthy."]},
  "revocation_checked":     {"status": "NOT_AVAILABLE",
     "explanation": "No revocation check was performed. SecureMailScope makes no network requests, so OCSP and CRL retrieval are out of scope by design. ..."}
}
```

Without those inputs the same capture reports `chain_verified:
NOT_AVAILABLE` ("SecureMailScope never falls back to a system trust store,
because a report must be able to name the anchors it used") and
`hostname_verified: NOT_AVAILABLE` ("The destination IP address is never used
as one, and an observed SNI value is the client's request rather than an
authorised expectation").

The independence is tested directly: a trusted chain with the wrong expected
name yields `chain_verified: PASSED` **and** `hostname_verified: FAILED`.

## 9. JSON evidence sample

```json
{
  "version": {
    "selected_version": {"value": 771, "hex_value": "0x0303", "name": "TLS 1.2", "known": true, "grease": false},
    "selected_source": "LEGACY_VERSION",
    "negotiation_status": "OBSERVED"
  },
  "cipher_suite": {
    "selected": {"value": 49195, "hex_value": "0xc02b",
                 "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "known": true},
    "decomposition_applicable": true,
    "key_exchange": "ECDHE", "authentication": "ECDSA",
    "encryption": "AES_128_GCM", "mac_or_prf": "SHA256", "aead": true,
    "registry_revision": "2026-09-21"
  },
  "key_exchange": {
    "method": "ECDHE", "method_source": "CIPHER_SUITE",
    "selected_group": {"value": 29, "hex_value": "0x001d", "name": "x25519", "known": true},
    "selected_group_source": "SERVER_KEY_EXCHANGE",
    "server_key_exchange_observed": true,
    "server_key_exchange_public_length": 32
  },
  "forward_secrecy": {
    "status": "EPHEMERAL_OBSERVED",
    "criteria": "RFC 4492 §5.4 / RFC 5246 §7.4.3: suite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 negotiates an ephemeral exchange, and a plaintext ServerKeyExchange carrying group x25519 was observed, so the ephemeral key material itself was on the wire.",
    "ephemeral_key_exchange_negotiated": true,
    "ephemeral_key_material_observed": true,
    "handshake_completion_observable": false,
    "handshake_completion_explanation": "Handshake completion is not observable passively. Verifying a Finished message requires the handshake traffic keys, which a capture does not contain ...",
    "evidence_refs": [
      {"packet_number": 4, "timestamp": "2026-06-01T12:00:00.003000Z", "timestamp_ns": 1780315200003000000},
      {"packet_number": 5, "timestamp": "2026-06-01T12:00:00.004000Z", "timestamp_ns": 1780315200004000000}
    ]
  },
  "encryption_boundaries": [
    {"direction": "CLIENT_TO_SERVER", "stream_offset": 214, "reason": "TLS12_CHANGE_CIPHER_SPEC"},
    {"direction": "SERVER_TO_CLIENT", "stream_offset": 903, "reason": "TLS12_CHANGE_CIPHER_SPEC"}
  ],
  "certificates": {
    "visibility": "OBSERVED",
    "certificates": [{
      "chain_position": 0,
      "sha256_fingerprint": "9c61f3c4e27486d5d259b44d0045d9b4bf172b5d6a1250d02fd543c2a6a02131",
      "der_size_bytes": 496, "version": "v3",
      "subject": "CN=mail.example.invalid",
      "issuer": "CN=SecureMailScope Synthetic Test Root",
      "serial_number": "64",
      "not_valid_before": "2026-05-02T12:00:00Z", "not_valid_after": "2027-06-01T12:00:00Z",
      "public_key": {"algorithm": "EC", "size_bits": 256, "curve": "secp256r1", "supported": true},
      "signature_algorithm": "ecdsa-with-SHA256", "signature_hash_algorithm": "sha256",
      "subject_alternative_names": ["DNS:mail.example.invalid", "DNS:*.alt.example.invalid"],
      "basic_constraints_ca": false,
      "key_usage": ["digital_signature", "key_encipherment"],
      "extended_key_usage": ["serverAuth"],
      "is_self_issued": false,
      "stream_offset": 73, "direction": "SERVER_TO_CLIENT",
      "packet_refs": [{"packet_number": 5, "timestamp": "2026-06-01T12:00:00.004000Z",
                       "timestamp_ns": 1780315200004000000}],
      "limitations": ["These are the certificate's own claims. Whether they are trustworthy is reported separately under validation."]
    }]
  }
}
```

No raw DER or PEM appears anywhere: the fingerprint and byte size stand in
for the certificate, and a test asserts `BEGIN CERTIFICATE` never reaches a
report.

---

## 10. Known limitations

### 10.1 Permanent limits of passive analysis

- **Handshake completion is never verified.** Confirming a Finished message
  needs the traffic keys. `handshake_completion_observable` is `false` for
  every session, and `handshakes_cryptographically_verified` is `0`.
- **TLS 1.3 certificates cannot be recovered.** They are encrypted under
  handshake traffic keys (RFC 8446 §2). Reported `ENCRYPTED_TLS13` with an
  explanation, never as a failure.
- **Revocation is never checked.** No OCSP, no CRL, no network requests at
  all. A verified chain is not evidence of non-revocation, and the chain
  check's own limitations say so.
- **Record alignment is lost at a hole.** Framing stops rather than guessing.
- **Ambiguous bytes are never parsed**, only framed and reported.

### 10.2 NOT_VERIFIED: the TShark cross-check

The directive asks for comparison against an independent offline reference.
TShark is **not installed** in this environment, so the four new TLS
cross-checks (version, cipher suite, certificate presence, TLS 1.3
invisibility) are written, wired and skip cleanly — but have **never been
observed passing**. No claim of agreement with TShark is made anywhere in this
repository.

To run them: install TShark and `SECUREMAILSCOPE_TSHARK=1 make test`. Any
deviation found must be recorded here rather than worked around.

### 10.3 Environment-dependent fixtures

- Live fixtures depend on the local OpenSSL's defaults. The TLS 1.3 fixtures
  assert the suite **OpenSSL itself reports negotiating**, which is an
  independent cross-check on our parse of the ServerHello rather than a copy
  of our own output — but a different build may negotiate a different suite or
  group.
- Static RSA (T_C) is exercised only while the local OpenSSL still offers
  `kRSA` at `@SECLEVEL=0`. The generator detects that and falls back to a
  constructed handshake, recording which path it took in the fixture's
  `generation` field.
- Live and certificate-bearing fixtures are **not byte-reproducible** (ECDSA
  signatures and TLS randoms are randomised), so their manifests record no
  capture hash. Structural fixtures remain byte-exact and do assert one.

### 10.4 Deliberate deviations

- **Chain and hostname are isolated by construction**, not by two separate
  library calls, because the installed API only exposes them together. The
  technique and its reasoning are documented in `certificates/validate.py`.
- **The trust anchor profile rejects Ed25519 CAs.** The synthetic CA therefore
  signs with ECDSA P-256, which is why certificate fixtures are not
  byte-reproducible. Ed25519 *leaf* keys are still exercised.

### 10.5 Not implemented

Certificate transparency, OCSP stapling, CAA, DANE/TLSA; session-ticket
contents; QUIC and DTLS; renegotiation and post-handshake authentication;
compression and 0-RTT payload; IP fragment reassembly (M1); per-OS reassembly
policy emulation (M1). No performance measurement has been taken and no
throughput figure is claimed.

---

## 11. M1 and M2 regression status

**No regression.** All 351 M1/M2 tests still pass, and no M1 or M2 behaviour
changed. The M1 TCP models (`models/tcp.py`) and the M2 protocol models are
untouched.

### Deliberate test updates (6)

The schema moved from 1.1.0 to 1.2.0 and six stage statuses changed, so six
assertions had to change with them. Each is a correction toward the new truth,
not a weakening:

| Test | Change |
|---|---|
| `test_report.py::test_report_declares_stage_status_honestly` | `TLS_RECORD_FRAMING` PARTIAL→IMPLEMENTED, `TLS_ANALYSIS` NOT_IMPLEMENTED→PARTIAL, schema 1.2.0; **added** assertions that a TLS-free capture reports `tls: []` and both cryptographic counters at 0 |
| `test_cli.py::test_status_reports_unimplemented_stages` | `TLS_ANALYSIS` → PARTIAL; **added** `CERTIFICATE_REVOCATION` and `RISK_ASSESSMENT` must stay NOT_IMPLEMENTED |
| `test_cli.py::test_status_reports_m2_stages` | Same stage corrections |
| `test_cli.py::test_analyze_reports_starttls_state` | Schema 1.2.0; the M2 summary line was replaced by the richer M3 one, which still states plainly that completion and revocation are not verified |
| `test_cli.py::test_fixture_generation_is_reproducible` | Restricted to fixtures that **declare** byte reproducibility |
| `test_cli.py::test_committed_manifests_match_regenerated_ones` | Ignores volatile fields for non-reproducible fixtures |

### Schema evolution

`REPORT_SCHEMA_VERSION` 1.1.0 → **1.2.0**, backward compatible:

- Added: top-level `tls` array and `tls_inventory` object.
- Added: four optional fields on `TLSRecordObservation` (`record_index`,
  `encrypted`, `body_interpreted`, `ambiguous`).
- Added: six `stage_status` members; changed two values.
- Changed: `capture_sha256` and `file_size_bytes` in fixture *manifests* are
  now nullable, so a non-reproducible fixture records no misleading hash.
  This is a test-support format, not the report schema.
- **Unchanged:** every 1.0.0 and 1.1.0 report field keeps its name, type and
  meaning. An older consumer can ignore the new keys.

### Bugs found and fixed during M3

Four, all caught by the fixtures or by mypy before commit:

1. **Incremental handshake reassembly dropped completed messages.** A message
   parsed as incomplete when one record arrived was never re-processed once
   the rest landed, so a Certificate spanning records was lost (fixture T_J).
   The buffer is now re-parsed on each append and a message is handled once,
   when it becomes complete.
2. **Ambiguous records were parsed.** Bytes from an unresolved TCP overlap
   conflict reached the handshake parser (fixture T_N). They are now framed
   and reported but never interpreted.
3. **A TLS 1.3 compatibility ChangeCipherSpec was read as a TLS 1.2 signal**
   (fixture T_HRR), which is exactly what RFC 8446 §D.4 warns against.
4. **Record index collision between directions.** Indices restart per
   direction, so a `set[int]` marked the client's encrypted Finished as
   "interpreted" because the server's record 3 was. Now keyed by
   `(direction, index)`.

A fifth, smaller one: when a configured limit stopped certificate decoding,
the note explaining *why* was discarded, leaving an unexplained
`PARSE_FAILED`. The reason is now carried through.

---

## 12. Acceptance gates

| # | Gate | Status |
|---|---|---|
| 1 | TLS records reconstruct correctly from TCP payload runs | **PASS** (T_I, T_K, `test_records_carry_provenance`) |
| 2 | Fragmented handshake messages reconstruct correctly | **PASS** (T_J) |
| 3 | TLS 1.2 and TLS 1.3 versions distinguished correctly | **PASS** (T_A vs T_D; extension-sourced) |
| 4 | Selected cipher suites extracted accurately | **PASS** (T_A, T_C, T_D) |
| 5 | Observable key-exchange details identified | **PASS** (T_A group from SKE; T_D from key_share) |
| 6 | TLS 1.2 certificates extracted from real handshake evidence | **PASS** (T_A, T_B, T_C — live OpenSSL) |
| 7 | Certificate dates, public keys and signatures analysed | **PASS** (T_O, T_P, `test_tls_wire.py`) |
| 8 | Chain and hostname validation separately implemented and tested | **PASS** (9 tests incl. independence) |
| 9 | TLS 1.3 encrypted certificate limitations represented honestly | **PASS** (T_E) |
| 10 | Forward-secrecy observations use defensible criteria | **PASS** (criteria asserted non-empty on every fixture) |
| 11 | All findings retain accurate packet provenance | **PASS** (records, messages, certificates) |
| 12 | Existing M1 and M2 regressions pass | **PASS** (351/351) |
| 13 | Security and resource limits remain enforced | **PASS** (11 new settings; 4 bound tests) |
| 14 | The CLI produces actual structured cryptographic evidence | **PASS** — with the TShark comparison **NOT_VERIFIED** (§10.2) |

---

## 13. Readiness for M4

M4 turns observations into findings. M3 was built so that it receives facts
with their evidence attached rather than having to re-derive them:

1. **Every observation carries provenance.** Records, handshake messages and
   certificates all name the packets and offsets they came from, so a finding
   can cite frames.
2. **Statuses already separate what is known from what is not.**
   `ForwardSecrecyStatus`, `CertificateVisibility` and `ValidationStatus` each
   distinguish "bad", "good", "not determinable" and "not attempted", which is
   the distinction a score must not blur.
3. **Criteria are already stated.** `ForwardSecrecyAssessment.criteria` and
   every `ValidationCheck.explanation` say why, so a finding can inherit the
   reasoning instead of inventing one.
4. **Algorithm facts are separated from judgements.**
   `certificates/policy.py` emits RFC-cited factual notes with no score
   attached; M4 supplies the weighting.
5. **The honesty constants are in place.** A scoring engine cannot
   accidentally treat an unverified handshake or an unchecked revocation as a
   pass, because those fields are explicit and asserted.

Recommended M4 scope: a findings model citing observations; a documented,
versioned rule set (plaintext authentication, absent or rejected STARTTLS,
static RSA, legacy versions, expired or untrusted certificates, weak keys);
severity that degrades honestly when evidence is `UNKNOWN` or `NOT_AVAILABLE`;
and an explainability requirement that every finding names the observations
and their evidence statuses.

**M4 was not started.** No scoring, no findings, no correlation and no ML
exist in this milestone.
