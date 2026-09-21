# ML feature schema

| | |
|---|---|
| **feature_schema_version** | `smsfeat/1` |
| **columns** | 93 |
| **source** | M1–M5 observations only |

A model trained under one schema version refuses to load against another. The
columns would not line up, and a silently misaligned model is worse than none.

## Three rules

**A code point is a name, not a magnitude.** TLS 1.2 is `0x0303` and TLS 1.3 is
`0x0304`, but the difference between them is not 1, and a cipher suite's
identifier says nothing about its strength. Every protocol identifier is
one-hot encoded. Feeding the raw integers to a model would invite it to learn
an ordering that does not exist.

**Missing is a category, and it has reasons.** A certificate absent from a TLS
1.3 session is `NOT_AVAILABLE` — the protocol encrypts it. A certificate absent
from a truncated TLS 1.2 session is `UNKNOWN` — it may well have been sent.
Collapsing both to zero would teach the model that TLS 1.3 servers have no
certificate.

**Incomplete evidence is not an observation.** A session showing no negotiation
has fewer features, and a naive detector would find it unusual for exactly that
reason — reporting the capture's shortcomings as the server's.

## Categorical features

One-hot encoded against a frozen vocabulary. Order is part of the schema.

| Feature | Vocabulary | Provenance |
|---|---|---|
| `tls_version` | TLS 1.0/1.1/1.2/1.3, OTHER, MISSING | `tls.version.selected_version` |
| `cipher_encryption` | AES-128/256-GCM, ChaCha20, AES-128/256-CBC, 3DES, RC4, NULL, OTHER, MISSING | `tls.cipher_suite` registry decomposition |
| `cipher_key_exchange` | ECDHE, DHE, RSA, PSK, ECDH, OTHER, MISSING | as above |
| `cipher_authentication` | ECDSA, RSA, PSK, ANON, OTHER, MISSING | as above |
| `cipher_mac` | SHA1, SHA256, SHA384, OTHER, MISSING | as above |
| `key_exchange_group` | x25519, secp256r1, secp384r1, ffdhe2048, OTHER, MISSING | `tls.key_exchange.selected_group` |
| `cert_key_algorithm` | RSA, EC, Ed25519, Ed448, DSA, OTHER, MISSING | `certificates[0].public_key.algorithm` |
| `cert_signature_hash` | sha256/384/512, sha1, OTHER, MISSING | `certificates[0].signature_hash_algorithm` |
| `entry_point` | IMPLICIT, STARTTLS, UNKNOWN, OTHER, MISSING | `tls.entry_point` |
| `handshake_state` | complete, server-hello, client-hello-only, none, OTHER, MISSING | `tls.handshake_state` |
| `protocol_detection` | CONFIRMED, PROBABLE, PORT_HINT, UNKNOWN, OTHER, MISSING | `protocol.detection.status` |
| `certificate_absence_reason` | OBSERVED, UNKNOWN, NOT_AVAILABLE, NOT_APPLICABLE | derived |
| `group_absence_reason` | as above | derived |

### The absence vocabulary

| Reason | Meaning |
|---|---|
| `OBSERVED` | Present in the capture. |
| `UNKNOWN` | The capture could have shown it and did not. |
| `NOT_AVAILABLE` | Passive capture can never show it for this session — a TLS 1.3 certificate. |
| `NOT_APPLICABLE` | The concept does not apply — a named group for a static-RSA suite. |

## Boolean features

`cipher_is_aead`, `forward_secrecy_observed`, `certificate_observed`,
`client_offered_tls13`, `sni_present`.

`sni_present` records **presence only, never the value**: whether a client sent
a name is a protocol observation; which name it sent is an identity.

## Numeric features

Each paired with an explicit `*_missing` indicator, so a missing value is never
mistaken for a small one.

| Feature | Scale | Provenance |
|---|---|---|
| `cert_key_bits` | 4096 | `certificates[0].public_key.size_bits` |
| `cert_lifetime_days` | 3650 | `certificates[0]` validity dates |
| `offered_suite_count` | 32 | `tls.cipher_suite.offered`, GREASE removed |
| `offered_version_count` | 4 | `tls.version.offered_versions`, GREASE removed |
| `evidence_completeness` | 1 | derived: fraction of core observations present |

Scales are **hand-set constants**, not fitted. A scaler fitted on the full
dataset would carry test-split information into training; a fixed divisor
cannot.

When a numeric value is missing the column is `0.0` **and** the indicator is
`1.0`. The model can tell the two apart because the indicator carries it.

## Eligibility

A session needs an observed **negotiated version and cipher suite**. Without
both there was no observed negotiation, and the session is
`ML_NOT_EVALUABLE`: not scored, not counted, not guessed at.

In this dataset 96 of 608 sessions fall below the floor. Reporting them as
anomalous would be reporting our own blind spots as the server's problem.

## Prohibited inputs

Excluded deliberately, and asserted against in `tests/test_ml.py`:

| Excluded | Why |
|---|---|
| File names, capture hashes, session ids, finding ids | Identifiers, not evidence |
| M4 scores, severities, rule outcomes, policy labels | The model would learn to imitate the rule engine |
| Split assignments, family and scenario names | Direct target leakage |
| IP addresses, host names, SNI values, certificate subjects and issuers | Memorising training entities, passed off as generalisation |
| Fingerprint digests as numbers | A hash has no magnitude. Using one as a quantity is numerology |

The *structure* of a fingerprint — how many components were observed — is
informative and is used, via `evidence_completeness`. The digest is not.

## Explanations

Every feature carries its provenance string, so an explanation in a report
names the M1–M5 field it came from. Explanations report how often a value
occurred in the training reference population:

> `TLS 1.0` occurred in 5.7% of the 246-session training reference population.

That is a frequency, not a cause. Neither a contingency table nor a tree
ensemble's feature importance establishes causation, and no explanation in this
system claims it does.
