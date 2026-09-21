# Cryptographic fingerprinting

## What a fingerprint is

A **versioned digest of the cryptographic parameters a server was observed to
choose**, plus the certificate it presented. It exists so that sessions with
the same configuration can be grouped without comparing every session with
every other one.

## What a fingerprint is not

It is **not an identity**. Two servers installed from the same distribution
package produce the same fingerprint on day one, and they are not the same
machine. Nothing in this system treats a fingerprint match as proof that two
endpoints are the same server, and the limitation is carried in the report
beside every fingerprint rather than left in this document.

## Algorithm version

```
smsfp/1
```

The version is the first line of the canonical form, so digests produced by
different algorithm versions cannot collide. Adding, removing or redefining any
component requires bumping it.

## Components

| Component | Source | Notes |
| --- | --- | --- |
| `tls_version` | `SERVER_SELECTED` | For TLS 1.3, read from `supported_versions`, never the legacy field. |
| `cipher_suite` | `SERVER_SELECTED` | What the server chose from what was offered. |
| `key_exchange_group` | `SERVER_SELECTED` | Where a named group was observable. |
| `alpn_selected` | `SERVER_SELECTED` | The protocol the server selected, if any. |
| `certificate_sha256` | `CERTIFICATE_OBSERVED` | SHA-256 over the end-entity DER. |
| `certificate_spki_sha256` | `CERTIFICATE_OBSERVED` | SHA-256 over the DER SubjectPublicKeyInfo. |
| `certificate_issuer` | `CERTIFICATE_OBSERVED` | The issuer distinguished name. |

### What is deliberately excluded

**Client offers.** A cipher suite the client *advertised* describes the client.
Including it would make the "server fingerprint" change whenever the client
changed, which is the exact confusion this milestone exists to prevent. A
test asserts that no component ever carries `CLIENT_OFFERED`.

**Source ports, packet timestamps and session identifiers.** These vary per
connection. Including any of them would make every session unique and the
fingerprint useless for grouping — which is the only thing it is for.

### Source vocabulary

`CLIENT_OFFERED`, `SERVER_SELECTED`, `CERTIFICATE_OBSERVED`, `INFERRED`,
`UNKNOWN`. A component that was not observed is recorded with source `UNKNOWN`
and `present=false`.

## Canonicalisation

One `name=value` per line, in the fixed component order, with the algorithm
version first:

```
version=smsfp/1
tls_version=TLS 1.2
cipher_suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
key_exchange_group=x25519
alpn_selected=<ABSENT>
certificate_sha256=ed128ed2827b480c...
certificate_spki_sha256=8ec9f17906a70376...
certificate_issuer=CN=SecureMailScope Synthetic Test Root
```

The digest is `sha256` of that string, truncated to 16 hex characters and
prefixed with the algorithm version. The canonical form is **published in the
report**, so any fingerprint can be recomputed by hand from what the report
contains. A test asserts exactly that.

### Why absences are written explicitly

`<ABSENT>` is a literal in the canonical form. Without it, a TLS 1.3 session —
which has no certificate components at all — could hash to the same value as a
TLS 1.2 session that happened to agree on everything else. Writing the absence
keeps an incomplete fingerprint from colliding with a complete one.

## Completeness

| Completeness | Meaning |
| --- | --- |
| `COMPLETE` | Every defined component was observed. |
| `PARTIAL` | The server's core selection was observed; something else was not. |
| `INSUFFICIENT` | No server selection was observed. Nothing may be concluded. |

The core is `tls_version` and `cipher_suite`: without them there was no
observed negotiation.

**A TLS 1.3 session is always at most `PARTIAL`.** The Certificate message is
encrypted, so no certificate component can exist without decryption material
this tool will never accept. That is not a fault in the capture and is not
reported as one — but neither is it allowed to look like a complete
fingerprint.

## Comparison

| Result | When |
| --- | --- |
| `EXACT_MATCH` | Identical digests **and** both sides `COMPLETE`. |
| `PARTIAL_AGREEMENT` | Everything present in both agrees; something is missing. |
| `CONFLICTING_COMPONENTS` | At least one component present in both differs. |
| `INSUFFICIENT_EVIDENCE` | One or both sides lack a server selection. |

Two TLS 1.3 sessions that agree on everything observable reach
`PARTIAL_AGREEMENT`, never `EXACT_MATCH`: the certificate components neither
of them could see might have differed. **Partial agreement is never treated as
proof that two endpoints are the same server**, and the comparison carries that
statement in its `limitations`.

## The configuration fingerprint

A second, narrower digest over the negotiated **settings** only —
`tls_version`, `cipher_suite`, `key_exchange_group`, `alpn_selected` — with the
certificate left out:

```
smsfp/1/cfg:<16 hex>
```

It exists because two servers can be configured identically and still present
different certificates, which is the normal case: a certificate names a host.
Including the certificate in a "same configuration" test would make it fire
only when the certificate matched too, at which point it would be a weaker
restatement of `SHARED_CERTIFICATE` rather than an independent signal.

It is used for two things, and only these:

* the `CONFIGURATION_MATCH` identity relation, and
* detecting `ENDPOINT_CONFIGURATION_DIVERGENCE` — several different
  configurations observed on one endpoint.

It returns `None` when the core selection was not observed, so an unobserved
negotiation never matches another unobserved one.

This distinction is what makes fixture `E_certificate_rotation_same_key` behave
correctly: a certificate renewal changes the full fingerprint and leaves the
configuration fingerprint untouched, so a routine renewal is not reported as a
configuration divergence.

## Related documents

- [drift-methodology.md](drift-methodology.md)
- [correlation-methodology.md](correlation-methodology.md)
- [blast-radius-methodology.md](blast-radius-methodology.md)
