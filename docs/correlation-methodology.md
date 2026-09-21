# Correlation methodology

A correlation groups sessions that share an **observation**. That is the whole
claim.

## What a correlation never says

* **Not "a coordinated attack".** Two servers negotiating TLS 1.0 is two
  servers with old configuration. Nothing in the bytes distinguishes that from
  anything else, and this tool does not detect attacks.
* **Not "the same organisation".** Sharing a certificate or an address is what
  shared hosting looks like. Inferring common ownership from it would be wrong
  far more often than right.
* **Not a network topology.** Endpoints are observed; the infrastructure
  between and behind them is not.
* **Not a cause.** The same rule failing in eight sessions means the same
  condition was observed eight times, not that one thing caused all eight.

A test asserts that no correlation's text uses "attacker", "adversary",
"campaign", "coordinated", "malicious" or "threat actor" as a claim.

## Types

| Type | Shared observation |
| --- | --- |
| `SHARED_RULE_FAILURE` | The same rule failed in more than one session. |
| `REPEATED_OBSOLETE_TLS` | `TLS-PROTO-001` repeated. |
| `REPEATED_WEAK_CIPHER` | `TLS-CIPHER-001` or `-003` repeated. |
| `AUTHENTICATION_EXPOSURE` | `MAIL-001` or `MAIL-002` repeated. |
| `SHARED_CERTIFICATE` | The same certificate was presented. |
| `SHARED_PUBLIC_KEY` | The same key pair, possibly under different certificates. |
| `SHARED_ENDPOINT` | The same observed `(ip, port)`. |
| `ENDPOINT_CONFIGURATION_DIVERGENCE` | Several configurations on one endpoint. |

## Identifiers

`correlation_id` is derived from the correlation's **type and shared value**
only — not from which sessions happened to be in the batch, and not from
argument order. The same grouping in two investigations carries the same
identifier, so two reports can be diffed.

## Evidence de-duplication

Supporting evidence is de-duplicated by `(packet number, timestamp)`. One
finding backed by several records must not look like several findings; the
directive is explicit about this and a test asserts it.

## Policy disclosure

Findings correlated across captures may have been produced under different
assessment policies. Where they were, `policy_versions` lists them and an extra
limitation is attached saying the members were judged by different criteria and
are grouped only by the condition they describe.

## Complexity

Grouping is done by **indexing on the shared value**: a dictionary keyed by
certificate digest, by rule id, by entity id. There is no all-pairs comparison
anywhere, so the work is linear in the number of sessions. This matters once a
batch holds thousands, and the directive requires it.

## False-correlation prevention

The negative fixture groups are the substance of this module's test coverage:

| Group | What must **not** happen |
| --- | --- |
| `L_unrelated_same_configuration` | Two unrelated servers with identical settings, different certificates, keys and names. Only `CONFIGURATION_MATCH` may be recorded — no certificate or key relation, and no `POSSIBLE_RELATION`. |
| `F_shared_certificate_distinct_endpoints` | Two endpoints behind one certificate must stay two entities. |
| `G_same_ip_multiple_services` | One address on two ports is two independently configurable services. |
| `E_certificate_rotation_same_key` | A renewal must not be reported as a configuration divergence. |
| `K_duplicate_capture` | The same bytes twice must not correlate with itself. |
| `H_tls13_encrypted_certificate_both` | No certificate relation may be claimed where no certificate was visible. |

## Entity resolution, and why nothing is merged

See [the identity module](../src/securemailscope/intelligence/identity.py). A
`ServerEntity` is one observed `(ip, port)`, and that exact equality is the
**only** merge performed. Every weaker signal becomes a typed relationship
between entities that remain separate:

| Relation | What it establishes |
| --- | --- |
| `EXACT_ENDPOINT` | The same `(ip, port)`. |
| `SHARED_CERTIFICATE` | The same certificate. Not the same machine. |
| `SHARED_PUBLIC_KEY` | The same key pair. |
| `OBSERVED_SNI` | The same name was requested by a client. |
| `CONFIGURATION_MATCH` | The same negotiated settings. |
| `POSSIBLE_RELATION` | Two or more weak signals corroborate, with no strong one. |
| `INSUFFICIENT_EVIDENCE` | Nothing links them. |

`POSSIBLE_RELATION` is reported for a human to consider and is never acted on
as an identity. It is suppressed where a certificate or key relation already
exists, since it would add nothing and would read as a second finding.

So a report can say *these two endpoints presented the same certificate*
without ever saying *these two endpoints are the same server* — which is the
difference between evidence and a guess about it.
