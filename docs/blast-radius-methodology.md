# Blast-radius methodology

How far a condition was **observed** to reach. Not how far it might reach, not
how far it probably reaches, and not how far it reaches across an estate nobody
captured.

Every result carries this statement verbatim, because the number is meaningless
without it:

> Observed within analyzed captures only.

## Counting rules

Each rule exists because it has an obvious wrong alternative.

| Counted | By | Wrong alternative it prevents |
| --- | --- | --- |
| Sessions | distinct `session_id` | — |
| Endpoints | distinct `(server ip, server port)` | Counting connections. A client with an eight-connection pool would multiply every number by eight. |
| Captures | distinct capture **content hash** | Counting file names. The same file submitted twice would double the radius by re-reading one piece of evidence. |
| Findings | distinct `finding_id` | Counting evidence records. One condition backed by six packets would look like six findings. |

A test asserts that each reported count equals the length of the list it
summarises, so the numbers and the identifier lists can never disagree.

## What a result contains

```
subject:               TLS-PROTO-001
subject_kind:          RULE
session_count:         2
entity_count:          2
capture_count:         2
finding_count:         2
affected_session_ids:  [...]
affected_entity_ids:   [...]
affected_capture_ids:  [...]
protocol_distribution: {"IMAP": 2}
counting_method:       "Sessions counted by distinct session id. ..."
scope_statement:       "Observed within analyzed captures only."
```

The identifier lists are the audit trail: a reader who doubts a count can check
it against the sessions it names, in the same document.

## What is never concluded

- That the whole enterprise is affected.
- That all users are vulnerable.
- That the issue exists on every server.
- That unobserved sessions are affected — **or that they are not**. Absence
  from a count is absence of observation, and the limitation says so.

A test asserts that no blast-radius text contains "enterprise", "all users",
"every server" or "organisation-wide".

## Endpoint identity is conservative on purpose

An endpoint may be a single machine, a load-balanced pool or a virtual host. A
capture does not distinguish them, so `entity_count` is a count of **observed
network endpoints**, not of physical servers, and it says so.

Two endpoints are never merged because they share a certificate — that would
fold unrelated infrastructure together and understate the radius while
appearing to tidy it up. See
[correlation-methodology.md](correlation-methodology.md).

## Business criticality

Not represented, and not inferred. No address, port or hostname makes a host
important. If an authorised asset inventory is ever supplied by a user, that is
a separate integration to be designed deliberately — not something to guess at
from a packet capture.

## Worked example

Fixture `Q_same_finding_across_endpoints`: two distinct endpoints, each in its
own capture, both negotiating TLS 1.0 with a static-RSA suite.

```
TLS-PROTO-001 observed in 2 sessions across 2 observed server endpoints,
in 2 captures.
```

That statement is permitted because each number comes from the evidence: two
`session_id` values, two distinct `(ip, port)` pairs, two distinct capture
hashes. The expected counts are written into the fixture's manifest by hand and
asserted against.

Contrast fixture `K_duplicate_capture`, where the same bytes are supplied twice
under two names. Every count is 1.
