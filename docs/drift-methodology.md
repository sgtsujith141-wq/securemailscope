# Drift methodology

Drift compares one **observed endpoint's** configuration between two captures.
Two refusals do most of the work.

## Rule 1: absence is not change

If a parameter was observed in the earlier capture and not in the later one,
the answer is `NOT_COMPARABLE` — never `OBSERVED_CHANGE`.

A short second capture, a session that ended before the ServerHello, a TLS 1.3
handshake that encrypted its certificate: all of these produce absences, and
none of them is evidence that anything moved. Reporting them as change would
make the tool generate a false alarm every time the capture was imperfect,
which is most of the time.

## Rule 2: a different answer is not necessarily a different server

TLS negotiation is a function of two inputs. A server that selected
AES-128-GCM for one client and AES-256-GCM for another may be configured
identically and simply answering two different questions.

So when a negotiated value differs, the engine compares what the **clients
offered**:

* **Offers identical** → `OBSERVED_CHANGE`. The server was asked the same
  question and gave a different answer, so the difference is attributable to it.
* **Offers differ** → `INCONCLUSIVE`, with both offers recorded in
  `client_offer_context`. The finding tells the analyst what to capture next:
  two sessions whose clients offer the same suites and versions.

The offer signature is sorted and GREASE-filtered, because GREASE values are
deliberately random and would otherwise make every offer look unique.

### Where the rule does not apply

A server presents its certificate regardless of what the client offered, so
certificate comparisons are not offer-sensitive. For those, `client_offers_comparable`
is `null` rather than `true`: reporting `true` would suggest a check that was
never relevant.

## Statuses

| Status | Meaning |
| --- | --- |
| `OBSERVED_CHANGE` | Both sides observed, they differ, and the difference is attributable. |
| `UNCHANGED_WITH_EVIDENCE` | Both sides observed and identical. Positive evidence of stability. |
| `INCONCLUSIVE` | Both observed and different, but something else differed too. |
| `NOT_COMPARABLE` | One side was not observed. |

`UNCHANGED_WITH_EVIDENCE` is deliberately not called "unchanged". *Having
looked and found the same thing twice* is a different statement from *not
having looked*, and the two must not share a name.

## What is compared

| Kind | Offer-sensitive |
| --- | --- |
| `NEGOTIATED_VERSION` | yes |
| `NEGOTIATED_CIPHER_SUITE` | yes |
| `KEY_EXCHANGE_GROUP` | yes |
| `CERTIFICATE_FINGERPRINT` | no |
| `CERTIFICATE_PUBLIC_KEY` | no |
| `CERTIFICATE_VALIDITY` | no |
| `POSTURE_SCORE` | separate; see below |

## Renewal versus rekey

Comparing the certificate fingerprint *and* the public-key fingerprint
separates two events that look identical if you only watch the certificate:

* certificate changed, key unchanged → an ordinary **renewal**;
* certificate changed, key changed → a **rekey**.

Fixture `E_certificate_rotation_same_key` exercises exactly this, and it is why
`spki_sha256` was added to the certificate model in M5.

## Scope and attribution

Drift is computed **within one entity** — one observed `(ip, port)`. A
certificate change is never attributed across endpoints, because two endpoints
presenting different certificates is the normal state of affairs, not a
rotation.

Where a capture holds several sessions to one endpoint, the earliest is used
for the comparison, so a busy capture does not produce a combinatorial
explosion of comparisons between sessions that are all describing the same
moment.

Chronology comes from **capture timestamps**, never from the order of
command-line arguments and never from file modification times. Supplying the
later capture first produces the same result.

## Score drift is kept separate

A posture score is a policy judgement. Comparing two of them across different
policies would report a threshold change as a security change, which would be
the most misleading thing this module could do.

So score drift is reported only when the two captures carry the **same policy
fingerprint** — the version *and* every applied override. Otherwise the status
is `NOT_COMPARABLE` and the explanation names both fingerprints.

If one side has no score at all — coverage below the floor — that is also
`NOT_COMPARABLE`, with the coverage named. Reporting nothing would leave a
reader diffing two reports to notice the score had vanished and guess why.

Score drift always carries the limitation that it is a judgement moving, not by
itself a cryptographic change; the cryptographic drift events are reported
alongside it and are the evidence.

## Limitations

- Attribution is to an observed `(ip, port)`. If that endpoint is a
  load-balanced pool, two different backends may have answered, and the capture
  does not distinguish them.
- Only what was captured is compared. A server may have changed and changed
  back between captures.
- Clocks across captures taken on different hosts are independent; see
  [the timeline limitations](test-strategy.md).
