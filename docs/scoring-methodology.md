# Scoring methodology

## What the score is, and what it is not

The posture score is **a transparent, project-defined analytical metric that
summarises the evidence in one capture under one named policy version.** It is
not an independently validated measure of enterprise-wide security, it is not
benchmarked against any industry data set, and it carries no accreditation.

Concretely, a SecureMailScope score does **not** tell you:

- how secure an organisation is — it saw one capture, of one or a few sessions;
- how you compare with your peers — no comparative data exists behind it;
- whether you are compliant with anything — compliance is assessed against a
  named standard by an assessor, not inferred from packet captures;
- what your score would become after a fix — the tool never simulates changes.

What it *does* tell you is narrow and checkable: **of the weighted controls
this capture contained enough evidence to evaluate, what fraction passed.**
Every input to that sentence is published in the report, so the number can be
recomputed by hand.

The **findings are the substance; the score is a reading aid.** Where the two
seem to disagree, the findings are what to act on. Fixture `AC_rc4_weak_cipher`
is kept in the suite precisely because it scores 70 (`ADEQUATE`) while
negotiating RC4: its certificate handling is otherwise sound, and the score
averages over the whole session rather than reporting its worst moment. The RC4
finding sits at P1 in the same report. A one-number summary that could never be
read misleadingly would have to be a summary of one thing.

## Scoring units, not rules

The score is computed over **scoring units**, not over raw rule results. A unit
is one `(session, de-duplication group)` pair.

Several rules can describe one underlying weakness. `TLS-CIPHER-001` (no
encryption) and `TLS-CIPHER-005` (not on the approved list) both fire on a NULL
cipher suite, but there is only one misconfigured setting. Counting both would
charge an operator twice for one mistake and would make the score depend on how
finely the catalogue happens to be subdivided.

For each unit:

- **Outcome** is the most serious outcome any member reached, in the order
  `FAIL` > `UNKNOWN` > `PASS` > `NOT_APPLICABLE`.
- **Representative** is the most severe member that produced that outcome, with
  ties broken by rule id so the choice is deterministic.
- **Weight** is the representative's policy weight.

Members that did not carry the unit are marked `counts_toward_score: false` and
are reported but not charged. The report's `tally.suppressed_duplicates` counts
them, so nothing is hidden.

## The formula

Let **E** be the set of units that were evaluated (`PASS` or `FAIL`), **F** the
failed units, **U** the units that came back `UNKNOWN`, and **A = E ∪ U** the
applicable units. Let **W(X)** be the total weight of a set. Units whose weight
is zero — `INFO`-severity controls — are excluded from all four sets; they are
still reported, and can still be findings, but they neither raise nor lower the
number.

```
coverage = W(E) / W(A)

score    = 100 * (W(E) - W(F)) / W(E)
```

The score is rounded to the nearest integer. `W(F) <= W(E)` always holds
because `F ⊆ E`, so the result lies in `[0, 100]` by construction rather than by
clamping.

### Why UNKNOWN is in neither the numerator nor the denominator

`U` appears in the coverage fraction and nowhere in the score. This is the
single most important property here, and it follows from a simple argument:

- If `UNKNOWN` were scored as a pass, a capture that showed nothing would score
  100. Missing evidence would be the most effective way to get a good score.
- If `UNKNOWN` were scored as a failure, a truncated capture would look like a
  misconfigured server. The tool would be reporting its own blind spots as the
  operator's problems.

Excluding it from both sides makes the score a statement about what was
actually checked, and makes **coverage** the separate statement about how much
that was. The two are always reported together, because a score of 100 over 4%
coverage is a statement about very little.

### Properties, and why each holds

1. **Range.** `0 <= score <= 100`, since `F ⊆ E` gives `0 <= W(F) <= W(E)`.
2. **Missing observations cannot improve the score.** Turning a `PASS` into an
   `UNKNOWN` removes weight `w` from both `W(E)` and `W(F)`'s complement. The
   new score is `100 (W(E) - w - W(F)) / (W(E) - w)`, which is `<=` the old
   score whenever the old score was `<= 100`. Evidence that a control passed can
   only help; losing it never helps. Asserted in
   `test_unknown_evidence_cannot_improve_the_score`.
3. **Missing observations cannot reduce the score below what was checked.**
   Symmetrically, removing a `FAIL` raises the score — which is correct, because
   the failure is no longer established.
4. **Monotonicity in failures.** For a fixed population, adding a failure never
   raises the score, and a more heavily weighted failure never scores higher
   than a lighter one. Asserted in `test_more_failures_never_raise_the_score`.
5. **No double counting.** Each unit contributes at most one deduction.
   Asserted in `test_each_dedup_group_contributes_at_most_one_deduction`.
6. **Disabling a rule removes it from both sides.** A disabled rule leaves the
   population entirely rather than being counted as passing. Asserted in
   `test_disabling_a_rule_removes_it_from_both_sides`.
7. **Determinism.** The same capture and policy produce the same number, every
   run. Asserted in `test_repeated_analysis_is_byte_identical`.
8. **Auditability.** Every deduction is listed in `deduction_detail` with its
   group, weight and rule, and they sum to `weighted_deductions`. Asserted in
   `test_severity_weights_are_reported_not_hidden`.
9. **Refusal below the coverage floor.** See below.
10. **The score never depends on the number of sessions in a capture.** Capture
    scope pools units; it does not average per-session scores, which would let
    a capture full of trivial sessions dilute a serious finding.

## When there is no score

If `W(E) == 0`, or if `coverage` falls below the policy's
`minimum_coverage_for_score` (default **0.50**), the status is
`SCORE_UNAVAILABLE` and `score` is `null`.

Refusing to produce a number is a feature. A capture containing only a
ClientHello can support almost no judgement, and printing "100" beside it would
be actively misleading — the reader would see a score, not the absence of
evidence behind it. The threshold is a policy choice and is configurable with
`--minimum-score-coverage`; any change is recorded in the report.

Fixture `T_G_client_hello_only` reaches 4% coverage and is scored
`SCORE_UNAVAILABLE`; fixture `A_complete_connection`, a plain TCP session with
no applicable controls at all, likewise.

## An investigation of several captures

A posture score describes **one capture**. An investigation may hold many, and
a single headline number then has to mean something.

**The headline is the weakest scored capture, not an average and not the
first.** The scope sentence names which capture it came from and gives the
range, so the figure is never read as describing every capture equally:

> weakest of 7 scored capture(s) in this investigation
> (02-weak-legacy-tls.pcap); scores ranged 59 to 100

Two reasons for the floor rather than a mean.

*An average would be a number the engine never produced.* This project does not
invent figures: every number in a report is one the analysis actually
calculated. There is no validated methodology for weighting captures against
each other — a capture holding one session and a capture holding four hundred
are not equal inputs — so no mean is computed rather than computing one that
looks authoritative and is not.

*Posture is a floor.* An attacker does not need every path to be weak. If one
observed configuration accepts TLS 1.0 with static RSA, the infrastructure has
that weakness whether or not six other captures were clean.

Until M9 the headline was taken from `results[0]` — whichever capture happened
to sort first. An investigation whose first capture was clean therefore
displayed a perfect score while carrying HIGH severity findings from another
capture in the same set. Every finding was still listed, so nothing was
deleted, but the number a reader looks at first described one capture and was
presented as describing all of them.
`tests/test_report_hardening.py::test_the_headline_score_is_the_weakest_capture_not_the_first`
is the regression, and it deliberately orders the strongest capture first.

A single-capture investigation is unaffected: the headline is that capture's
score, and the scope names it as before.

## Score bands

| Band | Range |
| --- | --- |
| `STRONG` | 90–100 |
| `ADEQUATE` | 70–89 |
| `WEAK` | 40–69 |
| `CRITICAL` | 0–39 |

These boundaries are **project-defined reading aids**, not thresholds with
external standing. They exist so a reader is not asked to interpret a bare
integer, and they are configurable.

## Priority, and why it is a matrix

Priority orders the work. It is a **lookup**, never a product:

| Severity \ Confidence | CONFIRMED | PROBABLE | LOW |
| --- | --- | --- | --- |
| **CRITICAL** | P1 | P1 | P2 |
| **HIGH** | P1 | P2 | P3 |
| **MEDIUM** | P2 | P3 | P3 |
| **LOW** | P3 | P4 | P4 |
| **INFO** | P4 | P4 | P4 |

Multiplying a severity by a confidence percentage would be the obvious
alternative and is wrong for two reasons. It invents precision — "70%
confidence" is not something a packet capture measures — and it collapses two
different questions into one number, so a reader can no longer tell whether a
finding ranked low because the condition is mild or because the evidence is
thin. Those call for different responses: the first for scheduling, the second
for a better capture.

Within a priority band, findings are ordered by a deterministic sort key:

```
(severity rank, confidence rank, asset criticality rank, -sessions observed,
 rule id, finding id)
```

Asset criticality is **operator-supplied and never inferred**. A port number
does not tell you a host is important. Unlabelled assets sort last within their
band, not first and not as though they were low-criticality.

## Confidence

| Confidence | When |
| --- | --- |
| `CONFIRMED` | Every supporting observation was `OBSERVED`, from a complete record. |
| `PROBABLE` | At least one supporting observation was `INFERRED`. |
| `LOW` | The session was partial, indeterminate, or identified only by port. |

Confidence grades the *evidence*, not the seriousness, and the two are always
reported side by side.

## Worked example

Fixture `AA_tls10_static_rsa_multiple_findings`: a server that negotiated TLS
1.0 with `TLS_RSA_WITH_AES_128_CBC_SHA`, presenting a valid EC certificate,
with no trust store or expected identity configured.

Units with non-zero weight:

| Unit | Outcome | Representative | Weight |
| --- | --- | --- | --- |
| `NEGOTIATED_PROTOCOL_VERSION` | FAIL | `TLS-PROTO-001` (HIGH) | 6 |
| `NEGOTIATED_CIPHER_SUITE` | FAIL | `TLS-CIPHER-005` (MEDIUM) | 3 |
| `FORWARD_SECRECY` | FAIL | `TLS-KEX-001` (HIGH) | 6 |
| `NEGOTIATION_OUTCOME` | PASS | `TLS-PROTO-003` (LOW) | 1 |
| `CERT_VALIDITY` | PASS | `CERT-001` (HIGH) | 6 |
| `CERT_KEY_STRENGTH` | PASS | `CERT-003` (HIGH) | 6 |
| `CERT_SIGNATURE` | PASS | `CERT-004` (HIGH) | 6 |
| `CERT_EKU` | PASS | `CERT-007` (MEDIUM) | 3 |
| `CERT_CHAIN` | UNKNOWN | `CERT-005` (HIGH) | 6 |
| `CERT_IDENTITY` | UNKNOWN | `CERT-006` (HIGH) | 6 |

```
W(F) = 6 + 3 + 6                 = 15
W(E) = 15 + (1 + 6 + 6 + 6 + 3)  = 37
W(U) = 6 + 6                     = 12
W(A) = 37 + 12                   = 49

coverage = 37 / 49              = 0.7551
score    = 100 * (37 - 15) / 37 = 59.46 -> 59   (WEAK)
```

`OFFERED_PROTOCOL_VERSION` also failed, at `INFO`. It is reported as a finding
— the client did offer TLS 1.0 — but weighs 0, so it does not move the number.

Note the two `UNKNOWN` units. No trust store was supplied, so the chain was not
verified and the identity was not checked. The report says exactly that; it
does not say the chain was good, and it does not say it was bad.

These numbers are the *committed expectation* in the fixture manifest, worked
out by hand before the engine was run against it. See
`src/securemailscope/testing/assessment_fixtures.py`.

## Policy fingerprint

Finding identifiers are derived from, among other things, a **policy
fingerprint**: a digest of the policy id, version and every applied override.

A policy version alone is not enough to identify the criteria a finding was
reached under. An operator who raises `minimum_rsa_bits` on the command line is
evaluating a different standard while still running policy `1.0.0`. Without the
fingerprint, two reports produced under different criteria would share finding
identifiers, and a diff between them would silently compare unlike things.

The fingerprint is published in the report's policy block, and every finding
carries it, so any identifier can be recomputed by hand.

## Related documents

- [security-policy.md](security-policy.md) — every rule, weight and threshold.
- [remediation-catalog.md](remediation-catalog.md) — the corrective actions.
- [evidence-model.md](evidence-model.md) — how observations are graded.
- [limitations.md](limitations.md) — what the system as a whole cannot do.
