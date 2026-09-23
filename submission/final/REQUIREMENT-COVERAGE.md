# SIH26159 requirement coverage

**SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for
Secure Email Communications**

Team **Zero-Day** · National Technical Research Organisation (NTRO) ·
Category: Software

Audited against the release commit **before** any presentation claim was
written. No slide asserts anything this table does not support, and no PARTIAL
was promoted to IMPLEMENTED for presentation optics.

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Built, tested against hand-derived expectations, working |
| **PARTIAL** | Real, but not met in full; the gap is stated |
| **NOT VERIFIED** | Code exists; nothing here proves it works |
| **NOT IMPLEMENTED** | No code exists |

---

| # | Requirement | Implementation | Status | Test / evidence | Limitation |
|---|---|---|---|---|---|
| 1 | Passive PCAP/PCAPNG analysis | `ingestion/` (1,166 loc) | **IMPLEMENTED** | `test_ingestion.py`, `test_formats.py`; 10 TShark cross-checks | Format from content, never the extension. Eight hard resource limits. |
| 2 | Automatic SMTP identification | `protocols/smtp.py` | **IMPLEMENTED** | `test_protocols.py`; fixtures P_A, P_C, P_H, P_T | From the dialogue, not the port. A port yields a `HINT:` with status INFERRED. |
| 3 | Automatic IMAP identification | `protocols/imap.py` | **IMPLEMENTED** | `test_protocols.py`; fixtures P_D, P_E, P_Q | Mid-stream sessions without a greeting are UNKNOWN, not guessed. |
| 4 | Automatic POP3 identification | `protocols/pop3.py` | **IMPLEMENTED** | `test_protocols.py`; fixtures P_F, P_G, P_I, P_R | Correctly identifies POP3 served on an IMAP port. |
| 5 | TCP stream reconstruction | `network/reassembly.py`, `seqspace.py` | **IMPLEMENTED** | `test_reassembly.py`, `test_sessions.py` | Bidirectional, with byte-accurate stream offsets. |
| 6 | Retransmission / out-of-order / gap handling | `network/reassembly.py` | **IMPLEMENTED** | Fixtures C, D, E, F, H, J | Bytes two segments disagree about are flagged ambiguous, never silently resolved. |
| 7 | STARTTLS / STLS detection | `protocols/starttls.py` | **IMPLEMENTED** | Fixtures P_A, P_D, P_F | Advertisement, request and outcome tracked separately. |
| 8 | STARTTLS acceptance / refusal validation | `protocols/starttls.py` | **IMPLEMENTED** | Fixtures P_B, P_G, P_J, P_K | A refusal is reported as a refusal, not as 'no TLS offered'. Demo capture 05 scores 86 with one finding. |
| 9 | TLS handshake reconstruction | `tls/records.py`, `tls/handshake.py` | **IMPLEMENTED** | `test_tls.py`; fixtures T_I–T_N | Parsing stops at a hole. Ambiguous bytes are never parsed. |
| 10 | TLS version extraction | `tls/version.py` | **IMPLEMENTED** | `test_tls.py`; TShark cross-check | Read from `supported_versions`, never from `legacy_version` (0x0303 for TLS 1.3). |
| 11 | Cipher-suite extraction | `tls/registry.py` | **IMPLEMENTED** | `test_tls_wire.py`; IANA registry | Offered and selected kept strictly apart. GREASE values identified. |
| 12 | Key-exchange identification | `tls/keyexchange.py` | **IMPLEMENTED** | `test_tls_wire.py::test_a_group_family_maps_to_the_key_exchange_method_without_guessing` | From `key_share` for TLS 1.3. A post-quantum hybrid is EPHEMERAL, not forced into a classical family. |
| 13 | Forward-secrecy assessment | `tls/forward_secrecy.py` | **IMPLEMENTED** | Rule `TLS-KEX-001`; demo capture 02 | A property of the negotiated exchange. Handshake completion is not verifiable, and the finding says so. |
| 14 | X.509 extraction | `certificates/parse.py` | **PARTIAL** | `test_certificates.py`; fixtures T_O–T_Y | **TLS 1.3 encrypts the Certificate message.** Reported NOT_AVAILABLE with the reason. TLS 1.2 chains are read in full. |
| 15 | Certificate expiry analysis | `certificates/validate.py` | **PARTIAL** | Fixtures T_O (expired), T_P (not yet valid) | Same TLS 1.3 constraint. Dates are compared against capture time, not wall-clock. |
| 16 | Public-key algorithm / length analysis | `certificates/parse.py` | **PARTIAL** | `test_tls_wire.py::test_public_key_sizes_are_reported_only_where_meaningful` | Sizes reported for RSA and EC, omitted for Ed25519 where a size is meaningless. |
| 17 | Signature-algorithm analysis | `certificates/parse.py` | **PARTIAL** | `test_certificates.py` | Same TLS 1.3 constraint. |
| 18 | Chain / hostname validation | `certificates/validate.py` | **PARTIAL** | Fixtures T_Q, T_R, T_S, T_T, T_U | RFC 5280 path verification and RFC 6125 identity matching, where a trust store is supplied. |
| 19 | Weak-cryptography detection | `assessment/rules.py` | **IMPLEMENTED** | `test_assessment.py` (225 tests) | 25 rules under a versioned policy. Demo 02 → 4 findings, 03 → 2. |
| 20 | Insecure-configuration detection | `assessment/policy.py` | **IMPLEMENTED** | `test_assessment.py` | Policy is the single source of prohibited primitives; ids change when policy changes. |
| 21 | Security scoring | `assessment/scoring.py` | **IMPLEMENTED** | `test_assessment.py`; `docs/scoring-methodology.md` | Arithmetic printed with the score. A project metric, not a validated measure of organisational security. |
| 22 | Assessment coverage | `assessment/scoring.py` | **IMPLEMENTED** | `test_assessment.py` | Unevaluable rules are excluded from **both** sides of the fraction. |
| 23 | Threat prioritisation | `assessment/prioritization.py` | **IMPLEMENTED** | `test_assessment.py` | Severity × confidence matrix producing P1–P4. |
| 24 | Remediation | `assessment/catalog.py` | **IMPLEMENTED** | `test_assessment.py`; `docs/remediation-catalog.md` | 12 remediations, each with expected security effect. |
| 25 | Evidence provenance | `models/evidence.py` | **IMPLEMENTED** | `test_intelligence.py`, `test_report_hardening.py` | Four statuses: OBSERVED, INFERRED, UNKNOWN, NOT_AVAILABLE. Packet numbers only — never payload bytes. |
| 26 | Cryptographic DNA | `intelligence/fingerprints.py` | **IMPLEMENTED** | `test_intelligence.py` | An observed profile, not proof of machine identity — stated in the interface. |
| 27 | Drift detection | `intelligence/drift.py` | **IMPLEMENTED** | `test_intelligence.py`; demo captures 08-1/08-2 | Attributable only when client offers match; otherwise INCONCLUSIVE. |
| 28 | Cross-session correlation | `intelligence/correlation.py` | **IMPLEMENTED** | `test_intelligence.py` | Relationship basis stated. No inferred topology. |
| 29 | Blast-radius analysis | `intelligence/blast_radius.py` | **IMPLEMENTED** | `test_intelligence.py` | Always qualified: 'Observed within analyzed captures only.' |
| 30 | AI/ML analysis | `ml/` (3,196 loc) | **PARTIAL** | `test_ml.py`; `docs/ml-evaluation.md`, `ml-model-card.md` | **Selected detector is a deterministic rarity baseline, not a model.** Isolation Forest trained, measured, not selected. Classifier NOT_VALIDATED; drives no finding or score. |
| 31 | Interactive dashboard | `frontend/`, `backend/` | **IMPLEMENTED** | 88 frontend tests; 5 Playwright specs; 22-step acceptance walkthrough | Cancellation is NOT IMPLEMENTED and its absence is asserted by test. |
| 32 | JSON export | `reporting/report_model.py` | **IMPLEMENTED** | `test_report.py` | Schema 1.4.0, additive since 1.0.0. |
| 33 | HTML export | `reporting/html_report.py` | **IMPLEMENTED** | `test_report_hardening.py` | `render_html` raises rather than emit a report that fetches an external resource. |
| 34 | PDF export | `reporting/pdf_report.py` | **IMPLEMENTED** | `test_report_hardening.py` | Built from the model via ReportLab, which has no URL resolver — so 'no external request' is structural. |
| 35 | Local / passive privacy model | whole engine; `scapy_guard.py` | **IMPLEMENTED** | `test_robustness.py` (7 passive tests) | Socket constructors replaced with raising stubs and the whole pipeline run through them. Scapy's neighbour resolver disabled. |

---

## Summary

| Status | Count |
|---|---:|
| IMPLEMENTED | **29** |
| PARTIAL | **6** |
| NOT VERIFIED | 0 |
| NOT IMPLEMENTED | 0 |
| **Total** | **35** |

## Why the PARTIALs are partial

Every one is limited by a property of the problem, not by unfinished work.

**Requirements 14–18 — certificate analysis.** TLS 1.3 encrypts the
Certificate message. A passive observer without decryption material cannot
read what is not on the wire. SecureMailScope reports `NOT_AVAILABLE` with the
reason rather than leaving a blank or inferring a value. For TLS 1.2 the chain
is read and verified in full: dates, chain, hostname, key size and signature
algorithm.

**Requirement 30 — AI/ML.** Three things are kept separate and named
separately, because conflating them would be the easiest way to overclaim:

- The **selected anomaly method is a deterministic rarity baseline**, and the
  interface says it is a frequency table, not a machine-learning model.
- An **Isolation Forest** was trained and evaluated. It measured worse than
  the baseline, so it was not selected. It ships labelled experimental.
- The **supervised classifier** is `NOT_VALIDATED` for real-world use. It was
  trained on controlled synthetic configurations (macro-F1 0.5624), which does
  not establish real-world accuracy. It drives no finding and no score.

## Explicitly out of scope

**Certificate revocation checking** is NOT IMPLEMENTED and permanently so: an
OCSP or CRL request would violate the passive-only rule.
`revocation_checks_performed` is `0` in every report, asserted by the test
suite. The same applies to `handshake_analyzed` (false) and
`handshakes_cryptographically_verified` (0) — a capture contains no traffic
keys.
