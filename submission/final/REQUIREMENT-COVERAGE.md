# SIH26159 requirement coverage

**SecureMailScope** — AI-Assisted Cryptographic Security Posture Assessment for
Secure Email Communications
Team **Zero-Day** · National Technical Research Organisation · Category: Software

Audited against the release commit before any presentation claim was written.
No slide asserts anything this table does not support.

| Status | Meaning |
|---|---|
| **IMPLEMENTED** | Built, tested against hand-derived expectations, working |
| **PARTIAL** | Real, but the requirement is not met in full; the gap is stated |
| **NOT VERIFIED** | Code exists; nothing in this repository proves it works |
| **NOT IMPLEMENTED** | No code exists |

---

## 1. Automatic email-protocol identification

| | |
|---|---|
| **Module** | `protocols/` (3,406 loc) — SMTP, IMAP and POP3 state machines |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_protocols.py`, `tests/test_protocol_behaviour.py`, `tests/test_protocol_reader.py`. Fixtures P_A–P_T include non-standard ports (`P_H_smtp_nonstandard_port`, `P_I_pop3_on_imap_port`) and decoys (`P_P_data_body_fake_starttls`, `P_Q_imap_literal_fake_commands`). |
| **How** | Identification is from the dialogue, never the port. A port yields a `HINT:` value carrying evidence status `INFERRED` and the limitation "NOT a confirmed protocol". |
| **Limitation** | A session that begins mid-stream may never show a greeting; it is reported `UNKNOWN`, not guessed. |

## 2. TCP stream reconstruction

| | |
|---|---|
| **Module** | `network/` (~900 loc) — `reassembly.py`, `seqspace.py`, `flows.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_reassembly.py`, `tests/test_sessions.py`. Fixtures cover out-of-order (C), duplicates (D), retransmission (E), missing segments (F), overlap conflicts (H), tuple reuse (J), mid-stream (M). |
| **How** | Bytes two segments disagree about are flagged ambiguous rather than silently resolved. |
| **Limitation** | A gap is a gap: reconstruction stops at a hole rather than interpolating. |

## 3. STARTTLS / STLS detection and validation

| | |
|---|---|
| **Module** | `protocols/starttls.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | Fixtures P_A (accepted), P_B (rejected), P_D (IMAP), P_F/P_G (POP3 STLS), P_J (no response), P_K (gap during upgrade), P_N (no plaintext after upgrade). |
| **How** | Advertisement, request, outcome, and the exact packet in each direction where plaintext stops. |
| **Limitation** | If the capture ends before the server answers, the outcome is `UNKNOWN`. |

## 4. TLS handshake reconstruction

| | |
|---|---|
| **Module** | `tls/` — record framing, handshake reassembly |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_tls.py`, `tests/test_tls_wire.py`. Fixtures T_I (record split across packets), T_J (handshake split across records), T_K (multiple messages one record), T_L (truncated), T_M (missing segment), T_N (conflicting bytes). |
| **How** | Parsing stops at a hole; ambiguous bytes are never parsed. |

## 5. TLS version and cipher-suite identification

| | |
|---|---|
| **Module** | `tls/version.py`, `tls/registry.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_tls.py`; ten independent **TShark cross-checks** compare our dissection against Wireshark's. |
| **How** | The negotiated version is read from the `supported_versions` extension, never from `legacy_version` (which reads 0x0303 for TLS 1.3). Offered and selected are kept strictly apart. |

## 6. Key-exchange identification where observable

| | |
|---|---|
| **Module** | `tls/keyexchange.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_tls.py`, `tests/test_tls_wire.py::test_a_group_family_maps_to_the_key_exchange_method_without_guessing` |
| **How** | From the `key_share` extension for TLS 1.3 and the suite for TLS 1.2 — never inferred from a TLS 1.3 suite name, which encodes only an AEAD and a hash (RFC 8446 §B.4). |
| **Limitation** | A post-quantum hybrid group is reported as the generic `EPHEMERAL`, not forced into ECDHE or DHE. |

## 7. X.509 certificate extraction and validation where observable

| | |
|---|---|
| **Module** | `certificates/` (861 loc) |
| **Status** | **PARTIAL** |
| **Evidence** | `tests/test_certificates.py`. Fixtures T_O (expired), T_P (not yet valid), T_Q (self-signed), T_R (valid trusted chain), T_S (incomplete chain), T_T (hostname scenarios), T_Y (malformed lengths). |
| **How** | Five independent checks — dates, chain, hostname, key, signature — with no defaults assumed. |
| **Limitation** | **TLS 1.3 encrypts the Certificate message.** No passive tool can read it without decryption material. Reported `NOT_AVAILABLE` with the reason, never blank and never guessed. This is a property of the protocol, not a gap in the implementation. |

## 8. Certificate expiry / public-key / key-length / signature analysis

| | |
|---|---|
| **Module** | `certificates/parse.py`, `certificates/validate.py` |
| **Status** | **PARTIAL** (same TLS 1.3 constraint as #7) |
| **Evidence** | `tests/test_tls_wire.py::test_public_key_sizes_are_reported_only_where_meaningful` — sizes are reported for RSA and EC and omitted for Ed25519, where a "size" would be meaningless. |
| **Limitation** | Revocation is **NOT IMPLEMENTED** and permanently out of scope: an OCSP or CRL request would violate the passive-only rule. `revocation_checks_performed` is `0` in every report. |

## 9. Weak cryptography / insecure configuration detection

| | |
|---|---|
| **Module** | `assessment/` (3,416 loc) — 25 rules under a versioned policy |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_assessment.py` (225 tests). Demo: `02-weak-legacy-tls.pcap` → 4 findings, score 59; `03-broken-cipher.pcap` → 2 findings, score 70. |
| **How** | Policy is the single source of prohibited primitives. A finding id changes when the policy changes, so a stale id cannot be mistaken for a current verdict. |

## 10. Forward-secrecy assessment

| | |
|---|---|
| **Module** | `tls/forward_secrecy.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | Rule `TLS-KEX-001`; fixture `aa_tls10_static_rsa` / demo `02-weak-legacy-tls.pcap`. |
| **Limitation** | Forward secrecy is a property of the negotiated key exchange. Handshake completion is **not verifiable** from a passive capture, and the finding says so in its own limitation text. |

## 11. AI/ML-assisted risk classification and anomaly analysis

| | |
|---|---|
| **Module** | `ml/` (3,196 loc) — 93-feature schema, dataset, evaluation, registry, inference |
| **Status** | **PARTIAL — and deliberately so** |
| **Evidence** | `tests/test_ml.py`, `docs/ml-evaluation.md`, `docs/ml-model-card.md` |
| **Anomaly detection** | A **deterministic rarity baseline** is the selected detector. An Isolation Forest was trained, measured and **not selected** because the baseline scored better. Both are shipped; the interface states which is in use and that the baseline is "a deterministic frequency table, not a machine-learning model". |
| **Supervised classification** | Trained and measured on synthetic data (macro-F1 0.5624). Reported **`NOT_VALIDATED`** for real-world use. No independent representative validation has been obtained. It does not drive any finding or any score. |
| **Limitation** | All ML evaluation is synthetic, by design: the project does not ingest private email traffic. Synthetic evaluation does not establish real-world accuracy. |

## 12. Security posture scoring and threat prioritisation

| | |
|---|---|
| **Module** | `assessment/scoring.py`, `assessment/prioritization.py` |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_assessment.py`; `docs/scoring-methodology.md` |
| **How** | `score = 100 × (W(evaluated) − W(failed)) / W(evaluated)`, printed with its arithmetic. A rule that could not be evaluated is excluded from **both** sides rather than counted as a pass or a violation. Priority comes from a severity × confidence matrix. |
| **Limitation** | A project-defined analytical metric, not a validated measure of organisational security. For several captures the headline is the **weakest** capture with the range stated — never an average, because no weighting methodology has been validated. |

## 13. Actionable remediation

| | |
|---|---|
| **Module** | `assessment/catalog.py` — 12 remediations |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_assessment.py`; `docs/remediation-catalog.md` |
| **How** | Each carries a technical explanation, a recommended action, an expected security effect and the rules it answers. |

## 14. Interactive forensic dashboard

| | |
|---|---|
| **Module** | `frontend/` (4,400+ loc), `backend/` (2,756 loc) |
| **Status** | **IMPLEMENTED** |
| **Evidence** | 88 frontend tests, 5 Playwright specs against the real backend, a 22-step acceptance walkthrough including a backend restart. |
| **How** | FastAPI on loopback over the unchanged engine; React with strict TypeScript. Navigation follows the investigation workflow. |
| **Limitation** | Analysis **cannot be cancelled** — a running analysis finishes or fails. The absence is asserted by test so it cannot be mistaken for a broken control. |

## 15. JSON / PDF / HTML reports

| | |
|---|---|
| **Module** | `reporting/` (1,582 loc) |
| **Status** | **IMPLEMENTED** |
| **Evidence** | `tests/test_report.py`, `tests/test_report_hardening.py` (38 tests) |
| **How** | One canonical `ReportModel` feeds all three, so their facts cannot disagree. Parity is asserted across capture ids, session counts, finding ids, severities, score, remediations and ML validation status. |
| **Security** | The HTML report fetches nothing — `render_html` raises rather than emit a report that would load an external resource. The PDF is built from the model through ReportLab, which has no URL resolver, so "no external request" is structural. |

---

## Summary

| Status | Count | Requirements |
|---|---:|---|
| IMPLEMENTED | 11 | 1, 2, 3, 4, 5, 6, 9, 10, 12, 13, 14, 15 |
| PARTIAL | 3 | 7, 8 (TLS 1.3 encrypts certificates); 11 (ML honesty) |
| NOT VERIFIED | 0 | — |
| NOT IMPLEMENTED | 0 | Revocation checking is out of scope by the passive rule, recorded under #8 |

Every PARTIAL is partial for a stated reason that is a property of the problem,
not an unfinished implementation:

- **TLS 1.3 certificate visibility** is a protocol guarantee. A passive
  observer without decryption material cannot read what is encrypted.
- **Supervised ML validation** requires a representative real-world corpus this
  project deliberately does not collect.

Neither is hidden. Both appear in the interface, in every report, and on the
submission slides.
