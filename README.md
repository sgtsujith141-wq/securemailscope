# SecureMailScope

Passive cryptographic security posture assessment for captured email traffic.
Smart India Hackathon 2026, problem statement **SIH26159**.

SecureMailScope reads packet captures you already have and reports what the
bytes actually show about how email was transported: which connections
existed, how much of each one the capture really contains, and — in later
milestones — whether the traffic was encrypted, how, and how well.

**Everything is local and passive.** The engine never contacts a captured
host, never resolves a domain, never scans anything, and never transmits
capture contents anywhere.

---

## Current status

This repository is at the end of **M0 + M1**. The table below is the honest
state of each stage; the same table is emitted into every report so a reader
never has to guess whether a missing TLS section means "no TLS in the capture"
or "not built yet".

| Stage | Status | Notes |
|---|---|---|
| Capture ingestion (pcap + pcapng) | **IMPLEMENTED** | Content-based format detection, streaming, bounded |
| TCP session reconstruction | **IMPLEMENTED** | Reordering, retransmission, gaps, overlap conflicts, tuple reuse |
| SMTP / IMAP / POP3 parsing | **IMPLEMENTED** | Real state machines; detection from payload, not ports |
| STARTTLS / STLS state reconstruction | **IMPLEMENTED** | Advertisement, request, outcome, both transition boundaries |
| Implicit TLS detection | **IMPLEMENTED** | Record framing only; the protocol inside stays a port hint |
| Authentication observation | **IMPLEMENTED** | Presence and mechanism only — never credentials |
| TLS record framing and handshake reassembly | **IMPLEMENTED** | Stops at a hole; never parses ambiguous bytes |
| Version, cipher suite, key exchange | **IMPLEMENTED** | Offered vs selected kept strictly apart |
| Forward-secrecy observation | **IMPLEMENTED** | Criteria stated per result, with RFC citations |
| Certificate extraction | **PARTIAL** | TLS ≤ 1.2 only — TLS 1.3 certificates are encrypted |
| Certificate validation (dates, chain, hostname) | **IMPLEMENTED** | Five independent checks, no defaults assumed |
| Certificate revocation | NOT IMPLEMENTED | Permanently out of scope: no network requests |
| Certificate posture assessment | NOT IMPLEMENTED | M4 |
| Risk assessment and findings | NOT IMPLEMENTED | M4 |
| Evidence correlation | NOT IMPLEMENTED | M5 |
| ML-assisted analysis | NOT IMPLEMENTED | M6 |
| REST backend / web UI | NOT IMPLEMENTED | M7+ |

Three things are constants in every report, and are asserted by the test
suite rather than left to trust: `handshake_analyzed` is `false`,
`handshakes_cryptographically_verified` is `0`, and
`revocation_checks_performed` is `0`. Verifying a handshake completed needs
the traffic keys a capture does not contain, and revocation checking would
need a network request the engine never makes.

---

## Requirements

- Python 3.12 (3.13+ is not supported yet; Scapy 2.6.1 is pinned against 3.12)
- No database server, message broker, container runtime or network service

Runtime dependencies are just `scapy` and `pydantic`. `fastapi`, `cryptography`
and `scikit-learn` are declared as optional extras for later milestones and are
not installed or imported by the engine.

## Install

```bash
make install            # creates .venv and installs the package plus dev tools
```

or manually:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Installation downloads packages from PyPI. That is the only outbound network
activity in the project, and it happens at install time only — the application
itself never transmits anything.

## Use

```bash
# Analyse a capture and write a JSON report
securemailscope analyze path/to/capture.pcap --output result.json

# Same, to stdout, for piping into jq
securemailscope analyze path/to/capture.pcap --quiet | jq '.inventory'

# What is actually implemented right now
securemailscope status

# Regenerate the synthetic test captures (no network access)
securemailscope fixtures
```

Useful flags:

| Flag | Effect |
|---|---|
| `--output PATH` | Write JSON to a file; the summary still goes to stderr |
| `--compact` | Single-line JSON |
| `--no-segments` | Omit per-packet segment provenance (much smaller reports) |
| `--quiet` | Suppress the human-readable summary |
| `--max-*` | Override any resource limit for this run |

Exit codes: `0` success, `2` bad input (missing file, not a capture, too
large), `1` unexpected error.

| `--no-protocol-events` | Omit per-line protocol event lists (much smaller reports) |

### Try it without a capture of your own

```bash
make fixtures

# TCP reconstruction with a hole in the stream
securemailscope analyze tests/fixtures/generated/f_missing_segment.pcap --quiet \
  | jq '.sessions[0].client_to_server | {bytes_reconstructed, runs, gaps}'

# A STARTTLS negotiation, with both transition boundaries
securemailscope analyze tests/fixtures/generated/p_a_smtp_starttls_accepted.pcap --quiet \
  | jq '.protocols[0] | {detection: .detection.status, state: .upgrade.state,
        client: .upgrade.client_boundary, server: .upgrade.server_boundary}'

# Plaintext authentication, recorded without the credential
securemailscope analyze tests/fixtures/generated/p_m_auth_before_tls.pcap --quiet \
  | jq '.protocols[0].authentication'

# A TLS 1.2 handshake: negotiated parameters and the certificate it presented
securemailscope analyze tests/fixtures/generated/t_a_tls12_complete_handshake.pcap \
  --trust-store tests/fixtures/generated/synthetic-root.pem \
  --expected-server-identity mail.example.invalid --quiet \
  | jq '.tls[0] | {version: .version.selected_version.name,
                   suite: .cipher_suite.selected.name,
                   forward_secrecy: .forward_secrecy.status,
                   validation: .certificates.validation | map_values(.status)}'

# TLS 1.3: the certificate is encrypted, and the report says so
securemailscope analyze tests/fixtures/generated/t_d_tls13_negotiation.pcap --quiet \
  | jq '.tls[0].certificates | {visibility, visibility_explanation}'
```

### Certificate validation needs inputs you supply

There is **no default trust store** and **no default expected identity**.
Without them, chain and hostname verification report `NOT_AVAILABLE` rather
than using a bundle the report cannot name or an identity nobody authorised:

| Flag | Enables |
|---|---|
| `--trust-store PEM` | Chain verification against anchors the report can identify |
| `--expected-server-identity NAME` | Hostname verification (the destination IP is never used) |
| `--trust-observed-sni` | Opt in to using the observed SNI as that identity |
| `--assess-current-time` | An additional, separately labelled current-time date check |

## What the report contains

Every statement carries its evidence. The output distinguishes:

- **Confirmed facts** — `EvidenceStatus.OBSERVED`, read directly from captured bytes
- **Hints and derivations** — `INFERRED`, with a recorded `basis` and explicit `limitations`
- **Unknowns** — `UNKNOWN` (this capture does not determine it) and
  `NOT_AVAILABLE` (passive capture cannot determine it, or the stage is not built)

Reconstructed data is reported as **contiguous runs with offsets**, never as a
single blob: if bytes are missing, you get two runs and an explicit gap, and
the gap's contents stay `UNKNOWN`.

Protocol detection has its own ladder — `CONFIRMED`, `PROBABLE`, `PORT_HINT`,
`UNKNOWN` — and **a port number can never reach `CONFIRMED`**. SMTP on port
8025 is confirmed from its payload; a silent session on port 993 is a port
hint and nothing more.

**Reports never contain application payload bytes.** They carry counts,
offsets, SHA-256 digests and packet references, so a report is safe to attach
to a ticket or a submission. The bytes themselves are available only through
the Python API (`analyze_capture_with_payloads`).

## Python API

```python
from securemailscope import AnalysisConfig, analyze_capture

result = analyze_capture("capture.pcap", config=AnalysisConfig())
for session in result.sessions:
    print(session.session_id, session.flow.client, "->", session.flow.server,
          session.completeness.value,
          session.client_to_server.bytes_reconstructed, "bytes")
```

To get the reconstructed bytes themselves (this is the hand-off point for the
M2 protocol layer):

```python
from securemailscope.pipeline import analyze_capture_with_payloads
from securemailscope.models.tcp import Direction

artifacts = analyze_capture_with_payloads("capture.pcap")
runs = artifacts.payload_runs[session_id, Direction.CLIENT_TO_SERVER]
# [(stream_offset, b"..."), ...] -- more than one run means there are holes
```

## Development

```bash
make check        # lint + typecheck + tests
make test         # pytest
make lint         # ruff
make typecheck    # mypy
make fixtures     # regenerate synthetic captures and manifests
make secrets-check  # refuse to commit captures, keys or .env files
```

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Data flow, module boundaries, execution model |
| [docs/evidence-model.md](docs/evidence-model.md) | Provenance types and the four evidence statuses |
| [docs/limitations.md](docs/limitations.md) | What passive analysis cannot do — read this before trusting a result |
| [docs/threat-model.md](docs/threat-model.md) | Risks from untrusted captures and how each is bounded |
| [docs/test-strategy.md](docs/test-strategy.md) | Fixtures, determinism, what is and is not verified |
| [docs/requirements-matrix.md](docs/requirements-matrix.md) | SIH26159 requirement → module → milestone → test → status |
| [docs/adr/](docs/adr/) | Architecture decision records |
| [docs/milestones/](docs/milestones/) | Milestone reports |

## Security and privacy

Packet captures of email traffic can contain credentials, message bodies and
personal data. Read [SECURITY.md](SECURITY.md) before putting a real capture
anywhere near this repository. In short: captures are gitignored, reports omit
payloads, and `make secrets-check` refuses to let capture data be committed.

## Licence

No licence has been granted. All rights reserved by the authors pending an
explicit licensing decision.
