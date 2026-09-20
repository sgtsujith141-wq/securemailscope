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
| Protocol hints | **PARTIAL** | Port-derived hints only, always labelled `INFERRED` |
| SMTP / IMAP / POP3 parsing | NOT IMPLEMENTED | M2 |
| STARTTLS / implicit TLS detection | NOT IMPLEMENTED | M2 / M3 |
| TLS handshake analysis | NOT IMPLEMENTED | M3 |
| Certificate assessment | NOT IMPLEMENTED | M3 / M4 |
| Risk assessment and findings | NOT IMPLEMENTED | M4 |
| Evidence correlation | NOT IMPLEMENTED | M5 |
| ML-assisted analysis | NOT IMPLEMENTED | M6 |
| REST backend / web UI | NOT IMPLEMENTED | M7+ |

The engine emits **no TLS or certificate findings of any kind**. Nothing in
this repository fabricates a cryptographic observation.

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

### Try it without a capture of your own

```bash
make fixtures
securemailscope analyze tests/fixtures/generated/f_missing_segment.pcap --quiet | jq '.sessions[0].client_to_server | {bytes_reconstructed, runs, gaps}'
```

## What the report contains

Every statement carries its evidence. The output distinguishes:

- **Confirmed facts** — `EvidenceStatus.OBSERVED`, read directly from captured bytes
- **Hints and derivations** — `INFERRED`, with a recorded `basis` and explicit `limitations`
- **Unknowns** — `UNKNOWN` (this capture does not determine it) and
  `NOT_AVAILABLE` (passive capture cannot determine it, or the stage is not built)

Reconstructed data is reported as **contiguous runs with offsets**, never as a
single blob: if bytes are missing, you get two runs and an explicit gap, and
the gap's contents stay `UNKNOWN`.

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
