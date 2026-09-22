# Architecture

Derived from the code in `src/securemailscope/`, not drawn from intention. Line
counts are `wc -l` over each package.

## Pipeline

```
                          ┌─────────────────────────────┐
     PCAP / PCAPNG  ──────▶│  ingestion/      1,166 loc │
     (untrusted, on disk)  │  format from content, not  │
                           │  extension; 8 hard limits  │
                           └──────────────┬──────────────┘
                                          │ packets, numbered, timestamped
                                          ▼
                           ┌─────────────────────────────┐
                           │  network/         ~900 loc  │
                           │  TCP reconstruction:        │
                           │  reorder, retransmit, gaps, │
                           │  overlap conflicts, reuse   │
                           └──────────────┬──────────────┘
                                          │ bidirectional sessions
                       ┌──────────────────┴──────────────────┐
                       ▼                                     ▼
        ┌─────────────────────────────┐       ┌─────────────────────────────┐
        │  protocols/      3,406 loc  │       │  tls/            3,042 loc  │
        │  SMTP / IMAP / POP3 state   │       │  record framing, handshake  │
        │  machines. Protocol from    │       │  reassembly, version,       │
        │  the dialogue, never the    │       │  cipher suite, key exchange │
        │  port. STARTTLS boundary.   │       │  forward secrecy            │
        └──────────────┬──────────────┘       └──────────────┬──────────────┘
                       │                                     │
                       │                                     ▼
                       │                      ┌─────────────────────────────┐
                       │                      │  certificates/     861 loc  │
                       │                      │  X.509 parse, RFC 5280 path │
                       │                      │  verification, hostname,    │
                       │                      │  dates. TLS 1.3: encrypted  │
                       │                      └──────────────┬──────────────┘
                       └──────────────────┬──────────────────┘
                                          ▼
                           ┌─────────────────────────────┐
                           │  assessment/     3,416 loc  │
                           │  25 rules, versioned policy │
                           │  explainable score,         │
                           │  priority matrix,           │
                           │  12 remediations            │
                           └──────────────┬──────────────┘
                                          │ findings, each citing a packet
                       ┌──────────────────┴──────────────────┐
                       ▼                                     ▼
        ┌─────────────────────────────┐       ┌─────────────────────────────┐
        │  intelligence/   2,275 loc  │       │  ml/             3,196 loc  │
        │  cryptographic fingerprint, │       │  93-feature schema,         │
        │  server identity, drift,    │       │  rarity baseline in use,    │
        │  correlation, timeline,     │       │  Isolation Forest held back │
        │  blast radius               │       │  classifier NOT_VALIDATED   │
        └──────────────┬──────────────┘       └──────────────┬──────────────┘
                       └──────────────────┬──────────────────┘
                                          ▼
                           ┌─────────────────────────────┐
                           │  reporting/      1,582 loc  │
                           │  ONE canonical ReportModel  │
                           │  ├─ JSON   (schema 1.4.0)   │
                           │  ├─ HTML   (self-contained) │
                           │  └─ PDF    (ReportLab)      │
                           └─────────────────────────────┘
```

## Application

```
   Browser (localhost only)
   ┌──────────────────────────────┐
   │ frontend/  4,395 loc TS/TSX  │
   │ React 18 · strict TS · Vite  │
   │ 9 pages, 1 canonical API     │
   └──────────────┬───────────────┘
                  │ fetch, token in a header (never in source)
                  ▼
   ┌──────────────────────────────┐        ┌───────────────────────────┐
   │ backend/    2,756 loc        │───────▶│ SQLite (outside the repo) │
   │ FastAPI on 127.0.0.1 only    │        │ 3 explicit migrations     │
   │ · host allowlist (rebinding) │        │ foreign keys enforced     │
   │ · explicit CORS origins      │        └───────────────────────────┘
   │ · per-install token, 0600    │
   │ · bounded collections        │        ┌───────────────────────────┐
   │ · streamed upload validation │───────▶│ capture store             │
   │ · ThreadPoolExecutor(2)      │        │ outside the repo and the  │
   └──────────────┬───────────────┘        │ web root; server-named    │
                  │                        └───────────────────────────┘
                  ▼
   ┌──────────────────────────────┐
   │ the SAME engine above.       │
   │ FastAPI is an adapter, not a │
   │ second implementation.       │
   └──────────────────────────────┘
```

## The boundary that matters

Nothing in the diagram points outward. The engine opens no socket: the only
network path in the whole system is the browser talking to `127.0.0.1`, which
is the application's own interface, not contact with anything observed in a
capture.

`securemailscope.scapy_guard` replaces Scapy's neighbour resolver with one that
raises, because Scapy will otherwise emit real ARP or NDP when asked to build a
link layer with an unresolved MAC. That is the one place the dissection library
could have spoken on the wire, and it is disabled.

`tests/test_robustness.py` proves it rather than asserting it: socket
constructors are replaced with functions that raise, and analysis, batch
analysis and all three renderers are run through them.

## Dependency floor

The forensic engine depends on three packages — `scapy`, `pydantic`,
`cryptography` — and nothing else. FastAPI, SQLAlchemy, scikit-learn, ReportLab
and Jinja2 are optional extras. `tests/test_dependencies.py` walks the AST of
every engine module and imports the pipeline in a subprocess to prove the web
and ML stacks are absent, so a vulnerability in the web layer cannot reach the
analysis path.
