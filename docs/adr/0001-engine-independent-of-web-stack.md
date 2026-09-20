# ADR 0001: The forensic engine is independent of FastAPI, React and any LLM

- **Status:** Accepted
- **Date:** 2026-09-21
- **Milestone:** M0

## Context

SecureMailScope's target architecture includes a FastAPI backend, a React
frontend, SQLite persistence and, eventually, ML-assisted analysis. The obvious
way to build such a system is to start with the web application and grow the
analysis logic inside it — request handlers that parse captures, ORM models
that double as analysis types, a UI that drives the feature list.

That approach is what produces the failure this project is specifically trying
to avoid: a convincing dashboard sitting on top of analysis nobody can verify.

Two additional pressures argue the same way. Hackathon projects are judged on
demonstrations, which rewards visible surface over correct internals. And LLM
assistance makes it very easy to generate a plausible-looking finding that has
no evidentiary basis at all.

## Decision

The forensic engine is a standalone, importable Python package with **no
dependency on any web framework, server, database, frontend or language model**.

Concretely:

1. `securemailscope` depends on exactly two runtime packages: `scapy` and
   `pydantic`. `fastapi`, `cryptography` and `scikit-learn` are declared as
   optional extras and are neither installed nor imported by the engine.
2. `analyze_capture(path, config)` is a pure function of its inputs. No global
   state, no service, no I/O beyond reading the capture.
3. The CLI is the reference interface and must stay fully capable. Anything the
   future API can do, the CLI can already do.
4. Dependencies point one way: `models/` imports nothing from the project;
   `ingestion/` does not know what a session is; `network/` does not know what
   a report is. A future `backend/` may import the engine; the engine will
   never import from `backend/`.
5. No analysis result is produced by, validated by, or explained by a language
   model. The engine must produce the same output on a machine with no network
   access and no model available.

## Consequences

**Good.**

- The engine is testable without a server. The 168 tests in this repository run
  in about eight seconds with no fixtures beyond generated files.
- Correctness is demonstrable at the unit level instead of through a UI.
- A demonstration failure in the web layer cannot invalidate the forensic
  results, and the forensic results can be reproduced by anyone with Python.
- The M1 effort went into TCP reassembly — the foundation every later milestone
  stands on — rather than into scaffolding.
- If the web stack is later replaced entirely, nothing of value is lost.

**Costs.**

- Two interfaces to maintain once the API exists; the CLI cannot be allowed to
  rot into a second-class path.
- Some duplication between CLI argument parsing and future request schemas.
- No web UI to show during an M1 demonstration. The CLI's JSON output and the
  test suite are the demonstration.

## Alternatives rejected

**Build the API first and extract the engine later.** Extraction is rarely
performed once a deadline is near, and by then the analysis types have
absorbed ORM and serialisation concerns.

**Let an LLM generate findings.** An LLM cannot cite a packet number it did not
compute. The project's core promise is provenance; a generated finding has
none. An LLM may later help *explain* a finding the engine produced, with the
evidence attached, but it will never produce one.

## Related

- [0002-custom-container-reader.md](0002-custom-container-reader.md)
- [../architecture.md](../architecture.md)
