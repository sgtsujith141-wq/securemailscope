# Architecture decision records

Short records of decisions that were not obvious, including what was rejected
and why. Each one states the context that forced a choice, so a future reader
can tell whether that context still holds.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-engine-independent-of-web-stack.md) | The forensic engine is independent of FastAPI, React and any LLM | Accepted |
| [0002](0002-custom-container-reader.md) | Parse pcap/pcapng framing directly; use Scapy for dissection | Accepted |
