# Backend

**STATUS: NOT IMPLEMENTED.** Planned for M7.

This directory is a placeholder. There is no FastAPI application, no route, no
database schema and no server process yet.

When it is built, it will be a thin adapter: upload a capture, call
`securemailscope.analyze_capture`, persist the result to a local SQLite file,
serve it back. The forensic engine will not import anything from here. See
[../docs/adr/0001-engine-independent-of-web-stack.md](../docs/adr/0001-engine-independent-of-web-stack.md)
for why that boundary exists and why it is worth keeping.

Until then, the CLI is the complete interface:

```bash
securemailscope analyze capture.pcap --output result.json
```
