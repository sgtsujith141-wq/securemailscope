# Threat model

SecureMailScope's input is a file supplied by someone else, and its subject
matter is other people's mail. Both facts generate risk. This document lists
what can go wrong, what the code does about it, and what remains open.

Scope: the M0/M1 engine and CLI. The backend and frontend do not exist yet;
their threats are listed as deferred so they are not forgotten.

## Assets

| Asset | Why it matters |
|---|---|
| Capture contents | May contain credentials, message bodies, recipient lists, personal data |
| Analysis reports | Disclose IP addresses, ports, timings and byte counts even without payload |
| The analyst's machine | Parsing untrusted input on it |
| The git repository | A single careless `git add -f` publishes a capture permanently |

## Adversaries

- **A hostile capture author** who crafts a file specifically to break the parser.
- **Traffic that was itself adversarial** — an attacker who used overlapping
  TCP segments to desynchronise a monitor from an endpoint.
- **Accident** — the most likely adversary. A developer commits a capture, or
  emails a report containing a message body.

---

## T1. Untrusted capture file contents

**Risk.** Parsing attacker-controlled binary data. Malformed lengths, inconsistent
headers, absurd counts, deeply nested encapsulation.

**Controls.**
- Format is decided by magic bytes only; the extension is never consulted. A
  file that is not a libpcap or pcapng container is rejected outright with
  `UnsupportedCaptureFormatError`.
- Container framing is parsed by hand with explicit bounds on every field
  (`ingestion/pcap_reader.py`, `ingestion/pcapng_reader.py`) rather than by a
  library whose failure modes we do not control.
- Every structural inconsistency becomes a typed diagnostic and stops parsing
  at that point; it never raises out of the engine and never fabricates data.
- Link types outside an explicit allowlist produce `UNSUPPORTED_LINK_TYPE` and
  their packets are skipped. Bytes we cannot interpret never become a session.
- Packets that fail dissection are counted and reported, not guessed at.

**Residual risk.** Scapy's IP and TCP dissectors are Python code that has not
been hardened against adversarial input, and we rely on them. Analyse captures
of unknown provenance in an isolated environment.
*Test:* `tests/test_ingestion.py` (rejection paths, corrupt `incl_len`),
`tests/test_formats.py`.

## T2. Memory exhaustion

**Risk.** A small file that expands into unbounded memory: a 4 GiB declared
packet length, millions of one-byte segments, a hundred thousand concurrent
flows, or an enormous reassembled stream.

**Controls.** Eight hard ceilings, all configurable, all checked:

| Limit | Default | What it bounds |
|---|---|---|
| `max_capture_bytes` | 512 MiB | File size, checked **before** any parsing |
| `max_packets` | 2,000,000 | Records read from one capture |
| `max_packet_bytes` | 256 KiB | A single record; a corrupt `incl_len` is refused on the header, before the read |
| `max_total_payload_bytes` | 256 MiB | Reconstructed data across all sessions |
| `max_session_payload_bytes` | 16 MiB | Reconstructed data per session |
| `max_concurrent_sessions` | 10,000 | Simultaneously open connections |
| `max_total_sessions` | 100,000 | Connections recorded per capture |
| `max_segments_per_direction` | 200,000 | Provenance records per direction |

Plus `max_gaps_per_direction` (10,000) and `max_warnings_per_code` (100) to
bound the *output* as well as the working set. pcapng block length is
separately capped at 64 MiB so a corrupt length field cannot trigger a large
allocation.

Container parsing is streaming: one packet record is resident at a time
regardless of file size. Reaching any limit produces a diagnostic and marks the
affected object truncated — analysis degrades, it does not crash, and it never
pretends the result is complete.
*Test:* `tests/test_ingestion.py::test_*_limit_*`.

## T3. Path traversal and filesystem abuse

**Risk.** A supplied path escaping an intended directory, or a symlink pointing
somewhere sensitive.

**Controls.** Paths are `expanduser().resolve()`d and must be an existing
regular file. Directories, devices and non-existent paths are rejected with
`CaptureNotFoundError`. Reports record only `path.name`, so a report never
discloses the analyst's directory layout.

**Residual risk.** The CLI reads any file the invoking user can read; that is
inherent to a local tool. When the M7 backend adds uploads it must confine
storage to a configured directory and generate its own server-side filenames —
this is recorded here so it is not forgotten.
*Test:* `tests/test_report.py::test_report_records_only_the_file_name_not_the_path`.

## T4. Command injection via filenames

**Risk.** A capture named `` `id`.pcap `` or `a; rm -rf ~` reaching a shell.

**Controls.** The package contains no `subprocess`, no `os.system`, no
`shell=True`, and no string-interpolated command anywhere. Paths are handled as
`pathlib.Path` objects end to end. A test monkeypatches `subprocess.Popen`,
`run` and `call` to raise, then runs a full analysis; another analyses a file
whose name contains shell metacharacters.
*Test:* `tests/test_passive.py::test_analysis_spawns_no_subprocess`,
`::test_shell_metacharacters_in_filename_are_harmless`.

## T5. Accidental exfiltration — the tool contacting the network

**Risk.** A passive tool that is not actually passive: alerting a captured host
that it is being analysed, or shipping capture contents to a service.

**This is not hypothetical.** Scapy is primarily a packet *crafting* library.
Building an `Ether()` layer with an unresolved destination MAC makes it emit a
**live ARP or Neighbour Solicitation**. This was hit during development of this
project's own fixture generator.

**Controls.**
- Importing `securemailscope` installs a guard that replaces Scapy's neighbour
  resolver with one that raises `PassiveModeViolation`.
- The read path strips link-layer headers by hand and hands only IP bytes to
  Scapy, keeping the crafting machinery out of analysis entirely.
- `conf.use_pcap = False` prevents live capture handles being opened.
- No HTTP client, socket, or DNS lookup exists anywhere in the package. There
  is no telemetry and no cloud AI call.
- A test monkeypatches `socket.socket`, `create_connection` and `getaddrinfo`
  to raise, then runs a full analysis.
*Test:* `tests/test_passive.py`.

## T6. Accidental publication to git

**Risk.** A capture, a key log, or a `.env` committed and pushed. Git history
is effectively permanent; a force-push does not undo a clone.

**Controls.**
- `.gitignore` excludes every capture extension, `data/`, `captures/`,
  `samples/`, `evidence/`, key material, `.env`, TLS key logs, analysis output
  and `tests/fixtures/generated/`.
- `scripts/check_staged.sh` (`make secrets-check`) inspects the staging area
  and refuses if capture data, key material or an environment file is staged.
- Synthetic fixtures are **not** committed. The generator and the expectation
  manifests are committed instead, so captures are reproducible byte for byte
  without existing in history.
- The repository is private and carries no licence grant.

**Residual risk.** `git add -f` defeats both controls. Look at `git status`.

## T7. Report injection

**Risk.** Attacker-controlled bytes from a capture flowing into a report and
being interpreted as markup, a formula, or a terminal escape by whatever opens
it.

**Controls.**
- Reports contain **no application payload bytes at all** — only counts,
  offsets, SHA-256 digests and packet references. The main injection vector
  does not exist.
- The single free-text field influenced by capture content is the pcapng
  interface name, decoded with `errors="replace"`.
- IP addresses and ports are rendered from parsed numeric fields, not copied
  from the file.
- Output is `json.dumps`, which escapes control characters.
- A test asserts that known fixture payload text never appears in a serialised
  report, as text or as hex.

**Deferred.** When the M8 UI renders reports it must not use
`dangerouslySetInnerHTML`, and any CSV export must guard against formula
injection (`=`, `+`, `-`, `@` prefixes).
*Test:* `tests/test_report.py::test_report_never_contains_payload_bytes`.

## T8. Subprocess invocation

**Risk.** Shelling out to `tshark`, `capinfos` or `editcap` — a common shortcut
in capture tooling — introduces argument injection, version-dependent output
parsing and an unbounded external process.

**Control.** The engine invokes no external program. Container parsing,
dissection and reassembly are all in-process. This is a deliberate constraint,
not an omission.
*Test:* `tests/test_passive.py::test_analysis_spawns_no_subprocess`.

## T9. Misleading output — the analytical threat

**Risk.** The subtlest failure mode: the tool is *wrong* in a way that looks
authoritative. A gap silently closed, a retransmission counted twice, an
inference displayed as a fact, an unimplemented stage read as "nothing found".

**Controls.**
- Four explicit evidence statuses; `INFERRED` values must carry `limitations`.
- Reconstructed data is exposed as contiguous runs; there is no API that joins
  across a gap.
- Overlapping conflicts are preserved, with both digests, under a documented
  `FIRST_OBSERVED_WINS` policy — never resolved silently.
- Session completeness is a four-state enum plus a list of every contributing
  reason, so "complete" means handshake observed, termination observed, no
  holes and no truncation.
- Every report embeds `stage_status`, so a reader can distinguish "no TLS
  findings because there was no TLS" from "no TLS findings because TLS analysis
  does not exist yet".
- Fixture manifests are hand-derived, so the test suite cannot rubber-stamp a
  regression.
*Test:* the whole of `tests/test_reassembly.py`.

## T10. Adversarial traffic — overlapping segment desynchronisation

**Risk.** An attacker sends overlapping TCP segments with different contents so
that a monitor and the real endpoint reconstruct different byte streams. Any
single reassembly policy will disagree with some operating system.

**Control.** The engine does not pretend to resolve this. It applies a
documented policy, reports every conflict with both digests and both packet
numbers, and downgrades the session's completeness with an explicit note. An
analyst is told the reconstruction is *one possible* interpretation.

**Residual risk.** Policy-dependent reconstruction is inherent to passive
analysis. Per-OS policy emulation (BSD, Linux, Windows variants) is a possible
later enhancement.
*Test:* `tests/test_reassembly.py::test_overlap_conflict_keeps_the_first_observation`.

## T11. Supply chain

**Risk.** A compromised dependency executing at import time, inside a process
that holds capture data.

**Controls.** Exactly two runtime dependencies (`scapy`, `pydantic`), both
pinned to exact versions. `fastapi`, `cryptography` and `scikit-learn` are
optional extras, not installed or imported by the engine. Installation is the
only outbound network activity in the project.

**Residual risk.** No hash pinning and no lock file yet. Adding a
`requirements.lock` with hashes is a recommended follow-up.

---

## Deferred to later milestones

| Threat | Milestone | Note |
|---|---|---|
| Upload handling, storage confinement, server-side filenames | M7 | Uploads must land in a configured private directory |
| Authentication and authorisation for the API | M7 | Reports disclose network topology |
| Denial of service against the backend | M7 | Per-request limits and concurrency caps |
| XSS and formula injection in the UI and exports | M8 | Escape all capture-derived strings |
| Poisoned training data for ML | M6 | Models must be trained on local, auditable data only |
| SQLite file permissions and at-rest protection | M7 | Reports are sensitive even without payload |
