# Performance benchmarks

Measured performance of the complete analysis pipeline, from reading a capture
file to writing a report, on locally generated synthetic captures with known
ground truth.

Everything here is a measurement of one machine running one corpus. It is not a
claim about throughput on other hardware, on real traffic, or on captures whose
shape differs from the corpus. Where a number is too small to distinguish from
run-to-run variation, it is reported as such rather than presented as a result.

## How to reproduce

```
python scripts/run_benchmarks.py                 # small, medium, large
python scripts/run_benchmarks.py --profile all   # adds the stress profile
python scripts/check_benchmarks.py               # judge against the thresholds
```

Captures are generated into a temporary directory and deleted afterwards. None
enters the repository. `benchmarks/results.json` and `benchmarks/verdicts.json`
hold the machine-readable output and are committed.

## The corpus

`src/securemailscope/benchmarks/corpus.py` builds each profile from a fixed
seed (`20260921`), so the same profile produces the same capture on every run.
Sessions are interleaved in time rather than written one after another, so the
TCP reassembler sees concurrent flows as it would on a real capture. Each
profile carries ground truth: how many sessions, how many of them complete a
TLS handshake, how many carry a certificate, how many are plaintext.

| profile | sessions | of which plaintext | packets | bytes |
|---|---:|---:|---:|---:|
| small | 25 | 5 | 150 | 24,751 |
| medium | 200 | 40 | 1,200 | 194,673 |
| large | 1,000 | 200 | 6,000 | 971,126 |
| stress | 4,000 | 800 | 24,000 | 3,884,717 |

The stress profile is a deliberate over-run past the size the application
claims to support. It is measured and reported; its timing and memory figures
are not used as pass/fail criteria.

## Measurement method

Each profile is run once to warm the process — the first analysis pays for
imports, the rule registry and the ML model load, none of which is per-capture
work — and then three times with timing. The median is reported, with the
minimum and maximum so a reader can see the spread rather than trusting a
single number.

Peak resident memory is read from `getrusage`, normalised to megabytes
(`ru_maxrss` is bytes on macOS and kilobytes on Linux). It is the peak for the
whole process, so it includes the interpreter and the loaded models, not only
the analysis.

Stage timings are obtained by running the pipeline in three configurations —
forensic only, plus security assessment, plus machine learning — each three
times, and reporting the difference between medians. This is not a profiler. An
increment smaller than the observed run-to-run spread is flagged rather than
presented as a measurement of that layer.

## Recorded run

Environment: Python 3.12.14 on macOS 26.6.2, x86_64, 16 logical CPUs, scapy
2.6.1, pydantic 2.9.2, scikit-learn 1.5.2, numpy 2.1.3, reportlab 4.2.5,
SQLAlchemy 2.0.36. Three repeats per profile.

| profile | packets | bytes | median (s) | min | max | packets/s | MB/s | peak RSS (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| small | 150 | 24,751 | 0.089 | 0.082 | 0.090 | 1,686 | 0.28 | 190 |
| medium | 1,200 | 194,673 | 0.859 | 0.850 | 0.983 | 1,398 | 0.23 | 270 |
| large | 6,000 | 971,126 | 4.730 | 4.674 | 4.934 | 1,268 | 0.21 | 625 |
| stress | 24,000 | 3,884,717 | 21.426 | 21.328 | 22.097 | 1,120 | 0.18 | 1,800 |

Throughput in megabytes per second is low because these captures are small
packets: the work is per packet and per session, not per byte. The packets per
second column is the meaningful one.

### Correctness under load

Session and TLS handshake counts matched ground truth exactly at every profile,
including stress: 25/25, 200/200, 1,000/1,000 and 4,000/4,000 sessions, with
every session's handshake detected. Findings produced were 24, 171, 845 and
3,376 respectively. No profile produced a note or a discrepancy.

### Where the time goes

| profile | forensic only | + security assessment | + machine learning |
|---|---:|---:|---:|
| small | 0.066 s | +0.036 s (within noise) | +0.001 s (within noise) |
| medium | 0.599 s | +0.294 s | +0.038 s (within noise) |
| large | 3.587 s | +1.156 s | +0.145 s (within noise) |
| stress | 15.219 s | +4.718 s (within noise) | +9.525 s |

Reading this honestly: ingestion, TCP reassembly, protocol analysis and TLS
dissection dominate at every size, taking roughly three quarters of the time.
The security assessment adds about a third again on top of that. Machine
learning inference is too small to measure reliably below the stress profile —
the increments at small, medium and large are all inside the run-to-run spread,
which is why they are flagged rather than quoted.

The stress row is noisier than the others, and its "+4.718 s (within noise)"
should not be read as a measurement: at that size a single run of the forensic
pipeline varies by more than the assessment costs.

### Report sizes

| profile | JSON | HTML | PDF |
|---|---:|---:|---:|
| small | 199 KB | 93 KB | 46 KB |
| medium | 1.4 MB | 369 KB | 144 KB |
| large | 6.3 MB | 1.6 MB | 537 KB |
| stress | 24.6 MB | 6.1 MB | 2.0 MB |

## Acceptance thresholds

Thresholds were written down in `benchmarks/thresholds.json` and committed
before the results they judge, so the order is visible in the repository
history rather than asserted here. Each one is derived from the deployment
target — an analyst laptop with 4 cores and 8 GB of RAM — and carries its
justification in the file.

An exploratory run had been executed before the thresholds were written, so the
author had seen approximate figures. This is disclosed in the thresholds file
itself. The derivations stand on the deployment target and can be judged on
their own terms.

### Verdicts

`python scripts/check_benchmarks.py` produced the following, recorded in
`benchmarks/verdicts.json`:

| id | scope | metric | observed | threshold | result |
|---|---|---|---:|---:|---|
| T1 | medium | packets/second | 1,397.5 | ≥ 500 | PASS |
| T2 | medium→large | time scaling exponent | 1.060 | ≤ 1.2 | PASS |
| T3 | large | peak RSS (MB) | 625.2 | ≤ 2048 | PASS |
| T4 | medium→large | RSS growth (KB/packet) | 75.7 | ≤ 100 | PASS |
| T5 | small, medium, large | largest report (bytes) | 6,277,058 | ≤ 33,554,432 | PASS |
| T6 | all four | ground truth matched | true | true | PASS |
| T7 | small, medium, large | max/min run ratio | ≤ 1.157 | ≤ 2.0 | PASS |

All fourteen gated checks passed.

### A repeat run on a contended machine

The recorded run above was taken on an otherwise-quiet machine. A confirmation
run taken later, while unrelated work was holding the load average between 14
and 20 on 16 logical CPUs, measured **257 packets/second on the medium
profile** — roughly a fifth of the 1,398 recorded above, and a clear **FAIL**
against T1's 500 packets/second.

This is recorded rather than discarded, because it establishes something the
headline figures do not: the throughput threshold is met on an idle machine and
is not met on a busy one. The run-to-run ratios in that same contended run
stayed within T7 (1.315, 1.327 and 1.867), so the measurement itself was
internally consistent — it was consistently slow, not erratic.

Neither the threshold nor the published figures were changed in response. T1
stands at 500 packets/second, and the numbers in the table above remain those
of the clean run, labelled as such.

The practical reading: SecureMailScope wants the machine's attention while it
analyses. On a laptop that is also running a browser, a build and a video call,
expect materially worse than the table above.

## What these numbers do not establish

**The thresholds were derived for weaker hardware than the machine that ran
them.** They assume 4 cores and 8 GB; the recorded run used a machine with 16
logical CPUs. A pass here does not prove a pass on the assumed minimum, and no
measurement on 4-core/8 GB hardware has been taken.

**Memory is the constraint that will bite first.** T4 came in at 75.7 KB per
packet against a 100 KB limit — the narrowest margin of any threshold. Peak
resident memory is 625 MB for a 6,000-packet capture and 1.8 GB for a
24,000-packet one. Two concurrent analyses share one process, so a second job
of comparable size on the target machine would approach or exceed the
budget. The application should not be described as handling 24,000-packet
captures on an 8 GB machine.

**Synthetic captures are not real traffic.** The corpus is generated from a
fixed set of seven cipher suites with a regular session structure. Real
captures have retransmissions, out-of-order segments, more varied handshakes
and longer-lived connections. Nothing here measures those.

**Concurrency is not benchmarked.** Every figure is one analysis at a time. The
backend's two-worker pool is exercised for correctness in
`tests/test_reliability.py`, not for throughput.

**The figures assume the machine is otherwise idle.** See the contended run
above: unrelated load cut throughput to a fifth and took the medium profile
below its threshold.

**Continuous integration does not validate these numbers.** The benchmark job
in CI runs the small and medium profiles to prove the harness works and the
ground truth still matches. A shared runner is not the target hardware, so its
timings judge nothing and the job is marked `continue-on-error`.
