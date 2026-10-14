# Happy (.hpy) — Benchmarks & Verified Metrics

**All numbers below are measured, not estimated.** They were produced by running the commands shown,
on the machine recorded in the benchmark JSON. Re-run everything yourself:

```bash
python benchmarks/benchmark.py --repeat 15 --out benchmarks/benchmark_results.json
python -m pytest -q
python tests/run_all_tests.py
python scripts/audit.py
coverage run --source=happy -m pytest && coverage report
```

Environment: Python **3.11.15**, Linux. Benchmark subject: `examples/backend_demo.hpy`
(102 lines `.hpy`), 15 timed runs per stage plus 3 warm-up runs.

---

## 1. Correctness & quality

| Metric | Result | Command |
|---|---|---|
| Unit + integration tests | **418 passed, 187 subtests passed** in ~3 s | `python -m pytest` |
| Master integration runner | **11 / 11 stages passed** | `python tests/run_all_tests.py` |
| Release audit | **0 errors, 0 warnings** (6 checks) | `python scripts/audit.py` |
| Official examples | **4 / 4** compile and run | `python -m happy run examples/*.hpy` |
| Formatter idempotence | **True** (format(format(x)) == format(x)) | benchmark harness |

The 11 master stages cover: pytest, CLI smoke (`check`/`build`/`run`/`fmt`/`lint`/`verify`/
`ai generate`/`new`+run), package-manager round-trip, and the LSP round-trip.

---

## 2. Compiler & runtime latency

| Stage | min (ms) | mean (ms) | median (ms) | p95 (ms) | ops/sec |
|---|---|---|---|---|---|
| lex | 1.780 | 1.826 | 1.801 | 1.845 | 547.7 |
| parse | 2.418 | 2.434 | 2.432 | 2.448 | 410.9 |
| semantic / type-check | 2.755 | 3.027 | 2.771 | 2.921 | 330.3 |
| IR lowering | 0.340 | 0.366 | 0.354 | 0.404 | 2,732.9 |
| optimize | 0.051 | 0.053 | 0.052 | 0.056 | 18,730.1 |
| Python codegen | 0.151 | 0.159 | 0.157 | 0.167 | 6,302.5 |
| **compile (source → Python)** | 3.462 | 5.278 | 3.493 | 3.612 | 189.5 |
| **end-to-end execute** | 0.839 | 0.914 | 0.880 | 1.009 | 1,094.1 |
| security analyze | 3.672 | 4.700 | 3.705 | 8.165 | 212.8 |
| format | 2.521 | 2.536 | 2.534 | 2.549 | 394.3 |
| lint | 2.595 | 2.890 | 2.887 | 3.137 | 346.0 |
| compile whole corpus (4 files) | 29.126 | 39.470 | 33.955 | 53.989 | 25.3 |

**How to read this:** a *full compile* of a real 102-line program to executable Python takes a
**median of ~3.5 ms** (~280 compiles/sec before optimization-noise), and that compiled program
**executes in a median of ~0.88 ms** (~1,094 runs/sec). Compilation is dominated by the front end
(lex + parse + semantic); IR lowering, optimization and codegen together are sub-millisecond.

*Note on the mean of `compile_to_python` and `security_analyze`:* their p95 shows occasional spikes
(GC/scheduler noise in the measuring interpreter). Min and median are the stable figures; means are
reported for transparency, not used in any claim.

---

## 3. Debuggability metric

| Metric | Value |
|---|---|
| Generated Python lines (for the 102-line subject) | **112 lines** |
| Build size ratio (generated LOC / Happy LOC) | **1.098×** |
| Source-map anchors | **64** |

The backend emits Python whose size is essentially 1:1 with the Happy source, and records 64
line/column anchors so a runtime traceback maps back to the original `.hpy` location (e.g.
`demo.hpy:4:5: error: [R1003] …`).

---

## 4. Test coverage (statement coverage)

Overall: **51%** of 12,274 statements (10 files at 100%). Per module:

| Module | Statements | Coverage |
|---|---|---|
| `happy/ai` | 994 | **78.0%** |
| `happy/security` | 356 | **75.6%** |
| `happy/compiler` | 5,998 | **64.7%** |
| `happy/runtime` | 979 | 43.0% |
| `happy/backend` | 770 | 40.0% |
| `happy/package` | 402 | 39.1% |
| `happy/pipeline.py` | 110 | 39.1% |
| `happy/tools` | 1,520 | 21.1% |
| `happy/cli` | 390 | **9.0%** |

**Honest note:** coverage is deliberately reported as-is. The **CLI layer's low 9%** is because CLI
behaviour is exercised end-to-end by the master runner (subprocess invocations) rather than by
in-process unit tests — so *observed working* behaviour exceeds what statement coverage captures.
The front end (the largest and most critical module) is at 64.7%.

---

## 5. Repository size

| Metric | Value |
|---|---|
| Python files | 92 |
| Python lines | 32,058 |
| Test files / lines | 16 / 5,814 |
| `.hpy` example lines | 308 |
| Package initializers (modules) | 10 |
| Runtime third-party dependencies | **0** |

---

## 6. What was NOT benchmarked

Stated plainly to avoid over-claiming:

- **Live AI provider latency** — the AI layer is benchmarked offline with the deterministic mock
  provider; calling a real OpenAI/Claude/Gemini endpoint depends on network and vendor latency and is
  **not** measured here.
- **LSP throughput** — the LSP round-trip is verified functionally (master runner) but not timed.
- **Memory footprint** — not profiled in this harness.
- **Native-code performance** — Happy targets Python 3 by design; no native backend exists to bench.

---

*Reproduce any figure above with the commands in the header. If a command on your machine yields a
different number, that is expected — these are latency measurements, not fixed constants.*
