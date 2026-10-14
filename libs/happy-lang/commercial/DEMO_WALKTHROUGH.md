# Happy (.hpy) — Demo Walkthrough

A buyer can run the whole toolchain themselves in under two minutes. No API keys, no network, no
third-party packages required.

---

## 0. Prerequisites

- **Python 3.9+** (the CI matrix covers 3.9–3.12; the demo above was verified on 3.11).
- That's it — Happy has **zero third-party runtime dependencies**.

## 1. Install (from a clean checkout)

```bash
pip install .          # installs the `happy` toolchain + console entry point
happy --version        # -> happy 1.0.0
```

## 2. The guided end-to-end demo

```bash
python demo/run_demo.py
```

This runs the **real** pipeline in five visible stages and prints the result of each:

1. **COMPILE** — `.hpy` source → Python 3, showing the generated code and source map.
2. **RUN** — executes the program inside the Happy Runtime and prints its output.
3. **TOOLING** — runs the formatter and the linter.
4. **SECURITY** — runs the static analyzer over the typed IR.
5. **ENFORCEMENT** — deliberately violates a `requires` contract and shows the run **fail
   (fail-closed)**, proving enforcement is real, not decorative.

> The demo prints only what the toolchain actually produces.

## 3. Drive the CLI yourself

From the package root:

```bash
# compile & run one of the shipped examples
python -m happy run examples/language_tour.hpy

# check / build / format / lint / verify a program
python -m happy check  examples/verified_demo.hpy
python -m happy build  examples/backend_demo.hpy -o /tmp/demo.py
python -m happy fmt    examples/backend_demo.hpy
python -m happy lint   examples/backend_demo.hpy
python -m happy verify examples/verified_demo.hpy      # trust-ladder AI verification

# scaffold and run a brand-new project
python -m happy new app hello && cd hello
python -m happy run main.hpy
```

## 4. See the security model at work

The linter and the security analyzer report findings with stable codes:

- Contracts: `R1001`–`R1005` · Capabilities/Permissions: `R2001`/`R2002` · Secrets: `R3001`.
- Static rules: `SEC001`–`SEC010` (secret exposure, unverified payments, permission escalation,
  unsafe IO, SSRF, path traversal, insecure deserialization, weak crypto, command injection,
  hardcoded secrets).

Run `python -m happy lint examples/backend_demo.hpy` and
`python demo/run_demo.py` to see them.

## 5. Reproduce the headline numbers

```bash
python -m pytest -q                 # 418 passed, 187 subtests
python tests/run_all_tests.py       # 11/11 master stages
python scripts/audit.py             # 0 errors, 0 warnings
python benchmarks/benchmark.py      # real per-stage timings
```

## 6. What you are looking at

| Folder | What it holds |
|---|---|
| `happy/` | the compiler, backend, runtime, stdlib, AI layer, security, CLI, package manager, tools |
| `tests/` | 16 test modules + the master runner |
| `examples/` | runnable `.hpy` programs |
| `benchmarks/` | the reproducible benchmark harness + results JSON |
| `commercial/` | this walkthrough, the commercial README, tech spec, one-pager, pitch deck, licensing docs, benchmarks |
| `demo/` | the guided demo script |

---

*If any command behaves differently on your machine, that is a real signal — the demo prints the
toolchain's own output, so nothing is staged or pre-recorded.*
