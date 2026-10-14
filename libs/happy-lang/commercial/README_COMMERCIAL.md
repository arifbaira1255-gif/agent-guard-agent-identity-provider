# Happy (`.hpy`) — The AI-Native, Security-First Programming Language

**Product:** Happy Language & Toolchain · **Version:** 1.0.0 · **Status:** Working prototype — fully implemented and tested
**Category:** Programming language + compiler + runtime + developer tooling (developer infrastructure / DevTools)

> A complete, self-contained programming language whose **contracts, capabilities, effects and
> permissions are enforced by real compiler and runtime machinery**, with a **first-class AI-native
> layer** and a **built-in security analyzer**. Implemented end-to-end on the Python standard
> library — **zero third-party runtime dependencies** — and ready to license, sell or acquire.

---

## 1. What Happy is

Happy is a statically-typed, contract-and-capability-oriented programming language. It ships as a
single toolchain that takes source through a full industrial pipeline:

```
Happy source (.hpy)
  → Lexer → Parser → AST
  → Semantic Analysis & Type Checking (types, generics, traits, modules)
  → IR → Optimizer
  → Python 3 code generation (with source maps)
  → Happy Runtime (contracts, capabilities, permissions, secrets, async)
  → Security Analyzer  +  AI-Native Layer  +  Developer Tooling
```

Every stage above is **implemented and executed by real code** in this repository — nothing is
documented that does not run. The full suite is green (**418 tests + 187 subtests**, `11/11` master
stages, release audit `0 errors / 0 warnings`) and reproducible on a clean machine.

---

## 2. Why it is different (the moat)

| Capability | What it means | Where it lives (real code) |
|---|---|---|
| **Contracts** | `requires` / `ensures` / `invariant` / `rule` checked **at runtime** and validated by the type checker, with diagnostics mapped back to `.hpy` lines | `happy/compiler/contracts.py`, `happy/runtime/contracts.py` |
| **Capabilities & Permissions** | Agents and functions declare the capabilities they hold; violations are compiler diagnostics **and** runtime errors (`R2001` / `R2002`) | `happy/compiler/permissions.py`, `happy/runtime/capability.py` |
| **Effects** | Effect declarations tracked and validated across calls | `happy/compiler/effects.py` |
| **Secret types** | `secret` values are wrapped; leaking them into logs/strings raises `R3001`, or redacts in warn mode | `happy/runtime/secrets.py` |
| **AI-native layer** | `ai` declarations compile to validated JSON plans; provider abstraction (OpenAI/Claude/Gemini/local); a **trust-ladder verification pipeline** gates any AI-generated code | `happy/ai/`, `happy/security/` |
| **Security analyzer** | A static rule engine (`SEC001`–`SEC010`) over the typed IR: secret exposure, unverified payments, permission escalation, unsafe IO, SSRF, path traversal, insecure deserialization, weak crypto, command injection, hardcoded secrets | `happy/security/analyzer.py` |
| **Async / concurrency** | `async`/`await`, `Task`, `Channel`, scheduler primitives | `happy/runtime/async_runtime.py` |
| **Zero dependencies** | Runs on the Python 3.9+ standard library only; trivial to audit and embed | `pyproject.toml` (`dependencies = []`) |

**Positioning in one line:** *"Rust-inspired safety discipline and Solidity-style explicit authority, applied to
practical application code — with an AI that can be trusted because its output must survive the
compiler, the contract engine, the security analyzer and the test suite before it is approved."*

---

## 3. Architecture summary

- **Front end** (`happy/compiler/`, 14 modules, ~11,500 LOC) — hand-written lexer with exact
  positions, deterministic recursive-descent parser, AST, static type system, symbol table,
  semantic analyzer, trait/conformance checking, exhaustive pattern matching, modules & imports.
- **IR + optimizer** — typed IR lowering and an optimization pass.
- **Backend** (`happy/backend/`, ~1,300 LOC) — IR → readable Python 3 with a **source map**
  (generated lines → original `.hpy` lines/columns) so runtime tracebacks point at Happy source.
- **Runtime** (`happy/runtime/`, ~2,300 LOC) — dynamic contract evaluation, capability/permission
  checks, secret protection, async runtime, and a `RuntimeContext` that wires it all together.
- **Standard library** (`happy/std/`, 17 modules) — `std.core`, `std.io`, `std.collections`,
  `std.json`, `std.async`, `std.crypto`.
- **AI layer** (`happy/ai/`, ~2,400 LOC) — provider abstraction + adapters, plan generator, agent
  capability sandbox, and the trust-ladder verifier.
- **Security** (`happy/security/`, ~950 LOC) — the static analyzer and rule engine.
- **Tooling** (`happy/cli/`, `happy/package/`, `happy/tools/`) — CLI (15 commands), package
  manager (`happy.toml` / `happy.lock`), AST-based deterministic formatter, linter, debugger,
  doc generator, REPL, publisher, and a JSON-RPC **LSP server**.

Full detail: see **`TECHNICAL_SPEC.md`** in this folder.

---

## 4. Verified results (measured, not marketing)

| Metric | Result | How to reproduce |
|---|---|---|
| Test suite | **418 passed, 187 subtests passed** in ~3 s | `python -m pytest -q` |
| Master integration runner | **11 / 11 stages passed** | `python tests/run_all_tests.py` |
| Release audit | **0 errors, 0 warnings** (6 checks) | `python scripts/audit.py` |
| Statement coverage | **51%** overall (12,274 statements; 10 files at 100%) | `coverage run --source=happy -m pytest && coverage report` |
| Compile speed | ~**280 full compiles/sec** (median ~3.5 ms / file) | `python benchmarks/benchmark.py` |
| Execution | ~**1,094 runs/sec** (median ~0.88 ms) | `python benchmarks/benchmark.py` |
| Examples | **4/4 `.hpy` examples compile & run** | `python -m happy run examples/*.hpy` |
| Codebase | 92 Python files · ~32,000 lines (of which ~5,800 are tests) | see `BENCHMARKS.md` |

Every number above traces to a reproducible command in this repository. Full per-stage timings,
per-module coverage and honesty notes are in **`BENCHMARKS.md`**.

---

## 5. Installation & quickstart

**Requires:** Python 3.9+ (CI targets 3.9–3.12). No third-party runtime dependencies.

```bash
# Install the toolchain from a checkout
pip install .

# Confirm
happy --version          # happy 1.0.0

# Create a project
happy new app my_app && cd my_app

# Write, check, build, run, test, format, lint, verify
happy check main.hpy
happy build main.hpy -o main.py
happy run   main.hpy
happy test
happy fmt   main.hpy --check
happy lint  main.hpy
happy verify main.hpy
```

Example Happy source:

```hpy
module demo.verified

type Point {
    x: Int
    y: Int
    invariant x >= 0, "x must be non-negative"
}

function add(a: Int, b: Int) -> Int
    requires a >= 0, "a must be non-negative"
    ensures result >= a
{
    return a + b
}

app Verified {
    let p = Point { x: 1, y: 2 }
    println(str(add(p.x, p.y)))
}
```

A self-guided, runnable tour for a buyer is in **`demo/`** (`run_demo.py` + `DEMO_WALKTHROUGH.md`).

---

## 6. Commercial highlights

- **Ready to operate as-is** — installable package, console entry point (`happy`), CI workflow, MIT
  license file present, `.gitignore`, CHANGELOG, and a passing release audit.
- **A rare asset class** — a complete language *plus* compiler *plus* runtime *plus* security model
  *plus* AI verification, in a single coherent, dependency-free codebase that one engineer produced
  in a handful of build steps. Most "AI codegen" products stop at generation; Happy is the
  **verification and enforcement layer** around it.
- **Multiple monetization paths** — see `LICENSING_ANALYSIS.md` (proprietary sale / dual-license /
  commercial license / acquisition).

---

## 7. Licensing summary

The repository currently carries an **MIT** `LICENSE` file as a placeholder. Commercialization
requires an explicit licensing decision by the owner **before** a sale; the recommended options and
trade-offs are laid out in **`LICENSING_ANALYSIS.md`**, with a ready-to-adapt **draft commercial
license agreement** in **`LICENSE_AGREEMENT_DRAFT.md`**. *(These documents are drafts for discussion,
not legal advice; a qualified attorney should review before execution.)*

---

## 8. Honest limitations

- **This is a working prototype, not a hardened production system.** Security is enforced at three
  levels — unknown calls rejected at compile time, sensitive operations without a capability denied
  at runtime, and a static analyzer — but there is **no OS-level isolation** (no separate process,
  container, or WASM sandbox). A hostile *program* restricted to the allowed builtins still executes
  in the host Python process; the guarantee is allowlist + capability enforcement, not a kernel jail.
- **Live AI calls require a vendor key.** `happy ai generate` uses a deterministic offline mock by
  default; calling a real model needs `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` or a
  `HAPPY_LOCAL_LLM_URL`. Everything else runs fully offline.
- **Coverage is uneven** — overall 51%; the CLI layer is the least-covered (9%), because most CLI
  paths are exercised end-to-end through the master runner rather than by unit tests.
- **Package registry is local** — `happy publish`/`add` operate on `.hpyz` archives and a path-based
  registry; there is no hosted remote registry service.
- **The backend targets Python 3** as its execution substrate (by design); Happy does not currently
  emit native machine code.

---

*All figures in this document were produced by running the commands cited above. No number has been
fabricated or estimated.*
