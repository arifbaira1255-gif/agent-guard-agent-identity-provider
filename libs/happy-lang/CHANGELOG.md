# Changelog

All notable changes to the Happy (`.hpy`) language toolchain are documented
here. The format follows [Keep a Changelog](https://keepachangelog.com/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## Security hardening pass (v10)

- runtime: unknown operations fail closed; agent scope is per-task (ContextVar); nested runs restore the outer context and std checkers; gated calls with no active context are denied; `_MemoryGuard` no longer shadows `Thread._stop`.
- analyzer: SEC011 now covers plain functions reachable from an app; new SEC012 flags aliased sensitive built-ins; more sensitive ops tracked.
- ai.tools: capability gate works with the real `AgentSandbox` and fails closed; hard per-call timeout, output token cap, arg isolation, per-turn call cap, tool output fenced as untrusted.
- ai.sandbox: output capped, process group killed on timeout.
- sourcemap: strict out-of-range resolve, validated `from_dict`.
- tests: `tests/test_regression_v10_security.py` (35 tests).
- isolation: new `happy.ai.isolation` (docker/podman, bubblewrap, Linux namespaces) wired into `run_sandboxed_python`; `HAPPY_ISOLATION=required` fails closed; `python -m happy.ai.isolation` self-test; `deploy/Dockerfile.sandbox`; `docs/isolation.md`.

## v9.2 — static contract proofs

### Added
- **Static contract prover** (`happy/compiler/contract_proofs.py`, no external solver). `requires` / `ensures` / `invariant` are now proved or refuted *at compile time* with interval abstract interpretation: branch conditions narrow variables (`if a < 0 { return 0 - a } else { return a }` proves `ensures result >= 0`), loops forget what they assign, a callee's `ensures` bounds its result in callers, and struct literals are checked against `invariant`s. It runs as a final analyzer phase, only on programs that are otherwise error-free, and can never crash the compiler.
- Diagnostics: `W4030` a call provably violates `requires`; `W4031` an `ensures` that no return path can satisfy; `W4032` contradictory `requires`; `W4033` an `ensures` violated on one return path; `W4034` a struct literal violates an `invariant`.
- **Soundness rule:** every abstract value is a superset of the real values, so a contract is reported only when it is *definitely* violated and never because the prover merely failed to prove it. Undecided contracts stay run-time checks.
- Reported as **warnings by default** (a program may deliberately demonstrate the run-time failure `R1003`). `SemanticOptions(contract_proof_severity=Severity.ERROR)` promotes them to errors with `E` codes.
- CLI: `happy check FILE --prove` prints `contracts: N proved, M violated, K left to run-time checks`; `--deny-violations` makes provable violations compile errors.
- `AnalysisResult.contract_proofs` exposes the counts programmatically.
- `tools/fuzz_contracts.py` — soundness fuzzer: checks every prover claim by brute force against independent Python execution, tests the interval primitives (`eval_expr`, `eval_cond`, `narrow`) directly against concrete points, and checks flow analysis (assignments, branches, loops) through per-return intervals. It was validated by mutation: four deliberately broken prover variants (wrong multiplication bound, wrong negation, branch-join dropping a side, loops not forgetting assignments) are all detected, while the real prover shows no failures.
- `tests/test_contract_proofs.py` — 24 tests (including no false positives on every shipped example).

### Fixed (found while building the prover)
- Narrowing an `Int` against a fractional bound was unsound (`x < 2.5` was treated as `x <= 1.5`, wrongly excluding `x == 2`); integer bounds now snap with floor/ceil.

### Limits
- Intervals are non-relational: `result >= a` cannot be proved from `result = a + 1` (the correlation is lost), so such contracts stay run-time checks. Only `Int`/`Float` arithmetic (`+ - *`, `**` with exponent 0-2) is modelled; other operators evaluate to "unknown", which is always safe.

## v9.1 — fuzzing, empty app, memory guard

### Fixed
- **`app` with an empty body failed to run** (`app A {}` or a body containing only `if false { ... }`, which the optimizer removes) with `R8001 no 'main' entry point`. An `app` now always gets an entry point; a module with no `app` still reports R8001. Found by the scope fuzzer.
- **`happy fmt` printed `-(-5)` as `--5`**, which the lexer reads as one token, so the formatted file no longer parsed. Nested unary operators are now parenthesised. Found by the differential fuzzer.

### Added
- **Runtime memory guard.** A run can no longer exhaust the machine's memory: a watchdog samples the process RSS and stops the program with `R6002` once it has allocated more than `max_memory_mb` (default 1024 MiB) beyond its starting point. `RuntimeContext(max_memory_mb=None)` disables it. It is enforced from a thread rather than `setrlimit`, so an embedding host (REPL, language server) is not constrained. A single huge allocation can overshoot between two samples; the run is stopped right afterwards. Linux reads `/proc/self/statm`; macOS falls back to peak RSS.
- **`tools/fuzz_differential.py`** — random expression programs checked for optimizer-on == optimizer-off, formatter round-trip + idempotence, and agreement with a Python reference.
- **`tools/fuzz_scopes.py`** — random nested `let` / `for` / `if` programs checked against an independent reference interpreter with lexical scopes. Run either with `python tools/<name>.py [count] [seed]`.
- `tests/test_regression_v91.py` — 11 tests, including fixed-seed fuzzer runs.

## v9 — bug-fix round

### Fixed
- **Scoping:** `let`, `for` variables and `match` bindings inside a nested block no longer overwrite an outer variable of the same name (they are renamed in the generated Python).
- **Reserved names:** `let class = 1` / `let None = 1` and keyword-named parameters compile and run; a keyword-named *top-level* declaration is a clean error (E4023).
- **Float:** Int values widen to Float in `let`, parameters, defaults, returns, assignment and struct fields (`let x: Float = 2` prints `2.0`). The optimizer no longer inlines Float functions (which dropped the widening) and no longer folds float overflow into an invalid `inf` literal.
- **`match`:** a braced single-statement arm (`A -> { println("a") }`) was compiled as `return println(...)`, silently skipping everything after the `match`. Only unbraced `pattern -> expr` arms now yield a value (new `bare_expr` flag).
- **Structs:** field writes re-check invariants and roll back a failed write; reassigning a `secret` field keeps it wrapped.
- **Checks:** missing `return` (E4021); trait `impl` signature mismatch (E4014); generic parameters must agree across arguments; unknown `std.*` import (E3007); second `app` block (E4022); `1 == "1"` is a type error; builtin arity is checked in full (`len(1, 2)`); a local variable that shadows a builtin is not callable.
- **Parameter defaults:** `function f(a: Int, b: Int = 5)` can be called as `f(1)`; the default is now emitted in the generated code.
- **Lexer/parser:** `1e400` is rejected cleanly; `-2 ** 2` is `-4`.
- **Sandbox:** dunder, single-underscore, frame/coroutine (`cr_frame`, `f_builtins`, ...) and `str.format` member access is rejected (E4020) — the previous underscore-only idea would not have stopped `c.cr_frame.f_builtins["open"]`. A struct field that merely shares a blocked name (e.g. `format`) is still allowed.
- **Formatter (`happy fmt`):** it dropped required parentheses, so `(1 + 2) * 3` became `1 + 2 * 3` and `10 - (3 - 1)` became `10 - 3 - 1`, changing program meaning. Printing is now precedence- and associativity-aware.
- **REPL:** one syntax error used to poison every later line; defining something after the `app` re-ran the app; programs with compile errors (including `open(...)`) were executed. Bad input is now discarded, the app runs once, multi-line input is supported, and the REPL compiles in strict mode.
- **`happy debug`:** compiles in strict mode, so it refuses programs the checker rejects.
- **Semver:** prerelease identifiers compare per the spec (`alpha.2 < alpha.10`); build metadata (`1.0.0+build`) is accepted and ignored for precedence; leading zeros and empty identifiers are rejected; `*`, `^`, `~` and comparison ranges no longer match unrelated prereleases.
- **`install_package`:** now verifies every file against the manifest checksums *before writing anything*, rejects unlisted/missing files, and fixes a path-traversal check that used a string-prefix test (`../outX/..` passed for dest `out`). Bad zips / missing / malformed manifests are clean errors (`PackageInstallError`, a `ValueError`).

### Added
- `backend.compile_source(..., strict=True)` — security-strict analysis that refuses programs with errors.
- `tests/test_regression_v9_bugs.py` — 71 regression tests for the items above.

### Known / not changed
- `backend.compile_source` and `compile_project` default to the historical lenient behaviour (they generate code even when analysis reports errors) because existing tests depend on runtime fallbacks. Use `strict=True` for untrusted source.

## Hardening - 2026-10-04 (post-review, toolchain version stays 1.0.0)

Security hardening following an independent review. All fixes are covered by a
new adversarial test suite (`tests/test_security_adversarial.py`, 16 tests).

### Fixed
- **Sandbox/capability bypass (critical).** An "unlisted" call such as
  `open(...)` or `__import__("os")` used to be only a *warning* and then
  executed verbatim in Python. Under the pipeline/CLI's security-strict mode
  such a call is now a hard compile error (`E3001`), and `happy check`,
  `happy build`, `happy run` and `happy verify` all reject the program.
- **Capability bypass at runtime.** A sensitive operation (`write_file`,
  `http_get`, a process spawn, …) placed in an `app` body ran with no agent
  scope and was therefore unchecked. The runtime now denies host-touching
  actions outside any agent (`R2001`) unless the host opts in with
  `CapabilityPolicy(default_allow=True)`; nothing is written.
- **Static detection of the bypass.** New analyzer rule **`SEC011`** flags
  sensitive operations performed outside any agent, so `happy verify` now
  *rejects* such a program instead of approving it.
- **User `main` was overridden.** The backend always emitted an
  `async def main():` wrapper, which clobbered a user-defined `function main()`;
  the user's entry point never ran. The wrapper is now emitted only when there
  is an `app` body *and* no user `main`.
- **Master runner pytest dependency.** `tests/run_all_tests.py` now falls back
  to standard-library `unittest` discovery when `pytest` is not installed, so
  the master run stays 11/11 either way.

### Documentation
- Commercial and pitch documents no longer use "production-ready" / "Rust-like
  safety" language; Happy is described as a **working prototype**. The security
  guarantee is stated precisely: compile-time rejection of unknown calls +
  runtime capability denial + static analysis — **not** OS-level isolation.

## [1.0.0] - 2026-10-03

First stable release (working prototype). The entire pipeline is implemented and
verified end to end:

**Source → Lexer → Parser → AST → Semantic Analysis → Type Checking → IR →
Optimization → Python Backend → Runtime**, with the security model, AI-native
layer and developer tooling integrated as one coherent system.

### Language & Compiler
- Full front end: lexer, recursive-descent parser, AST, static type system,
  generics, modules/imports, functions, structs, enums, and **traits/impl**
  with conformance checking.
- **Pattern matching** (`match`) with exhaustiveness analysis.
- Error handling, async/concurrency, memory/resource semantics.
- **Effects, capabilities, permissions and contracts** enforced at compile
  time and at run time.
- IR with a real optimizer (constant folding, dead-code elimination,
  constant-condition pruning, pure inlining).
- Python 3 code generator with source-map preservation so runtime errors map
  back to `.hpy` source lines.

### Runtime & Standard Library
- Execution runtime (`RuntimeContext`), dynamic contract evaluation, the
  capability & permission checker, and secret-protection wrappers.
- Standard library: `std.core`, `std.io`, `std.collections`, `std.json`,
  `std.async`, `std.crypto` and extended modules.

### AI-Native Layer
- Provider abstraction with adapters for OpenAI, Claude, Gemini and local
  (OpenAI-compatible) LLMs, with environment-based credential handling.
- Structured output/plan generation, tool/function interaction, and the
  AI trust-ladder verification engine (RAW → PARSED → GROUNDED → VERIFIED →
  TESTED → APPROVED).

### Security Model
- Static security analyzer with rules SEC001–SEC010 (secret exposure,
  unverified payment, permission escalation, unsafe IO, SSRF, path traversal,
  insecure deserialization, weak crypto, command injection, hardcoded secrets).
- Runtime enforcement of capabilities, permissions, contracts and effects.

### Developer Tooling
- Full CLI: `new`, `check`, `build`, `run`, `test`, `fmt`, `lint`, `verify`,
  `ai`, `debug`, `doc`, `repl`, `publish`, `add`, `lsp`.
- Deterministic AST-based formatter, linter, Language Server Protocol server
  (diagnostics, completion, hover, definition, document symbols).
- Package manager: `happy.toml` manifest parsing, `happy.lock` generation,
  dependency-graph resolution, project initialization and publishing.

### Packaging
- `pyproject.toml` with a `happy` console-script entry point, zero runtime
  dependencies, and editable/standard install support.
- Master test runner validating the whole pipeline; 400+ tests passing.
