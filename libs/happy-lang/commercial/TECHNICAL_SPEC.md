# Happy (.hpy) — Technical Specification & Architecture

**Version:** 1.0.0 · **Implementation language:** Python 3 (standard library only) · **Target:** Python 3.9+

This document describes **only what is actually implemented** in the repository. Anything marked
"not implemented" is called out explicitly.

---

## 1. System overview

Happy is a statically-typed, contract- and capability-oriented language. The canonical pipeline is:

```
source → lex → parse → AST → semantic analysis (types, traits, contracts,
         capabilities, permissions, effects) → IR lowering → optimization
       → Python code generation (+ source map) → runtime execution
```

The single integration entry point is `happy/pipeline.py`, exposing:

| Function | Purpose |
|---|---|
| `compile_source(source, filename)` / `compile_file(path)` | run the full front-to-backend pipeline, return generated Python + source map + diagnostics |
| `run_source(source, filename)` / `run_file(path)` | compile and execute under the runtime, returning captured output |
| `check_source(source, filename)` / `check_file(path)` | one call across compile + lint + security analysis |
| `format_source`, `lint_source`, `analyze_security_source` | tooling wrappers |

`compile_source` catches front-end exceptions and returns a uniform `CompileResult(ok=False, …)` with
diagnostics instead of raising.

---

## 2. Repository layout

| Path | Contents | Files | LOC (approx.) |
|---|---|---|---|
| `happy/compiler/` | lexer, parser, AST, types, symbol table, semantic analyzer, contracts, permissions, effects, modules, IR, optimizer | 14 | 11,533 |
| `happy/backend/` | Python code generation + source map | 5 | 1,289 |
| `happy/runtime/` | contracts, capability, secrets, async runtime, context, errors | 9 | 2,311 |
| `happy/std/` | standard library modules | 17 | 1,921 |
| `happy/ai/` | provider abstraction, agent/plan/sandbox, verifier | 6 | 2,377 |
| `happy/security/` | static security analyzer (rule engine) | 2 | 946 |
| `happy/cli/` | command-line interface | 3 | 658 |
| `happy/package/` | manifest, lockfile, dependency graph, project init | 2 | 830 |
| `happy/tools/` | formatter, linter, debugger, docgen, REPL, publisher, LSP | 8 | 2,711 |
| top level | `__init__.py`, `__main__.py`, `pipeline.py` | 3 | 357 |

---

## 3. Front end (`happy/compiler/`)

### 3.1 Lexer (`lexer.py`)
Hand-written scanner producing `Token(TokenKind, value, line, column)`. Tracks exact source
positions. Public API: `tokenize(source, filename)`.

### 3.2 Parser (`parser.py`)
Deterministic recursive-descent parser. Public API: `parse(source, filename) -> ast.Program`.
Emits precise `ParseError` with location and a "help" hint. Language constructs parsed include:
modules/imports, functions (including generics `<T>`), structs (`type`), enums with payloads,
traits, `impl` blocks, `match`, contracts (`requires`/`ensures`/`invariant`/`rule`), capabilities,
permissions, effects, `agent`, `app`, `async`/`await`, `secret` fields, control flow
(`if`/`else if`/`else`, `while`, `for`), and expressions.

### 3.3 AST (`ast.py`)
Dataclasses for every node (`Program`, `FunctionDecl`, `StructDecl`, `EnumDecl`, `TraitDecl`,
`ImplDecl`, `MatchStmt`, `MatchPattern`, `AgentDecl`, `CapabilityDecl`, `AppDecl`, statements,
expressions, type nodes).

### 3.4 Type system (`types.py`)
`Type`, `PrimitiveType`, `FunctionType`, `StructType`, `EnumType`, plus generics and trait
conformance. Built-in traits: `Display`, `Debug`, `Eq`, `Ord`, `Hash`, `Iterator`.

### 3.5 Symbol table (`symbol_table.py`)
Scopes (`Scope`, `ScopeKind`), symbols and bindings; lexical scoping.

### 3.6 Semantic analysis (`semantic.py`)
`SemanticAnalyzer` performs type checking, name resolution, trait-conformance validation, and
validation of contracts, capabilities, permissions and effects. Produces `AnalysisResult` with
`Diagnostic`s (severity, location, code). Public API: `analyze(source_or_program, filename)`.

### 3.7 Sub-engines
- `contracts.py` — contract model and static validation of `requires`/`ensures`/`invariant`/`rule`.
- `permissions.py` — capability and permission model.
- `effects.py` — effect declarations and validation.
- `modules.py` — `ModuleLoader` for multi-module projects (`load_project`).

### 3.8 IR & optimizer (`ir.py`, `optimizer.py`)
`IRModule`, `IRBuilder`, `lower(analysis_or_program)`. IR nodes include functions, structs, agents,
traits (`IRTrait`/`IRImpl`), and pattern matching (`IRMatch`/`IRPattern`). `optimizer.optimize(module,
level)` returns an `OptimizationReport`.

---

## 4. Backend (`happy/backend/`)

`python_gen.py` — `PythonGenerator` / `generate(module, source, filename) -> GeneratedProgram`
and the one-call `compile_source(source, filename)` (analyze → lower → optimize → generate).

Emitted Python is readable and faithful:
- structs → `HappyStruct` subclasses (declared defaults as class attributes; `secret` fields
  auto-wrapped),
- enums → `VariantCtor` bindings,
- functions → Python functions (async when the IR says so),
- control flow → `if`/`elif`/`else`, `while`, `for`, `break`/`continue`,
- sensitive calls inside an agent route through a capability gate (`__happy_call__`),
- the whole module compiles under the filename `<happy-generated>`.

`sourcemap.py` — `SourceMap` / `SourceMapEntry` map generated lines → original `.hpy`
line/column. `SourceMap.resolve(generated_line)` and `.render()` let the runtime turn errors back
into Happy source locations. (Measured: 64 anchors for the 102-line backend demo.)

`GeneratedProgram` exposes `.source` (the Python text), `.sourcemap`, `.compile()`, `.execute(ctx)`
and `.run(ctx)`.

---

## 5. Runtime (`happy/runtime/`)

`RuntimeContext(filename, source, module, sourcemap)` wires the services and installs builtins.

| Module | Responsibility | Error codes |
|---|---|---|
| `contracts.py` | dynamic evaluation of `requires`/`ensures`/`invariant`/`rule` with policies `enforce`/`warn`/`off` | `R1001`–`R1005` |
| `capability.py` | capability & permission enforcement, built from the IR so it cannot disagree with the compiler | `R2001` `R2002` |
| `secrets.py` | tainted `Secret` box; strict mode raises on leak, redact mode renders `<secret ***>`; `reveal()` is the audited escape hatch | `R3001` |
| `async_runtime.py` | `Task` (`Future<T>`), `Channel`, `spawn`, `gather`, `sleep`, `Scheduler` | — |
| `context.py` | wires services, installs builtins, resolves errors via the source map | `R8001` |

Contract violations surface with the failing `.hpy` line (e.g. a `requires` violation reports
`R1003`).

---

## 6. Standard library (`happy/std/`)

Core runtime modules: `std.core`, `std.io`, `std.collections`, `std.json`, `std.async`, `std.crypto`
(plus supporting modules). `std.io` file/network operations are capability-gated; `std.json` is
secret-aware (it will not serialise a secret without explicit reveal).

---

## 7. AI-native layer (`happy/ai/`)

### 7.1 Providers (`providers.py`)
`AIProvider` abstract base with one required method `complete()`, plus a neutral data model
(`Message`, `AIRequest`, `AIResponse`, `Usage`, `ToolCall`). Concrete adapters: **OpenAI**,
**Claude** (Anthropic Messages), **Gemini** (`generateContent`), **Local LLM** (Ollama / llama.cpp
/ vLLM, OpenAI-compatible). Keys come from the environment (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY` / `GOOGLE_API_KEY`, `HAPPY_LOCAL_LLM_URL`). HTTP is via the standard library. A
deterministic **`MockProvider`** is the default for offline/test use. Registry helpers:
`get_provider`, `resolve_provider`, `provider_from_env`.

### 7.2 Agent & sandbox (`agent.py`)
- `PlanGenerator` turns an `ai` declaration into a **validated** JSON `Plan` (unique step ids,
  resolvable dependencies, cycle detection, step-count cap). Malformed model output is rejected,
  never executed.
- `AgentSandbox` — deny-by-default limits on what an agent may read / modify / execute / access
  (glob path grants, command allow-list, capability grants, network opt-in), with an audit trail and
  `SandboxViolation` on escape.

### 7.3 Verifier (`verifier.py`)
A monotonic, fail-closed trust-state pipeline:
`RAW → PARSED → GROUNDED → VERIFIED → TESTED → APPROVED`. Each rung runs the *real* compiler — lexer
+ parser → semantic/type checker → contracts + rules + capabilities + effects → the candidate's own
tests (subprocess) → the security analyzer. A failure freezes the candidate at its last state with a
full diagnostic report.

---

## 8. Security model (`happy/security/analyzer.py`)

`SecurityAnalyzer(strict=…)` runs over the typed IR (with a source-level fallback scan) and emits
`SecurityFinding`s (stable code, severity, precise `.hpy` location, remediation hint). Rules:

| Code | Detects |
|---|---|
| `SEC001` | secret exposure |
| `SEC002` | unverified payment execution |
| `SEC003` | permission escalation |
| `SEC004` | unsafe IO (dynamic targets, unsanitised writes, `eval`/`exec`) |
| `SEC005` | SSRF |
| `SEC006` | path traversal |
| `SEC007` | insecure deserialization |
| `SEC008` | weak cryptography |
| `SEC009` | command injection |
| `SEC010` | hardcoded secrets |

Also: `aggregate_reports()` and project-level `audit_project(entry_path)` (walks every module of a
project). Enforcement is real: capabilities/permissions deny at runtime and contracts fire as shown
in tests.

---

## 9. Developer tooling

### 9.1 CLI (`happy/cli/main.py`)
`argparse`-based; each command is a thin wrapper over a library function. Subcommands:
`new`, `check`, `build`, `run`, `test`, `fmt`, `lint`, `verify`, `ai`, `debug`, `doc`, `repl`,
`publish`, `add`, `lsp`; plus `--version` (`happy 1.0.0`). Run as `happy <cmd>` or
`python -m happy <cmd>`.

### 9.2 Package manager (`happy/package/manager.py`)
`happy.toml` manifest parser/renderer, `happy.lock` lockfile (deterministic JSON with `sha256:`
checksums), semver resolution (caret/tilde/range), `DependencyGraph` with cycle detection and
topological build order, a local `Registry` / `PathRegistry`, and `init_project()` scaffolding
(`app` / `lib` / `agent` templates, each producing a project that compiles and runs).

### 9.3 Formatter (`happy/tools/fmt.py`)
Deterministic, **AST-based** and **idempotent** (verified): canonical 4-space style, contract/effect
clauses, `} else if {` chains, no trailing whitespace. `format_source` returns a `FormatResult`
(`.original`, `.formatted`, `.changed`, `.diff_summary()`).

### 9.4 Linter (`happy/tools/lint.py`)
Rules: `L001` naming conventions, `L002` missing contracts, `L003` unused imports/variables/
functions, `L004` weak permission models. Emits findings with locations and fix hints.

### 9.5 LSP server (`happy/tools/lsp.py`)
JSON-RPC 2.0 with `Content-Length` framing over stdio. Capabilities: `initialize`,
`publishDiagnostics` (compiler + linter), `completion` (keywords + builtins + declared symbols),
`hover` (signature + contract hints), `definition` (jump-to-definition), `documentSymbol`. The
protocol layer is a pure `handle()` method, unit-testable without a socket.

### 9.6 Additional tools
`debugger.py` (trace/step), `docgen.py` (Markdown docs from a `.hpy` file), `repl.py` (interactive
session), `publish.py` (package a project into a `.hpyz` archive).

---

## 10. Distribution & packaging

- `pyproject.toml` (setuptools, PEP 621), `console_scripts` entry point `happy` →
  `happy.cli.main:main`, `dependencies = []`, optional `dev` extra (`pytest>=7`).
- `happy/__main__.py` enables `python -m happy`.
- `LICENSE` (MIT placeholder), `.gitignore`, `CHANGELOG.md`, `happy/py.typed`.
- CI workflow (`.github/workflows/`) runs pytest + the master runner + a CLI smoke test across
  Python 3.9–3.12.

---

## 11. Explicitly not implemented

- **OS-level isolation (sandbox).** Enforcement is *behavioural*: unknown/unlisted calls are rejected
  at compile time (``E3001``) and sensitive operations without a capability are denied at runtime
  (``R2001``/``R2002``). There is **no separate process, container, seccomp or WASM jail** — a
  hostile program restricted to the allowed builtins still runs in the host Python process. The
  guarantee is allowlist + capability enforcement, not kernel isolation.
- **Native machine-code backend.** The execution substrate is Python 3; Happy emits Python, not
  assembly/native binaries.
- **Hosted package registry.** Publishing/installing works against `.hpyz` archives and a local
  path registry; there is no remote registry service.
- **Live LLM I/O without credentials.** The AI layer is fully functional with a mock provider
  offline; real calls need a vendor key or local LLM URL.
- **Distributed/networked runtime.** Async concurrency is in-process (tasks/channels/scheduler);
  there is no cluster runtime.

---

*Weasel-word policy: this specification deliberately contains no "fast", "scalable" or "enterprise"
claims that are not backed by a measurable value in `BENCHMARKS.md`.*
