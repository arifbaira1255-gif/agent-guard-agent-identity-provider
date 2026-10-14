# Happy Language (.hpy) — Compiler (Steps 1–6 of 6)

Bootstrap implementation of the **Happy** programming language toolchain,
written in Python. All six stages are complete:

- **Step 1 — Frontend Core:** lexer, AST, recursive-descent parser, diagnostics.
- **Step 2 — Semantic Analysis & Type Checking:** type system, lexical symbol
  tables, type inference/checking, enum exhaustiveness, import/export
  resolution, unused/unreachable detection, and contract / permission /
  capability / effect validation.
- **Step 3 — Core Semantic Differentiators:** typed Intermediate Representation,
  the Contract System, the Rule Engine + Capability System, and the Effect
  Tracker.
- **Step 4 — Python Backend & Runtime Execution Layer:** an IR → Python 3 code
  generator with source maps, the Happy Runtime (dynamic contract evaluation,
  runtime capability enforcement, secret protection, and async Task/Channel
  concurrency), and the standard library (`std.core`, `std.io`,
  `std.collections`, `std.json`, `std.async`, `std.crypto`).
- **Step 5 — AI-Native Layer:** a unified AI provider abstraction (OpenAI /
  Claude / Gemini / Local), structured plan generation from `ai` declarations,
  an agent capability sandbox, a trust-state verification pipeline
  (`RAW → PARSED → GROUNDED → VERIFIED → TESTED → APPROVED`) that forces AI
  output through the real compiler before it may run, and a static security
  analyzer (secret exposure, unverified payments, permission escalation,
  unsafe IO).
- **Step 6 — CLI Ecosystem & Developer Tooling:** the full `happy` CLI (`new`,
  `check`, `build`, `run`, `test`, `fmt`, `lint`, `verify`, `ai generate`), a
  package manager (`happy.toml` manifest + `happy.lock` lockfile + dependency
  graph + project scaffolding), a deterministic AST-based formatter, a static
  linter (naming / missing contracts / unused code / weak permissions), an LSP
  language server (diagnostics, completion, contract hints, jump-to-definition),
  and a master test runner.

## The `happy` CLI

```
python -m happy.cli new <app|lib|agent> [--name NAME] [--dir DIR]
python -m happy.cli check <file.hpy>        # parse + type-check
python -m happy.cli build <file.hpy> [-o out.py]
python -m happy.cli run <file.hpy>          # compile + execute
python -m happy.cli test                    # run the master test suite
python -m happy.cli fmt <file.hpy> [--check | --stdout]
python -m happy.cli lint <file.hpy> [--strict]
python -m happy.cli verify <file.hpy>       # AI trust-ladder verification
python -m happy.cli ai generate --prompt "…" --goal "…" [--provider mock]
```

## Layout

```
happy/compiler/
  __init__.py       # public API: tokenize(), parse(), analyze(), lower(), ...
  errors.py         # SourceLocation + diagnostic rendering (HappyError/LexerError/ParseError)
  lexer.py          # hand-written scanner -> Token stream                (Step 1)
  ast.py            # complete AST node hierarchy                         (Step 1)
  parser.py         # deterministic recursive-descent parser -> AST       (Step 1)
  types.py          # strong static type system                           (Step 2)
  symbol_table.py   # lexical scoping + let/var bindings                  (Step 2)
  semantic.py       # type checker, contracts, permissions, diagnostics    (Step 2)
  ir.py             # AST -> typed Happy IR (deterministic node IDs)      (Step 3)
  contracts.py      # requires/ensures/invariant engine + assertion lowering (Step 3)
  permissions.py    # rule verifier + capability enforcement mapper        (Step 3)
  effects.py        # effect inference, call-graph propagation, purity     (Step 3)
happy/backend/
  python_gen.py     # IR -> executable Python 3 code generator             (Step 4)
  sourcemap.py      # generated-line <-> .hpy source map                    (Step 4)
  cli.py            # `python -m happy.backend` compile/map/run/ir          (Step 4)
happy/runtime/
  core.py           # public runtime API                                    (Step 4)
  context.py        # RuntimeContext: ties services + installs module glue  (Step 4)
  contracts.py      # dynamic requires/ensures/invariant evaluation         (Step 4)
  capability.py     # runtime capability & permission enforcement           (Step 4)
  secrets.py        # secret protection (tainted Secret box + guard)        (Step 4)
  async_runtime.py  # Task / Channel / Scheduler concurrency primitives     (Step 4)
  values.py         # value model (structs, enums, Option/Result, display)  (Step 4)
  errors.py         # HappyRuntimeError hierarchy + Python translation      (Step 4)
happy/std/
  core.py io.py collections.py json.py async.py crypto.py                   (Step 4)
happy/ai/
  providers.py      # AIProvider interface + OpenAI/Claude/Gemini/Local + Mock (Step 5)
  agent.py          # structured Plan generator + AgentSandbox capability sandbox (Step 5)
  verifier.py       # trust-state verification pipeline RAW -> APPROVED        (Step 5)
happy/security/
  analyzer.py       # static security rule engine (SEC001-SEC004)             (Step 5)
tests/
  test_lexer_parser.py   # 37 unit tests (Step 1)
  test_semantic.py       # 60 unit tests (Step 2)
  test_ir_contracts.py   # 34 unit tests (Step 3)
  test_e2e_backend.py    # 44 end-to-end tests (Step 4)
  test_ai_verifier.py    # 48 AI-layer tests (Step 5)
examples/
  banking.hpy       # full demo script exercising the whole language surface
  run_demo.py       # parse a script and print an AST summary            (Step 1)
  analyze_demo.py   # semantically analyze a script and print diagnostics (Step 2)
  pipeline_demo.py  # run the full 7-stage pipeline over a script        (Step 3)
  ai_demo.py        # AI-native flow: plan -> sandbox -> verify           (Step 5)
  backend_demo.hpy  # full backend/runtime demo program                  (Step 4)
```

## Quick start

```bash
# Step 1 — lexer + parser
python -m pytest tests/test_lexer_parser.py -v
python examples/run_demo.py examples/banking.hpy

# Step 2 — semantic analysis
python -m pytest tests/test_semantic.py -v
python examples/analyze_demo.py examples/banking.hpy

# Step 3 — IR, contracts, permissions, effects
python -m pytest tests/test_ir_contracts.py -v
python examples/pipeline_demo.py examples/banking.hpy      # add --ir to dump nodes

# Step 4 — Python backend & runtime
python -m pytest tests/test_e2e_backend.py -v
python -m happy.backend compile examples/backend_demo.hpy   # print generated Python
python -m happy.backend map examples/backend_demo.hpy       # print the source map
python -m happy.backend run examples/backend_demo.hpy       # compile + execute
```

Full-pipeline programmatic API:

```python
from happy.compiler import analyze, parse, lower
from happy.compiler.contracts import ContractEngine
from happy.compiler.permissions import PermissionEngine
from happy.compiler.effects import EffectTracker

module = lower(analyze(parse(source)))
print(module.fingerprint())                                    # deterministic
print(ContractEngine(source=source).analyze(module).summary())
print(PermissionEngine(source=source).verify(module).summary())
print(EffectTracker(source=source).analyze(module).summary())
```

## Language surface covered

| Area | Constructs |
|------|-----------|
| Primitive types | `Int`, `Float`, `String`, `Bool`, `Byte`, `Char`, `Unit` |
| Generics | `Option<T>`, `Result<T, E>`, `List<T>`, `Map<K, V>`, `Set<T>`, `Future<T>`, user generics `type Box<T>` |
| Declarations | `module`, `import`, `type` (struct), `enum`, `function`, `rule`, `permission`, `capability`, `agent`, `ai`, `app` |
| Contracts | `requires`, `ensures`, `invariant` (Bool-typed predicates, optional message strings) |
| Effects | `effects [io, net, ...]` — unknown effects warned |
| Concurrency | `async function`, `await` (Future-only) |
| AI | `agent { goal ... }`, `ai { prompt ... }`, inline `ai { ... }` expressions |
| Security | `secret` fields, `permission { can / cannot }`, `capability { grants }` |
| Statements | `let`/`var`, assignment (`=`, `+=`, ...), `if`/`else`, `while`, `for`, `return`, `break`, `continue`, blocks |
| Expressions | literals, identifiers, binary/unary ops (full precedence), calls, member access, indexing, list literals, struct literals, `await`, `ai` |
| Lexical | line `//` and nestable block `/* */` comments, string/char literals with escapes, hex/bin/oct ints, floats with exponents |

## Semantic analysis (Step 2)

**Type system** (`types.py`) — primitives, generics, nominal struct/enum types,
plus `Any` (dynamic boundary), `Unknown` (error poison) and `Never` (bottom).
Provides structural equality, `assignable` (with numeric widening, covariance,
contravariance and `None`-to-`Option<T>`), `unify` (with occurs-check),
`apply_substitution` and `common_supertype`.

**Symbol tables** (`symbol_table.py`) — a tree of lexical scopes (module,
function, block, struct, enum, agent, ai, loop, import) with outward lookup,
shadowing detection, duplicate-definition rejection, unused-tracking, import
registries and **`let` vs `var`** enforcement.

**Analyzer** (`semantic.py`) — a two-phase pass (declare → analyze) so
declaration order never matters:

- type inference + strict checking for every expression/statement;
- **enum exhaustiveness** for consecutive `if v == Variant` chains (and a
  reusable `check_exhaustive()` engine + `Pattern` API);
- module **import/export resolution** against supplied `ModuleInterface`;
- static **unused-variable**, **unused-import** and **unreachable-code** detection;
- **contract** Bool-typing for `requires`/`ensures`/`invariant` (with a
  `result` pseudo-variable in `ensures`);
- **permission** conflict checks (`can` ∩ `cannot`), **capability** reference
  checks, and **effect** validation.

### Diagnostic codes (Steps 1–2)

| Code | Meaning |
|------|---------|
| `E3001` | unknown name |
| `E3002` | duplicate definition |
| `E3003` | unknown type |
| `E3004` | unknown field |
| `E3005` | module does not export symbol |
| `E3006` | assignment to a `let` (immutable) binding |
| `E4001` | invalid declaration |
| `E4002` | type mismatch |
| `E4003` | contract condition is not `Bool` |
| `E4004` | wrong number of arguments |
| `E4005` | invalid expression (`await` of non-Future, `break` outside loop) |
| `E4006` | missing struct field in literal |
| `E4007` | duplicate field initializer |
| `E4010` | permission conflict (`can` + `cannot`) |
| `E4011` | unknown permission/capability reference |
| `W3100` | unreachable code |
| `W3101` | unused variable |
| `W3108` | non-exhaustive enum match |
| `W3109` | unknown effect |
| `W3120` | secret field access |
| `N3200` | unused import |

## Step 3 — Core semantic differentiators

**Intermediate Representation** (`ir.py`) — lowers the analyzed AST into an
explicit, *typed* Happy IR. Every node carries a stable ID and a source
location; the graph is built by a deterministic pre-order walk so identical
input yields an identical `IRModule` (verified by `IRModule.fingerprint()`).
Imports, structs, enums, functions (with params/contracts/effects), rules,
permissions, capabilities, agents, AI blocks and apps are all first-class IR
nodes; expressions are typed (`IRLiteral`, `IRName`, `IRCall`, `IRStruct`, …).

**Contract System** (`contracts.py`) — checks and lowers `requires`, `ensures`
and `invariant`:

- predicates must be `Bool` (non-Bool predicates are hard errors);
- `result` is only valid where the function actually returns a value
  (using it on a `Unit` return is an error);
- `old(...)` / `pre` state references are recognised and recorded;
- trivially-true and duplicate clauses are flagged;
- invariants are attached to their owning `type`;
- each clause is lowered to an executable `IRAssert` — preconditions to *entry*
  assertions, postconditions to *exit* assertions.

**Rule Engine & Capability System** (`permissions.py`) — verifies security
posture:

- a catalogue of built-in rules (`must_never_be_exposed`,
  `authentication_required`, `rate_limited`, `no_pii_leak`, …) whose arity and
  Bool-typed predicate are checked; unknown rule names are recorded as custom;
- **permission overlap** (`can` ∩ `cannot`) and **capability/permission
  conflicts** (an agent holding a capability it is denied);
- an **enforcement map**: every sensitive operation (`read_file`, `http_get`,
  `ai { … }`, …) inside an agent method must be covered by one of the agent's
  capabilities, otherwise an uncovered-enforcement error is reported.

**Effect Tracker** (`effects.py`) — infers and enforces side-effects:

- canonical effect kinds: `IO`, `Network`, `DatabaseRead`, `DatabaseWrite`,
  `FileSystem`, `Secrets`, `Payments`, `AI`, `Log`, `Time`, `Random`, …;
- direct inference from body calls/builtins plus **inter-procedural
  propagation** across the call graph to a fixed point;
- **purity violations** (a body performing an effect it did not declare),
  over-declaration of unused effects, and pure-function classification.

### Diagnostic codes (Step 3)

| Code | Meaning |
|------|---------|
| `E5001` | contract predicate is not `Bool` |
| `E5002` | `ensures` references `result` on a `Unit` return |
| `E5003` | invariant references an unknown field |
| `E5005` | contract clause has no condition |
| `W5004` | contract references an unknown name |
| `W5011` | contract predicate is trivially true |
| `W5012` | duplicate contract clause |
| `N5001` | old/pre state referenced |
| `N5002` | contract declared without a body |
| `E6001` | permission both permits and denies an action |
| `E6002` | capability conflicts with a permission's `cannot` |
| `E6003` | sensitive operation not covered by any capability |
| `E6004` | capability grants nothing |
| `E6005` | permission grants and denies nothing |
| `E6006` / `E6007` | duplicate capability / permission |
| `E6008` | agent references an unknown permission/capability |
| `W6011` | non-built-in rule recorded as custom |
| `W6012` | rule has neither predicate nor body |
| `W6013` | built-in rule arity mismatch |
| `W6014` | rule predicate is not `Bool` |
| `W6015` | capability declared but unused |
| `W6016` | sensitive action outside any agent |
| `N6001` | enforcement point covered by a capability |
| `E7001` | undeclared effect performed by the body |
| `W7011` | declared effect never performed (over-declaration) |
| `W7012` | effects performed but not annotated |
| `N7001` | function is pure (no effects) |
| `N7002` | inferred-effect note |

## Diagnostics

Every error/warning carries an exact 1-based line/column and renders with the
offending source line, a caret, a code and a contextual suggestion:

```
broken.hpy:10:23: error: [E4002] type mismatch in assignment: expected Float, found String
  10 |     account.balance = "oops"
     |                       ^
  help: provide a value of type Float
```

## Design notes

- **Deterministic LL(1)-friendly grammar** — every decision is made from the
  current token plus at most one token of lookahead.
- **Newlines are soft statement terminators**; `;` is also accepted.
- **Struct literals** (`Account { id: 1 }`) are disambiguated from blocks by
  requiring a capitalised type name followed by `{ ident : ... }`.
- **Nestable block comments** are supported.
- **In-range integer-literal narrowing** allows `pin: 7` for a `Byte` field.
- **Errors are collected, not thrown**, so one run reports many problems.
- **Deterministic IR** — lowering never depends on dictionary ordering, so the
  IR fingerprint of a program is reproducible build-to-build.

## Step 4 — Python backend & runtime execution layer

**Python code generator** (`happy/backend/python_gen.py`) turns the typed IR
into readable, executable Python 3:

- structs become `HappyStruct` subclasses (declared defaults as class
  attributes, `secret` fields auto-wrapped in `Secret`); enums become
  `VariantCtor` bindings and enum values;
- functions/methods become Python functions (async when the IR says so);
  `if`/`elif`/`else`, `while`, `for`, `break`/`continue` map one-to-one;
- `requires` / `ensures` / `invariant` / `rule` clauses become calls against the
  runtime's `ContractChecker` (preconditions on entry, postconditions before
  every `return` with `result` bound);
- sensitive calls inside an agent are routed through `__happy_call__`, which
  checks the capability and then invokes the callee.

**Source maps** (`happy/backend/sourcemap.py`) anchor every emitted statement to
the `.hpy` line/column it came from. Because the module is compiled under the
synthetic name `<happy-generated>`, the runtime resolves a Python traceback to
the original Happy line:

```
demo.hpy:4:5: error: [R4005] ZeroDivisionError: division by zero
  4 |     return a / b
    |     ^
```

**Runtime** (`happy/runtime/`) provides the execution services:

- **Dynamic contracts** (`contracts.py`) — `enforce` / `warn` / `off` policies;
  failures raise `PreconditionViolation`, `PostconditionViolation`,
  `InvariantViolation` or `RuleViolation` (`R1001`–`R1005`).
- **Capability & permission checker** (`capability.py`) — built from the IR, so
  it can never disagree with the compiler; uncovered operations raise
  `CapabilityDenied` (`R2001`), explicit denials raise `PermissionDenied`
  (`R2002`).
- **Secret protection** (`secrets.py`) — a tainted `Secret` box: `str`, f-strings
  and concatenation refuse to leak (strict mode, `SecretLeakError` `R3001`) or
  redact (`<secret ***>`), and `reveal()` is the audited escape hatch.
- **Async** (`async_runtime.py`) — `Task` (`Future<T>`), `Channel`, `spawn`,
  `gather`, `sleep`, and a `Scheduler` over `asyncio`.
- **Errors** (`errors.py`) — the `HappyRuntimeError` hierarchy renders with the
  same source-line + caret + `help:` diagnostic format as the compiler.

**Standard library** (`happy/std/`) — `core` (builtins), `io` (capability-gated
file/network IO), `collections`, `json` (secret-aware), `async`, `crypto`.

### Programmatic use

```python
from happy.backend import compile_source
from happy.runtime import RuntimeContext

program = compile_source(source, filename="demo.hpy")
ctx = RuntimeContext(filename="demo.hpy", source=source,
                     module=program.module, sourcemap=program.sourcemap)
result = program.run(ctx)
print(result.output)          # program output
print(result.error.render())  # Happy-rendered runtime error, if any
```

### Diagnostic codes (Step 4)

| Code | Meaning |
|------|---------|
| `R1001` / `R1003` | contract violated / precondition failed |
| `R1002` / `R1004` | invariant broken / postcondition failed |
| `R1005` | rule violated |
| `R2001` / `R2002` | capability denied / permission denied |
| `R3001` | secret leaked into a string or log |
| `R4001`–`R4005` | type / name / index / key / division-by-zero |
| `R5001`–`R5007` | async runtime failures |
| `R6001` | explicit panic |
