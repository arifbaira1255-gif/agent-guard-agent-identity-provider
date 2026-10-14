# Getting Started with Happy

Happy (`.hpy`) is a statically-typed, contract-first language that compiles to
Python 3 and runs inside a security-hardened runtime. This guide takes a real
developer from **Install → Create Project → Write → Check → Build → Run →
Test → Format → Lint → Verify**.

Every command shown here is implemented and tested; nothing is aspirational.

---

## 1. Install

Happy is a pure-Python toolchain with **zero third-party runtime
dependencies**. Install it from a source checkout:

```bash
git clone <repo> happy-lang
cd happy-lang
pip install -e .
```

This puts a `happy` executable on your `PATH` (a `console_scripts` entry
point). You can also run it without installing, straight from the checkout:

```bash
python -m happy --version     # -> happy 1.0.0
happy --version               # same, once installed
```

> Requires Python 3.9+. For development (running the test suite) install the
> extra: `pip install -e ".[dev]"` (adds `pytest`).

---

## 2. Create a project

```bash
happy new app --name hello --dir ./hello
cd hello
```

`happy new` scaffolds a `happy.toml` manifest plus a `src/main.hpy` entry
point. Three templates are available: `app` (an executable), `lib` (a
library), and `agent` (an AI-agent project). Each produced project compiles
and runs out of the box.

---

## 3. Write Happy code

A minimal program. The entry point is an **`app` block**; output uses the
built-in **`println`**.

```happy
module hello.main

function add(a: Int, b: Int) -> Int
  requires a >= 0
  requires b >= 0
  ensures result >= a
{
  return a + b
}

app Main {
  println(str(add(2, 3)))
  println("hello, happy")
}
```

Key language features (all enforced by the compiler and runtime):

* **types** — `Int`, `Float`, `Bool`, `String`, structs (`type`), enums,
  generics (`function identity<T>(value: T) -> T`).
* **traits & impl** — interfaces with conformance checking.
* **pattern matching** — `match value { ... }` with exhaustiveness analysis.
* **contracts** — `requires` / `ensures` / `invariant`, checked at run time.
* **capabilities & permissions** — sensitive operations must be granted.
* **effects** — side effects are tracked and validated.

See `examples/language_tour.hpy` for a runnable tour of all of these.

---

## 4. Check (parse + type-check)

```bash
happy check src/main.hpy
# -> 0 error(s), 0 warning(s), 0 note(s)
```

Runs the lexer, parser and full semantic analysis (types, traits, contracts,
capabilities, permissions, effects) and prints precise, source-anchored
diagnostics.

---

## 5. Build (compile to Python 3)

```bash
happy build src/main.hpy            # writes src/main.py
happy build src/main.hpy -o out.py  # custom output path
```

Lowers to typed IR, runs the optimizer, and emits executable Python 3 with a
source map so runtime errors point back to `.hpy` lines.

---

## 6. Run

```bash
happy run src/main.hpy
# -> 5
# -> hello, happy
```

Compiles **and** executes the program inside the Happy runtime, where
contracts, capabilities, permissions and secret protection are enforced.

---

## 7. Test

```bash
happy test
```

Runs the project's test suite: the master runner `tests/run_all_tests.py`
when present (which drives pytest plus CLI / package-manager / LSP
round-trips), otherwise `pytest` over the `tests/` directory.

---

## 8. Format

```bash
happy fmt src/main.hpy            # format in place
happy fmt --check src/main.hpy    # exit non-zero if not formatted
happy fmt --stdout src/main.hpy   # print formatted source
happy fmt -r src/                 # format a whole tree
```

The formatter is deterministic and AST-based; formatting is idempotent.

---

## 9. Lint

```bash
happy lint src/main.hpy
happy lint --strict src/main.hpy   # treat warnings as errors
```

Checks naming conventions (`L001`), missing contracts (`L002`), unused code
(`L003`) and weak permission models (`L004`), each with a location and a fix
hint.

---

## 10. Verify (AI trust ladder)

```bash
happy verify src/main.hpy
happy verify --json src/main.hpy
```

Pushes the source through the AI verification pipeline — RAW → PARSED →
GROUNDED → VERIFIED → TESTED → APPROVED — running the real lexer, parser, type
checker, contracts, rules, capabilities and security analyzer at each rung.

---

## Other commands

| Command | What it does |
|---|---|
| `happy ai generate` | generate Happy code via a configured AI provider |
| `happy debug <file>` | trace or step a `.hpy` program |
| `happy doc <file>` | generate Markdown docs from a `.hpy` file |
| `happy repl` | start an interactive Happy session |
| `happy publish` | package a project into a `.hpyz` archive |
| `happy add <pkg>` | add a dependency to `happy.toml` |
| `happy lsp` | start the Language Server Protocol server |

Run `happy <command> --help` for the exact flags of any command.

---

## Using Happy as a Python library

The whole pipeline is available programmatically through one entry point:

```python
from happy import pipeline

result = pipeline.compile_source(source, filename="demo.hpy")
if result.ok:
    run = pipeline.run_source(source, filename="demo.hpy")
    print(run.output)

# One call across compile + lint + security analysis:
check = pipeline.check_source(source, filename="demo.hpy")
print(check.summary())
```

See `happy/pipeline.py` for the full API.
