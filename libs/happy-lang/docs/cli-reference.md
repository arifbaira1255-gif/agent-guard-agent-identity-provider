# Happy CLI Reference

The `happy` command is the single entry point to the toolchain. Install it
with `pip install -e .` (or run `python -m happy` from a checkout).

```
happy [--version] <command> [options]
```

`happy --version` prints `happy 1.0.0`.

---

## `happy new <template>`
Scaffold a new project.

```
happy new {app,lib,agent} --name NAME [--dir DIR] [--description TEXT]
```
Creates `happy.toml` and a `src/` entry point that compiles and runs.

## `happy check <file.hpy>`
Parse and type-check a file (lexer → parser → semantic analysis: types,
traits, contracts, capabilities, permissions, effects). Prints diagnostics;
exits non-zero on error.

## `happy build <file.hpy>`
Compile to Python 3.

```
happy build file.hpy [-o OUTPUT.py]
```
Runs IR lowering + optimization + code generation with a source map.

## `happy run <file.hpy>`
Compile and execute under the Happy runtime (contracts, capabilities,
permissions and secret protection enforced). Program output goes to stdout.

## `happy test`
Run the project test suite: `tests/run_all_tests.py` when present, else
`pytest tests/`.

## `happy fmt <file.hpy>`
Deterministic, AST-based formatting.

```
happy fmt file.hpy            # in place
happy fmt --check file.hpy    # verify only
happy fmt --stdout file.hpy   # print result
happy fmt -r <dir>            # recursive
```

## `happy lint <file.hpy>`
Lint for naming (`L001`), missing contracts (`L002`), unused code (`L003`)
and weak permission models (`L004`).

```
happy lint file.hpy [--strict]
```

## `happy verify <file.hpy>`
Run the AI trust-ladder pipeline (RAW → PARSED → GROUNDED → VERIFIED → TESTED
→ APPROVED).

```
happy verify file.hpy [--json]
```

## `happy ai generate`
Generate Happy code through a configured AI provider.

```
happy ai generate --prompt "<prompt>" [--goal G] [--provider NAME] [--live] [--file OUT.hpy] [--sandbox]
```
**Offline by default.** With no flags the command uses the deterministic
offline mock provider and never makes a network call. Connecting to a *live*
model is strictly opt-in — pass `--provider openai|claude|gemini|local` (or
`--live` to auto-detect from environment API keys) — and requires the matching
credential (see "AI providers" below).

## `happy debug <file.hpy>`
Trace or step a `.hpy` program with source-mapped locations.

## `happy doc <file.hpy>`
Generate Markdown documentation for a `.hpy` file.

## `happy repl`
Start an interactive Happy session (`:help` for commands, `:quit` to exit).

## `happy publish [directory]`
Package a project into a distributable `.hpyz` archive.

```
happy publish [dir] [-o OUTPUT] [--name NAME] [--version V] [--install CMD] [--dest DIR]
```

## `happy add <package>`
Add a dependency to `happy.toml`.

```
happy add <package> [--version V] [--dir DIR] [--dev]
```

## `happy lsp`
Start the Language Server Protocol server (diagnostics, completion, hover,
definition, document symbols).

```
happy lsp [--stdio]
```

---

## AI providers

The AI layer ships adapters for **OpenAI**, **Claude** (Anthropic), **Gemini**
and **local** OpenAI-compatible servers (Ollama / llama.cpp / vLLM).
Credentials are read from the environment and connecting to a live model is
always opt-in:

| Provider | Environment variable |
|---|---|
| OpenAI | `OPENAI_API_KEY` |
| Claude | `ANTHROPIC_API_KEY` |
| Gemini | `GEMINI_API_KEY` or `GOOGLE_API_KEY` |
| Local | `HAPPY_LOCAL_LLM_URL` |

Without a key (or with the default offline policy), AI commands use a
deterministic offline provider so nothing makes a network call implicitly.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| non-zero | a compile / lint / verify / runtime error occurred (details on stderr) |
