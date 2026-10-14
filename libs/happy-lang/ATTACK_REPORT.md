# happy-lang v8 (hardened) — Attack Report (before / after)

This report records every attack that was run against the project, the state
**before** the fixes (baseline) and **after** the fixes.  All attacks are
reproducible:

```bash
python attacks/repro_all.py     # the 13 reported bugs
python attacks/new_attacks.py   # 39 additional adversarial checks
```

## Summary

| # | Attack | Before | After |
|---|--------|--------|-------|
| 1 | Sandbox escape via `"x".__class__.__mro__[1].__subclasses__()` | **VULNERABLE** (verify APPROVED) | **CLOSED** (REJECTED at `sandbox` gate) |
| 2 | `happy fmt` destroys `language_tour.hpy` (79 → 52 lines, `// <unformattable TraitDecl>`) | **VULNERABLE** | **CLOSED** (79 → 77, compiles, idempotent) |
| 3 | Verifier `tests` stage runs arbitrary host Python | **VULNERABLE** (marker file written) | **CLOSED** (sandboxed subprocess) |
| 4 | Env vars read/written without a capability | **VULNERABLE** (API key leaked) | **CLOSED** (capability-gated, fail-closed) |
| 5 | Optimizer folds `7 / 2` to `3` | **VULNERABLE** | **CLOSED** (`3.5`) |
| 6 | Secret leak via `u.pin._value` and `==` oracle | **VULNERABLE** | **CLOSED** (both refused) |
| 7 | Emoji crash / `len("😀") == 2` | **VULNERABLE** | **CLOSED** (prints, `len == 1`) |
| 8 | Raw traceback on deep nesting (200 parens / 500-term `+` / 5000-digit) | **VULNERABLE** | **CLOSED** (clean diagnostics) |
| 9 | `while true { }` never terminates | **VULNERABLE** (hangs) | **CLOSED** (wall-clock timeout) |
| 10 | Non-exhaustive `match` only warns (W3108) | **VULNERABLE** | **CLOSED** (compile error E4012) |
| 11 | LSP server dies on malformed JSON | **VULNERABLE** | **CLOSED** (ProtocolError, keeps serving) |
| 12 | `happy publish` writes machine path into manifest | **VULNERABLE** | **CLOSED** (`entry = "src/main.hpy"`) |
| 13 | `requires ... {` one-line / `reveal()` import / Hindi idents / BOM | **VULNERABLE** | **CLOSED** (all four) |

**Result: 13/13 reported attacks closed. 0/13 still open.**

## Additional attacks (new pass)

39 extra checks across sandbox escape, capability bypass, numeric/unicode edge
cases, parser fuzzing and resource exhaustion.  **All 39 blocked** after the
fixes.  Two *new* issues were found and fixed (see `NEW_ISSUES.md`):

* **N1 — unreachable / duplicate `match` arms accepted silently** (now E4013).
* **N2 — `_literal_key` used the wrong AST node shape** (found while fixing N1;
  literal duplicate detection now works).

## Evidence

```
$ python attacks/repro_all.py
[blocked] #1 sandbox escape via __class__: state=REJECTED
[blocked] #2 fmt destroys trait/impl: 79 -> 77 lines, unformattable=False
[blocked] #3 verifier tests run host python: marker written=False
[blocked] #4 env var read without capability: leaked=False ok=False
[blocked] #5 optimizer 7/2 == 3: output='3.5\n3.5'
[blocked] #6 secret leak via _value / ==: output=''
[blocked] #7 emoji crash / len: ok=True output='😀\n1\n'
[blocked] #8 deep nesting raw traceback: clean
[blocked] #9 infinite loop no timeout: result='OK'
[blocked] #10 non-exhaustive match not compile error: ok=False diags=['E4012', 'W3101']
[blocked] #11 LSP malformed JSON: raised ProtocolError (server keeps serving)
[blocked] #12 publish manifest machine path: entry='src/main.hpy'
[blocked] #13 small: requires/reveal/hindi/BOM: requires=True reveal=True hindi=True bom=True

=== 0/13 attacks still VULNERABLE ===

$ python attacks/new_attacks.py
... (39 checks) ...
=== 0/39 new checks VULNERABLE ===

$ python -m pytest tests/
453 passed, 187 subtests passed in 12.69s
```

## Files changed

| File | Fix |
|------|-----|
| `happy/ai/sandbox.py` (new) | Static escape scan + restricted subprocess runner |
| `happy/ai/verifier.py` | Sandbox gate for candidate source; tests stage sandboxed |
| `happy/compiler/permissions.py` | `env` added to agent-required actions |
| `happy/std/env.py` | Fail-closed capability check |
| `happy/compiler/optimizer.py` | `/` folds to Float (true division) |
| `happy/runtime/secrets.py` | `Secret` refuses `_value`, `==`, formatting |
| `happy/backend/python_gen.py` | `json.dumps(..., ensure_ascii=False)` |
| `happy/compiler/lexer.py` | BOM strip, Unicode identifiers, big-int guard |
| `happy/compiler/parser.py` | Nesting-depth guard, single-line `requires` |
| `happy/compiler/semantic.py` | E4012 non-exhaustive, E4013 unreachable arms, `reveal`/`secret` builtins, expr-depth guard |
| `happy/runtime/context.py` | Wall-clock run timeout |
| `happy/cli/main.py` | UTF-8 stdout/stderr; fmt refuses lossy overwrite |
| `happy/tools/fmt.py` | trait/impl/match formatting; unformattable → keep original |
| `happy/tools/lsp.py` | `ProtocolError`; server survives bad messages |
| `happy/tools/publish.py` | Project-relative manifest `entry` |
| `happy/pipeline.py` | RecursionError → clean diagnostic |
| `tests/test_regression_v8_bugs.py` (new) | 33 regression tests |
| `attacks/repro_all.py`, `attacks/new_attacks.py` (new) | Reproducible attack harnesses |
