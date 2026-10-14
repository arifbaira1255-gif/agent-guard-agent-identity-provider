# New issues found by the extra attack pass

Beyond the 13 reported bugs, an additional adversarial pass
(`attacks/new_attacks.py`, 39 checks) was run across sandbox escape,
capability bypass, numeric/unicode edge cases, parser fuzzing and resource
exhaustion.  All 39 checks are now blocked.  Two **new** issues were found and
fixed.

## N1 — Unreachable / duplicate `match` arms accepted silently

**Severity:** medium (correctness / dead code).

**Symptom.** A `match` with a duplicate variant arm, a duplicate literal arm,
or any arm placed *after* a wildcard arm compiled with **no diagnostic at all**:

```happy
enum E { A B }
function f(e: E) -> Int {
  match e {
    _ -> { return 0 }   // matches everything
    A -> { return 1 }   // unreachable — silently accepted
  }
  return 0
}
```

The second arm can never run, yet the compiler said nothing.  This is the same
class of problem as the reported non-exhaustive-match bug (#10): the language
promises compile-time match checking, so unreachable arms should be reported.

**Fix.** `happy/compiler/semantic.py` now tracks seen variants, seen literal
keys and whether a catch-all arm has already appeared, and raises
**E4013 `unreachable match arm`** for:

* a variant arm whose variant is already covered,
* a literal arm whose literal is already covered,
* any arm after a wildcard/binding arm.

**Regression tests.** `tests/test_regression_v8_bugs.py::TestUnreachableMatchArms`
(4 tests: duplicate variant, arm-after-wildcard, duplicate literal, and a
positive case with distinct literals).

## N2 — `_literal_key` used the wrong AST node shape

**Severity:** low (found while implementing N1).

**Symptom.** The first version of the duplicate-literal check keyed off
`expr.kind`, but literal pattern values are `IntLiteral` / `StringLiteral` /
… nodes with a `.value` field and **no** `.kind`, so duplicate literal arms
were not detected.

**Fix.** `_literal_key` now keys off the node's class name
(`IntLiteral`, `FloatLiteral`, `StringLiteral`, `CharLiteral`, `BoolLiteral`).

**Regression test.** `TestUnreachableMatchArms::test_duplicate_literal_arm`.

## Checks that were already safe (no fix needed)

The extra pass confirmed the following are correctly blocked after the fixes:

* **Sandbox escape variants** — `getattr`, `__import__`, `__bases__`,
  `__globals__`, `().__subclasses__()`, `__reduce__` → all REJECTED.
* **Sandboxed test runner** — `import os`, dunder access, `eval`, `open`,
  `getattr`, `__builtins__`, `importlib`, `subprocess`, `socket`, `ctypes`
  → all refused by the static scan.
* **Capability bypass** — `std.fs.write`, `std.process.run`, `std.env.get_or`
  outside an agent → all denied.
* **Numeric edges** — division/modulo by zero, negative division, huge
  multiplication, NaN, int overflow → clean errors or correct values, no raw
  tracebacks.
* **Unicode edges** — combining marks, ZWJ emoji, RTL, CJK, NUL, lone
  surrogate → no raw tracebacks.
* **Parser fuzzing** — 300 random token strings → 0 crashes.
* **Resource exhaustion** — deep lists, 200 KB strings, 20 000 statements →
  clean diagnostics, no raw tracebacks.
* **Secret handling** — concatenation, `str()`, JSON encoding → all refused;
  `reveal()` still works.
