"""Reproduce all 13 reported bugs against happy-lang v8 (hardened).

Run:  python attacks/repro_all.py
Prints a PASS/FAIL line per attack.  "VULNERABLE" means the bug is present.

Attack #9 (infinite loop) is executed in a *subprocess* with an external
timeout so a still-unfixed runtime cannot hang this script.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

RESULTS = []


def record(bug, name, vulnerable, detail=""):
    RESULTS.append((bug, name, vulnerable, detail))
    tag = "VULNERABLE" if vulnerable else "blocked"
    print(f"[{tag}] #{bug} {name}: {detail}")


# ---------------------------------------------------------------------------
# #1 sandbox escape via __class__.__mro__[1].__subclasses__()
# ---------------------------------------------------------------------------
def attack_1():
    from happy.ai.verifier import VerificationPipeline
    src = (
        'app demo {\n'
        '  let x = "x"\n'
        '  let subs = x.__class__.__mro__[1].__subclasses__()\n'
        '}\n'
    )
    try:
        res = VerificationPipeline(run_tests=False).verify(src, filename="escape.hpy")
        record(1, "sandbox escape via __class__", res.approved,
               f"state={res.state}")
    except Exception as exc:  # noqa: BLE001
        record(1, "sandbox escape via __class__", False, f"raised {type(exc).__name__}")


# ---------------------------------------------------------------------------
# #2 happy fmt destroys data
# ---------------------------------------------------------------------------
def attack_2():
    from happy.tools.fmt import format_source
    path = os.path.join(ROOT, "examples", "language_tour.hpy")
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    res = format_source(src, filename=path)
    before = len(src.splitlines())
    after = len(res.formatted.splitlines())
    destroyed = ("unformattable" in res.formatted) or (after < before - 5)
    record(2, "fmt destroys trait/impl", destroyed,
           f"{before} -> {after} lines, unformattable={res.unformattable}")


# ---------------------------------------------------------------------------
# #3 verifier tests stage runs arbitrary host Python
# ---------------------------------------------------------------------------
def attack_3():
    from happy.ai.verifier import VerificationPipeline
    marker = os.path.join(tempfile.gettempdir(), "happy_pwned_marker.txt")
    if os.path.exists(marker):
        os.remove(marker)
    tests = 'import os\nopen(%r, "w").write("pwned")\n' % marker
    try:
        VerificationPipeline(run_tests=True).verify(
            'app demo {\n  let x = 1\n}\n', filename="t.hpy", tests=tests
        )
    except Exception:  # noqa: BLE001
        pass
    escaped = os.path.exists(marker)
    if escaped:
        os.remove(marker)
    record(3, "verifier tests run host python", escaped,
           f"marker written={escaped}")


# ---------------------------------------------------------------------------
# #4 env vars readable/writable without capability
# ---------------------------------------------------------------------------
def attack_4():
    from happy.pipeline import run_source
    os.environ["HAPPY_FAKE_API_KEY"] = "sk-supersecret-123"
    src = (
        'import std.env { get_or }\n'
        'app demo {\n'
        '  println(get_or("HAPPY_FAKE_API_KEY", "x"))\n'
        '}\n'
    )
    out = run_source(src, filename="env.hpy")
    leaked = "sk-supersecret-123" in (out.output or "")
    record(4, "env var read without capability", leaked,
           f"leaked={leaked} ok={out.ok}")


# ---------------------------------------------------------------------------
# #5 optimizer wrong division
# ---------------------------------------------------------------------------
def attack_5():
    from happy.pipeline import run_source
    src = (
        'app demo {\n'
        '  println(7 / 2)\n'
        '  let x: Float = 7 / 2\n'
        '  println(x)\n'
        '}\n'
    )
    out = run_source(src, filename="div.hpy")
    text = (out.output or "").strip()
    wrong = "3.5" not in text
    record(5, "optimizer 7/2 == 3", wrong, f"output={text!r}")


# ---------------------------------------------------------------------------
# #6 secret leak via _value and ==
# ---------------------------------------------------------------------------
def attack_6():
    from happy.pipeline import run_source
    src = (
        'type User {\n'
        '  secret pin: String\n'
        '}\n'
        'app demo {\n'
        '  let u = User { pin: "1234" }\n'
        '  println(u.pin._value)\n'
        '  if u.pin == "1234" { println("guessed") }\n'
        '}\n'
    )
    out = run_source(src, filename="secret.hpy")
    text = out.output or ""
    leaked = "1234" in text or "guessed" in text
    record(6, "secret leak via _value / ==", leaked, f"output={text!r}")


# ---------------------------------------------------------------------------
# #7 emoji crash + len
# ---------------------------------------------------------------------------
def attack_7():
    from happy.pipeline import run_source
    src = (
        'app demo {\n'
        '  println("😀")\n'
        '  println(len("😀"))\n'
        '}\n'
    )
    try:
        out = run_source(src, filename="emoji.hpy")
        text = out.output or ""
        bad = (not out.ok) or ("2" in text)
        record(7, "emoji crash / len", bad, f"ok={out.ok} output={text!r} err={out.error}")
    except Exception as exc:  # noqa: BLE001
        record(7, "emoji crash / len", True, f"raised {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# #8 deep nesting raw traceback
# ---------------------------------------------------------------------------
def attack_8():
    from happy.pipeline import run_source
    cases = {
        "200 parens": "app demo {\n  let x = " + "(" * 200 + "1" + ")" * 200 + "\n}\n",
        "500-term +": "app demo {\n  let x = " + " + ".join(["1"] * 500) + "\n}\n",
        "5000-digit": "app demo {\n  let x = " + "9" * 5000 + "\n}\n",
    }
    bad = False
    details = []
    for name, src in cases.items():
        try:
            out = run_source(src, filename="deep.hpy")
            err = out.error or ""
            if "Traceback (most recent call last)" in err or "RecursionError" in err:
                bad = True
                details.append(f"{name}: raw traceback")
        except RecursionError:
            bad = True
            details.append(f"{name}: RecursionError")
        except Exception as exc:  # noqa: BLE001
            details.append(f"{name}: {type(exc).__name__}")
    record(8, "deep nesting raw traceback", bad, "; ".join(details) or "clean")


# ---------------------------------------------------------------------------
# #9 runtime timeout  (run in a subprocess with an external timeout)
# ---------------------------------------------------------------------------
def attack_9():
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from happy.pipeline import run_source\n"
        "o = run_source('app demo {\\n  while true { }\\n}\\n', filename='loop.hpy')\n"
        "print('OK' if not o.ok else 'HUNG')\n" % ROOT
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=25,
        )
        out = (proc.stdout or "").strip()
        hung = "HUNG" in out
        record(9, "infinite loop no timeout", hung, f"result={out!r}")
    except subprocess.TimeoutExpired:
        record(9, "infinite loop no timeout", True, "external timeout hit (still hangs)")


# ---------------------------------------------------------------------------
# #10 non-exhaustive match only warns
# ---------------------------------------------------------------------------
def attack_10():
    from happy.compiler import analyze, parse
    src = (
        'enum Color {\n  Red\n  Green\n  Blue\n}\n'
        'function f(c: Color) -> Int {\n'
        '  match c {\n'
        '    Red -> { return 1 }\n'
        '  }\n'
        '  return 0\n'
        '}\n'
        'app demo { let x = 1 }\n'
    )
    program = parse(src, filename="m.hpy")
    res = analyze(program, filename="m.hpy")
    has_error = any(d.severity == "error" for d in res.diagnostics)
    record(10, "non-exhaustive match not compile error", not has_error,
           f"ok={res.ok} diags={[d.code for d in res.diagnostics]}")


# ---------------------------------------------------------------------------
# #11 LSP crashes on malformed JSON
# ---------------------------------------------------------------------------
def attack_11():
    from happy.tools.lsp import _read_message, ProtocolError
    bad = io.BytesIO(b"Content-Length: 5\r\n\r\n{bad}")
    try:
        _read_message(bad)
        record(11, "LSP malformed JSON", False, "handled")
    except ProtocolError:
        record(11, "LSP malformed JSON", False, "raised ProtocolError (server keeps serving)")
    except Exception as exc:  # noqa: BLE001
        record(11, "LSP malformed JSON", True, f"raised {type(exc).__name__}")


# ---------------------------------------------------------------------------
# #12 publish manifest machine path
# ---------------------------------------------------------------------------
def attack_12():
    from happy.tools.publish import create_package
    with tempfile.TemporaryDirectory() as tmp:
        proj = os.path.join(tmp, "proj")
        os.makedirs(os.path.join(proj, "src"))
        with open(os.path.join(proj, "src", "main.hpy"), "w") as fh:
            fh.write("app demo { let x = 1 }\n")
        with open(os.path.join(proj, "happy.toml"), "w") as fh:
            fh.write('[package]\nname="demo"\nversion="0.1.0"\nentry="src/main.hpy"\n')
        out = os.path.join(tmp, "pkg.hpyz")
        info = create_package(root=proj, output=out)
        entry = info.entry or ""
        bad = os.path.isabs(entry) or tmp in entry
        record(12, "publish manifest machine path", bad, f"entry={entry!r}")


# ---------------------------------------------------------------------------
# #13 small things
# ---------------------------------------------------------------------------
def attack_13():
    from happy.compiler import parse
    from happy.compiler.errors import HappyError
    from happy.pipeline import run_source

    # (a) requires ... { on one line
    one_line = (
        'function f(a: Int) -> Int requires a > 0 { return a }\n'
        'app demo { let x = 1 }\n'
    )
    try:
        parse(one_line, filename="r.hpy")
        a_ok = True
    except HappyError:
        a_ok = False

    # (b) reveal() without import
    src = (
        'type U {\n  secret pin: String\n}\n'
        'app demo {\n'
        '  let u = U { pin: "1" }\n'
        '  println(reveal(u.pin))\n'
        '}\n'
    )
    out = run_source(src, filename="rev.hpy")
    b_ok = out.ok and "unknown function" not in (out.error or "")

    # (c) hindi identifiers
    hindi = 'app demo {\n  let नाम = 5\n  println(नाम)\n}\n'
    try:
        out2 = run_source(hindi, filename="hi.hpy")
        c_ok = out2.ok
    except Exception:  # noqa: BLE001
        c_ok = False

    # (d) BOM file
    bom = '\ufeffapp demo {\n  let x = 1\n}\n'
    try:
        out3 = run_source(bom, filename="bom.hpy")
        d_ok = out3.ok
    except Exception:  # noqa: BLE001
        d_ok = False

    bad = not (a_ok and b_ok and c_ok and d_ok)
    record(13, "small: requires/reveal/hindi/BOM", bad,
           f"requires={a_ok} reveal={b_ok} hindi={c_ok} bom={d_ok}")


def main():
    for fn in [attack_1, attack_2, attack_3, attack_4, attack_5, attack_6,
               attack_7, attack_8, attack_9, attack_10, attack_11, attack_12,
               attack_13]:
        try:
            fn()
        except Exception:  # noqa: BLE001
            print(f"!! {fn.__name__} crashed:")
            traceback.print_exc()
    vuln = sum(1 for _, _, v, _ in RESULTS if v)
    print(f"\n=== {vuln}/{len(RESULTS)} attacks still VULNERABLE ===")
    return vuln


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
