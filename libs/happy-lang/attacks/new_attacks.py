"""Additional adversarial attacks and edge cases beyond the 13 reported bugs.

Run:  python attacks/new_attacks.py
Each check prints [VULNERABLE] or [blocked].  Anything VULNERABLE is a new
issue to fix (and to cover with a regression test).
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FINDINGS = []


def record(name, vulnerable, detail=""):
    FINDINGS.append((name, vulnerable, detail))
    tag = "VULNERABLE" if vulnerable else "blocked"
    print(f"[{tag}] {name}: {detail}")


# --- sandbox escape variants ------------------------------------------------
def escape_variants():
    from happy.ai.verifier import VerificationPipeline
    variants = {
        "getattr": 'app d {\n  let x = getattr("x", "__class__")\n}\n',
        "dunder-import": 'app d {\n  let x = __import__("os")\n}\n',
        "bases": 'app d {\n  let x = "x".__class__.__bases__\n}\n',
        "globals": 'app d {\n  let x = f.__globals__\n}\n',
        "subclasses": 'app d {\n  let x = ().__class__.__subclasses__()\n}\n',
        "reduce": 'app d {\n  let x = "x".__reduce__()\n}\n',
    }
    for name, src in variants.items():
        try:
            res = VerificationPipeline(run_tests=False).verify(src, filename="e.hpy")
            record(f"escape/{name}", res.approved, f"state={res.state}")
        except Exception as exc:  # noqa: BLE001
            record(f"escape/{name}", False, f"raised {type(exc).__name__}")


# --- sandboxed test runner escape variants ----------------------------------
def sandbox_runner_variants():
    from happy.ai.sandbox import run_sandboxed_python
    variants = {
        "import os": "import os\nprint(os.getcwd())\n",
        "dunder": "print(().__class__.__bases__)\n",
        "eval": "eval('1+1')\n",
        "open": "open('/etc/passwd').read()\n",
        "getattr": "getattr(object, '__subclasses__')()\n",
        "builtins": "print(__builtins__)\n",
        "importlib": "import importlib\nimportlib.import_module('os')\n",
        "subprocess": "import subprocess\nsubprocess.run(['id'])\n",
        "socket": "import socket\nsocket.socket()\n",
        "ctypes": "import ctypes\nctypes.CDLL(None)\n",
    }
    for name, code in variants.items():
        ok, out = run_sandboxed_python(code, timeout=10)
        record(f"sandbox-runner/{name}", ok, f"ok={ok} out={out[:60]!r}")


# --- capability bypass ------------------------------------------------------
def capability_bypass():
    from happy.pipeline import run_source
    cases = {
        "fs-write": 'import std.fs { write }\napp A { write("/tmp/happy_pwn.txt", "x") }\n',
        "process": 'import std.process { run }\napp A { run("id") }\n',
        "env": 'import std.env { get_or }\napp A { println(get_or("PATH", "x")) }\n',
    }
    for name, src in cases.items():
        out = run_source(src, filename="c.hpy")
        record(f"capability/{name}", out.ok, f"ok={out.ok} out={out.output!r}")


# --- numeric edge cases -----------------------------------------------------
def numeric_edges():
    from happy.pipeline import run_source
    cases = {
        "div-zero": 'app d {\n  println(1 / 0)\n}\n',
        "mod-zero": 'app d {\n  println(1 % 0)\n}\n',
        "neg-div": 'app d {\n  println(-7 / 2)\n}\n',
        "big-mul": 'app d {\n  let x = 99999999999999999999 * 99999999999999999999\n  println(x)\n}\n',
        "float-nan": 'app d {\n  let x: Float = 0.0 / 0.0\n  println(x)\n}\n',
        "int-overflow": 'app d {\n  let x = 9223372036854775807 + 1\n  println(x)\n}\n',
    }
    for name, src in cases.items():
        try:
            out = run_source(src, filename="n.hpy")
            err = out.error or ""
            raw = "Traceback" in err
            record(f"numeric/{name}", raw, f"ok={out.ok} raw_tb={raw} out={out.output!r}")
        except Exception as exc:  # noqa: BLE001
            record(f"numeric/{name}", True, f"raised {type(exc).__name__}")


# --- unicode edge cases -----------------------------------------------------
def unicode_edges():
    from happy.pipeline import run_source
    cases = {
        "combining": 'app d {\n  println(len("e\u0301"))\n}\n',
        "zwj-emoji": 'app d {\n  println(len("👨‍👩‍👧"))\n}\n',
        "rtl": 'app d {\n  println("مرحبا")\n}\n',
        "cjk": 'app d {\n  println("日本語")\n}\n',
        "nul": 'app d {\n  println("a\\u0000b")\n}\n',
        "surrogate": 'app d {\n  println("\\ud800")\n}\n',
    }
    for name, src in cases.items():
        try:
            out = run_source(src, filename="u.hpy")
            err = out.error or ""
            raw = "Traceback" in err
            record(f"unicode/{name}", raw, f"ok={out.ok} raw_tb={raw} out={out.output!r}")
        except Exception as exc:  # noqa: BLE001
            record(f"unicode/{name}", True, f"raised {type(exc).__name__}")


# --- parser / lexer fuzzing -------------------------------------------------
def parser_fuzz():
    from happy.pipeline import compile_source
    import random
    random.seed(1234)
    alphabet = list("{}()[]<>+-*/%=!&|.,:;\"'\\ \n\tabcxyz0123456789_#")
    crashes = 0
    for i in range(300):
        n = random.randint(1, 60)
        src = "".join(random.choice(alphabet) for _ in range(n))
        try:
            compile_source(src, filename="fuzz.hpy")
        except RecursionError:
            crashes += 1
        except Exception as exc:  # noqa: BLE001
            # A clean HappyError is fine; anything else is a crash.
            if type(exc).__name__ not in ("HappyError", "LexerError", "ParserError"):
                crashes += 1
    record("fuzz/random-tokens", crashes > 0, f"{crashes}/300 crashed")


# --- resource exhaustion ----------------------------------------------------
def resource_exhaustion():
    from happy.pipeline import run_source
    cases = {
        "deep-list": 'app d {\n  let x = ' + "[" * 90 + "]" * 90 + '\n}\n',
        "huge-string": 'app d {\n  let x = "' + "a" * 200000 + '"\n}\n',
        "many-stmts": 'app d {\n' + "  let x = 1\n" * 20000 + '}\n',
    }
    for name, src in cases.items():
        try:
            out = run_source(src, filename="r.hpy")
            err = out.error or ""
            raw = "Traceback" in err
            record(f"resource/{name}", raw, f"ok={out.ok} raw_tb={raw}")
        except RecursionError:
            record(f"resource/{name}", True, "RecursionError")
        except Exception as exc:  # noqa: BLE001
            record(f"resource/{name}", True, f"raised {type(exc).__name__}")


# --- secret handling edge cases --------------------------------------------
def secret_edges():
    from happy.pipeline import run_source
    cases = {
        "concat": 'type U {\n  secret pin: String\n}\napp d {\n  let u = U { pin: "1234" }\n  println("pin=" + u.pin)\n}\n',
        "fstring": 'type U {\n  secret pin: String\n}\napp d {\n  let u = U { pin: "1234" }\n  println(str(u.pin))\n}\n',
        "json": 'import std.json { encode }\ntype U {\n  secret pin: String\n}\napp d {\n  let u = U { pin: "1234" }\n  println(encode(u))\n}\n',
        "reveal-ok": 'type U {\n  secret pin: String\n}\napp d {\n  let u = U { pin: "1234" }\n  println(reveal(u.pin))\n}\n',
    }
    for name, src in cases.items():
        out = run_source(src, filename="s.hpy")
        text = out.output or ""
        if name == "reveal-ok":
            record(f"secret/{name}", not (out.ok and "1234" in text),
                   f"ok={out.ok} out={text!r}")
        else:
            leaked = "1234" in text
            record(f"secret/{name}", leaked, f"ok={out.ok} leaked={leaked} out={text!r}")


def main():
    for fn in [escape_variants, sandbox_runner_variants, capability_bypass,
               numeric_edges, unicode_edges, parser_fuzz, resource_exhaustion,
               secret_edges]:
        try:
            fn()
        except Exception:  # noqa: BLE001
            print(f"!! {fn.__name__} crashed:")
            traceback.print_exc()
    vuln = sum(1 for _, v, _ in FINDINGS if v)
    print(f"\n=== {vuln}/{len(FINDINGS)} new checks VULNERABLE ===")
    return vuln


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
