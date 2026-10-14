"""Tests for the static contract prover (happy.compiler.contract_proofs)."""
from __future__ import annotations

import glob
import importlib.util
import os
import subprocess
import sys
import unittest

from happy.compiler import SemanticOptions, analyze, parse
from happy.compiler.contract_proofs import verify_program
from happy.compiler.semantic import Severity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

F_NONNEG = 'function f(a: Int) -> Int\n  requires a >= 0, "non-neg"\n{ return a }\n'


def prove(src):
    msgs = []
    rep = verify_program(
        parse(src, filename="t.hpy"), lambda sev, code, msg, loc, hint: msgs.append((sev, code, msg))
    )
    return rep, msgs


def codes(src, **opts):
    res = analyze(parse(src, filename="t.hpy"), filename="t.hpy", options=SemanticOptions(**opts))
    return res, [d.code for d in res.diagnostics]


class CallSiteTests(unittest.TestCase):
    def test_violating_call_is_reported(self):
        rep, msgs = prove(F_NONNEG + 'app A { println(str(f(-1))) }')
        self.assertEqual((rep.proved, rep.violated, rep.unknown), (0, 1, 0))
        self.assertEqual(msgs[0][1], "E4030")
        self.assertIn("non-neg", msgs[0][2])

    def test_satisfying_call_is_proved(self):
        rep, msgs = prove(F_NONNEG + 'app A { println(str(f(5))) }')
        self.assertEqual((rep.proved, rep.violated, msgs), (1, 0, []))

    def test_unknown_argument_is_left_to_runtime(self):
        src = F_NONNEG + 'function g(x: Int) -> Int { return f(x) }\napp A { println("x") }'
        rep, msgs = prove(src)
        self.assertEqual((rep.proved, rep.violated, rep.unknown), (0, 0, 1))
        self.assertEqual(msgs, [])

    def test_branch_condition_proves_the_call(self):
        src = F_NONNEG + 'function g(x: Int) -> Int {\n if x >= 0 { return f(x) }\n return 0\n}\napp A { println("x") }'
        rep, msgs = prove(src)
        self.assertEqual((rep.proved, rep.violated), (1, 0))

    def test_local_shadowing_the_function_is_not_checked(self):
        src = F_NONNEG + 'app A {\n let f = 3\n println(str(f))\n}'
        rep, msgs = prove(src)
        self.assertEqual(msgs, [])

    def test_default_argument_is_used(self):
        src = 'function f(a: Int, b: Int = 0 - 1) -> Int\n  requires b >= 0\n{ return a }\napp A { println(str(f(1))) }'
        rep, msgs = prove(src)
        self.assertEqual(msgs[0][1], "E4030")


class EnsuresTests(unittest.TestCase):
    def test_ensures_proved_through_arithmetic(self):
        rep, msgs = prove('function f(a: Int) -> Int\n  requires a >= 0\n  ensures result >= 0\n{ return a + 1 }\napp A { println("x") }')
        self.assertEqual((rep.proved, rep.violated), (1, 0))

    def test_ensures_proved_through_branch_narrowing(self):
        src = 'function f(a: Int) -> Int\n  ensures result >= 0\n{\n if a < 0 { return 0 - a } else { return a }\n}\napp A { println("x") }'
        rep, msgs = prove(src)
        self.assertEqual((rep.proved, rep.violated, msgs), (1, 0, []))

    def test_ensures_violated_on_every_path(self):
        rep, msgs = prove('function f(a: Int) -> Int\n  requires a >= 0\n  ensures result < 0\n{ return a + 1 }\napp A { println("x") }')
        self.assertEqual(msgs[0][1], "E4031")

    def test_ensures_violated_on_one_path_is_a_warning(self):
        src = 'function f(a: Int) -> Int\n  ensures result >= 0\n{\n if a > 0 { return a } else { return 0 - 5 }\n}\napp A { println("x") }'
        rep, msgs = prove(src)
        self.assertEqual([m[1] for m in msgs], ["W4033"])
        self.assertEqual(msgs[0][0], "warning")

    def test_loop_assigned_variables_are_forgotten(self):
        src = (
            'function f(n: Int) -> Int\n  ensures result == 0\n{\n var t = 0\n var k = 0\n'
            ' while k < 3 {\n  k = k + 1\n  t = t + 1\n }\n return t\n}\napp A { println("x") }'
        )
        rep, msgs = prove(src)
        self.assertEqual(rep.proved, 0)  # must NOT claim result == 0
        self.assertNotIn("E4031", [m[1] for m in msgs])

    def test_callee_ensures_flows_into_caller(self):
        src = (
            'function p(a: Int) -> Int\n  ensures result >= 1\n{ return a * a + 1 }\n'
            'function q(x: Int) -> Int\n  ensures result >= 1\n{ return p(x) }\napp A { println("x") }'
        )
        rep, msgs = prove(src)
        self.assertEqual(rep.violated, 0)
        self.assertGreaterEqual(rep.proved, 1)


class OtherChecksTests(unittest.TestCase):
    def test_contradictory_requires(self):
        rep, msgs = prove('function f(a: Int) -> Int\n  requires a > 5\n  requires a < 3\n{ return a }\napp A { println("x") }')
        self.assertEqual(msgs[0][1], "E4032")

    def test_struct_literal_violating_invariant(self):
        rep, msgs = prove('type P {\n n: Int\n invariant n >= 0, "neg"\n}\napp A {\n let p = P{n: -3}\n println("x")\n}')
        self.assertEqual(msgs[0][1], "E4034")

    def test_struct_literal_satisfying_invariant(self):
        rep, msgs = prove('type P {\n n: Int\n invariant n >= 0\n}\napp A {\n let p = P{n: 3}\n println("x")\n}')
        self.assertEqual((rep.proved, rep.violated, msgs), (1, 0, []))


class IntegerFloatSoundnessTests(unittest.TestCase):
    """Regression: ``x < 2.5`` must allow x == 2 for an Int ``x``."""

    def test_int_below_fractional_bound_is_not_refuted(self):
        src = 'function g(x: Int) -> Int\n  requires x < 2.5\n{ return x }\napp A { println(str(g(2))) }'
        rep, msgs = prove(src)
        self.assertEqual(msgs, [])
        self.assertEqual(rep.violated, 0)

    def test_int_at_or_above_fractional_lower_bound(self):
        base = 'function g(x: Int) -> Int\n  requires x >= 2.5\n{ return x }\n'
        self.assertEqual(prove(base + 'app A { println(str(g(2))) }')[1][0][1], "E4030")
        self.assertEqual(prove(base + 'app A { println(str(g(3))) }')[1], [])


class IntegrationTests(unittest.TestCase):
    def test_default_severity_is_warning_with_w_code(self):
        res, cs = codes(F_NONNEG + 'app A { println(str(f(-1))) }')
        self.assertTrue(res.ok)  # still compiles: runtime enforces (R1003)
        self.assertIn("W4030", cs)
        self.assertEqual(res.contract_proofs.violated, 1)

    def test_can_be_promoted_to_error(self):
        res, cs = codes(F_NONNEG + 'app A { println(str(f(-1))) }', contract_proof_severity=Severity.ERROR)
        self.assertFalse(res.ok)
        self.assertIn("E4030", cs)

    def test_not_run_when_program_has_other_errors(self):
        res, _ = codes(F_NONNEG + 'app A { println(str(f(-1)) + unknown_name) }')
        self.assertIsNone(res.contract_proofs)

    def test_prover_crash_never_breaks_compilation(self):
        import happy.compiler.contract_proofs as cp

        orig = cp.verify_program
        cp.verify_program = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            res, _ = codes('app A { println("hi") }')
        finally:
            cp.verify_program = orig
        self.assertTrue(res.ok)
        self.assertIsNone(res.contract_proofs)

    def test_no_false_positives_on_shipped_examples(self):
        for path in sorted(glob.glob(os.path.join(ROOT, "examples", "*.hpy"))):
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            try:
                res = analyze(parse(src, filename=path), filename=path)
            except Exception:  # noqa: BLE001 - examples that need other modules
                continue
            bad = [d.code for d in res.diagnostics if d.code in ("W4030", "W4031", "W4032", "W4034", "E4030", "E4031", "E4032", "E4034")]
            self.assertEqual(bad, [], os.path.basename(path))

    def test_cli_check_prove_and_deny(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.hpy")
            with open(path, "w") as fh:
                fh.write(F_NONNEG + 'app A { println(str(f(-1))) }\n')
            env = dict(os.environ, PYTHONPATH=ROOT)
            plain = subprocess.run([sys.executable, "-m", "happy", "check", path, "--prove"], capture_output=True, text=True, cwd=ROOT, env=env)
            self.assertEqual(plain.returncode, 0, plain.stdout + plain.stderr)
            self.assertIn("W4030", plain.stdout)
            self.assertIn("0 proved, 1 violated", plain.stdout)
            deny = subprocess.run([sys.executable, "-m", "happy", "check", path, "--deny-violations"], capture_output=True, text=True, cwd=ROOT, env=env)
            self.assertEqual(deny.returncode, 1)
            self.assertIn("E4030", deny.stdout)


class ProverSoundnessFuzzTests(unittest.TestCase):
    def test_fixed_seed_fuzz_runs_are_sound(self):
        spec = importlib.util.spec_from_file_location("fuzz_contracts", os.path.join(ROOT, "tools", "fuzz_contracts.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        old = sys.argv
        try:
            for seed in (31, 32, 33):
                sys.argv = ["fuzz_contracts", "120", str(seed)]
                self.assertEqual(mod.main(), 0, f"seed {seed}")
        finally:
            sys.argv = old


if __name__ == "__main__":
    unittest.main()
