"""Regression tests for the v9 bug-fix round.

Every test pins one defect that was reproduced against v8 and then fixed.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile

from happy.pipeline import compile_source, run_source


def out(src: str) -> str:
    r = run_source(src, filename="t.hpy")
    assert r.ok and not r.error, f"unexpected failure: {r.error}\n{src}"
    return r.output


def diag_text(src: str) -> str:
    r = compile_source(src, filename="t.hpy")
    return "\n".join(r.diagnostics)


def compiles(src: str) -> bool:
    return compile_source(src, filename="t.hpy").ok


class ScopingTests(unittest.TestCase):
    def test_if_block_let_does_not_clobber_outer(self):
        self.assertEqual(
            out('app A {\n let x = 1\n if true { let x = 2 }\n println(str(x))\n}'), "1\n"
        )

    def test_for_variable_does_not_clobber_outer(self):
        src = 'app A {\n let i = 9\n for i in [1, 2] { println(str(i)) }\n println(str(i))\n}'
        self.assertEqual(out(src), "1\n2\n9\n")

    def test_match_binding_does_not_clobber_outer(self):
        src = (
            'enum E {\n A(Int)\n B\n}\napp M {\n let n = 7\n'
            ' match A(1) {\n A(n) -> { println(str(n)) }\n B -> { println("b") }\n }\n'
            ' println(str(n))\n}'
        )
        self.assertEqual(out(src), "1\n7\n")

    def test_local_shadowing_a_module_constant(self):
        src = 'const K = 5\napp A {\n let K = K + 1\n println(str(K))\n}'
        if compiles(src):
            self.assertEqual(out(src), "6\n")

    def test_same_scope_redeclaration_is_still_an_error(self):
        # Shadowing is only allowed in a *nested* scope (existing E3002).
        self.assertIn("E3002", diag_text('app A {\n let x = 1\n let x = x + 1\n println(str(x))\n}'))


class ReservedNameTests(unittest.TestCase):
    def test_python_keyword_as_local(self):
        self.assertEqual(out('app A {\n let class = 1\n println(str(class))\n}'), "1\n")

    def test_none_as_local(self):
        self.assertEqual(out('app A {\n let None = 1\n println(str(None))\n}'), "1\n")

    def test_keyword_parameter(self):
        self.assertEqual(
            out('function f(lambda: Int) -> Int { return lambda + 1 }\napp A { println(str(f(1))) }'),
            "2\n",
        )

    def test_top_level_keyword_name_is_clean_error(self):
        self.assertIn("E4023", diag_text('function lambda() -> Int { return 1 }\napp A { println("x") }'))


class FloatCoercionTests(unittest.TestCase):
    def test_let(self):
        self.assertEqual(out('app A {\n let x: Float = 2\n println(str(x))\n}'), "2.0\n")

    def test_parameter(self):
        self.assertEqual(
            out('function f(y: Float) -> Float { return y }\napp A { println(str(f(3))) }'), "3.0\n"
        )

    def test_return_value(self):
        self.assertEqual(
            out('function f() -> Float { return 4 }\napp A { println(str(f())) }'), "4.0\n"
        )

    def test_default_parameter(self):
        self.assertEqual(
            out('function f(a: Float = 2) -> Float { return a }\napp A { println(str(f())) }'), "2.0\n"
        )

    def test_struct_field_construction_and_assignment(self):
        src = 'type P {\n f: Float\n}\napp A {\n let p = P{f: 2}\n println(str(p.f))\n p.f = 3\n println(str(p.f))\n}'
        self.assertEqual(out(src), "2.0\n3.0\n")

    def test_bool_is_not_widened(self):
        from happy.runtime.values import to_float

        self.assertIs(to_float(True), True)
        self.assertEqual(to_float(2), 2.0)
        self.assertIsInstance(to_float(2), float)

    def test_float_overflow_is_not_folded_to_invalid_literal(self):
        r = run_source('app A { println(str(1e308 * 10.0)) }', filename="t.hpy")
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output, "inf\n")


class MatchArmTests(unittest.TestCase):
    ENUM = 'enum E {\n A\n B\n}\n'

    def test_braced_single_statement_arm_does_not_return(self):
        src = self.ENUM + (
            'function f(e: E) -> Int {\n match e {\n A -> { println("a") }\n B -> { println("b") }\n }\n'
            ' println("after")\n return 1\n}\napp M { println(str(f(A))) }'
        )
        self.assertEqual(out(src), "a\nafter\n1\n")

    def test_bare_arm_still_yields_the_result(self):
        src = self.ENUM + (
            'function f(e: E) -> Int {\n match e {\n A -> 1\n B -> 2\n }\n}\n'
            'app M { println(str(f(A)) + str(f(B))) }'
        )
        self.assertEqual(out(src), "12\n")


class ReturnAnalysisTests(unittest.TestCase):
    def test_missing_return_is_an_error(self):
        self.assertIn("E4021", diag_text('function f(a: Int) -> Int {\n let b = a\n}\napp A { println(str(f(1))) }'))

    def test_if_without_else_is_an_error(self):
        self.assertIn(
            "E4021",
            diag_text('function f(a: Int) -> Int {\n if a > 0 { return 1 }\n}\napp A { println(str(f(1))) }'),
        )

    def test_if_else_all_paths_ok(self):
        self.assertTrue(compiles(
            'function f(a: Int) -> Int {\n if a > 0 { return 1 } else { return 2 }\n}\napp A { println(str(f(1))) }'
        ))

    def test_unit_function_needs_no_return(self):
        self.assertTrue(compiles('function f() {\n println("x")\n}\napp A { f() }'))


class TypeCheckTests(unittest.TestCase):
    def test_generic_parameters_must_agree(self):
        self.assertIn("E4002", diag_text(
            'function f<T>(a: T, b: T) -> T { return a }\napp A { println(str(f(1, "a"))) }'
        ))

    def test_generic_same_type_ok(self):
        self.assertTrue(compiles('function f<T>(a: T, b: T) -> T { return a }\napp A { println(str(f(1, 2))) }'))

    def test_int_equals_string_is_a_type_error(self):
        self.assertFalse(compiles('app A { println(str(1 == "1")) }'))

    def test_int_equals_float_is_fine(self):
        self.assertEqual(out('app A { println(str(1 == 1.0)) }'), "true\n")

    def test_builtin_arity(self):
        self.assertIn("E4004", diag_text('app A { println(str(len([1], [2]))) }'))

    def test_local_shadowing_builtin_is_not_callable(self):
        self.assertFalse(compiles('app A {\n let len = 5\n println(str(len([1])))\n}'))

    def test_unknown_std_module(self):
        self.assertIn("E3007", diag_text('import std.nope\napp A { println("x") }'))

    def test_second_app_block(self):
        self.assertIn("E4022", diag_text('app A { println("1") }\napp B { println("2") }'))

    def test_trait_impl_return_type_mismatch(self):
        src = (
            'trait T {\n function f(self) -> Int\n}\ntype R {\n w: Int\n}\n'
            'impl T for R {\n function f(self) -> String { return "x" }\n}\napp A { println("x") }'
        )
        self.assertIn("E4014", diag_text(src))

    def test_trait_impl_matching_signature_ok(self):
        src = (
            'trait T {\n function f(self, n: Int) -> Int\n}\ntype R {\n w: Int\n}\n'
            'impl T for R {\n function f(self, n: Int) -> Int { return n }\n}\n'
            'app A { println(str(R{w: 1}.f(2))) }'
        )
        self.assertTrue(compiles(src))


class ParameterDefaultTests(unittest.TestCase):
    F = 'function f(a: Int, b: Int = 5) -> Int { return a + b }\n'

    def test_omitted(self):
        self.assertEqual(out(self.F + 'app A { println(str(f(1))) }'), "6\n")

    def test_supplied(self):
        self.assertEqual(out(self.F + 'app A { println(str(f(1, 2))) }'), "3\n")

    def test_too_few_still_errors(self):
        self.assertIn("E4004", diag_text(self.F + 'app A { println(str(f())) }'))

    def test_too_many_still_errors(self):
        self.assertIn("E4004", diag_text(self.F + 'app A { println(str(f(1, 2, 3))) }'))


class LexerParserTests(unittest.TestCase):
    def test_huge_float_literal_rejected_cleanly(self):
        r = compile_source('app A { let x = 1e400\n println(str(x)) }', filename="t.hpy")
        self.assertFalse(r.ok)

    def test_unary_minus_binds_looser_than_power(self):
        self.assertEqual(out('app A { println(str(-2 ** 2)) }'), "-4\n")

    def test_parenthesised_negative_base(self):
        self.assertEqual(out('app A { println(str((-2) ** 2)) }'), "4\n")

    def test_negative_exponent(self):
        self.assertEqual(out('app A { println(str(2 ** -1)) }'), "0.5\n")


class SandboxTests(unittest.TestCase):
    def test_dunder_member_blocked(self):
        self.assertIn("E4020", diag_text('app A { let x = "s"\n println(x.__class__) }'))

    def test_frame_member_blocked(self):
        src = 'async function g() -> Int { return 1 }\napp A {\n let c = g()\n let f = c.cr_frame.f_builtins\n println("x")\n}'
        self.assertIn("E4020", diag_text(src))

    def test_format_string_traversal_blocked(self):
        self.assertIn("E4020", diag_text('app A { let x = "{0.__globals__}".format(1)\n println(x) }'))

    def test_single_underscore_member_blocked(self):
        self.assertIn("E4020", diag_text('app A { let x = "s"\n println(x._value) }'))

    def test_secret_internals_blocked(self):
        src = 'type S {\n secret pin: String\n}\napp A {\n let a = S{pin: "1"}\n println(a.pin._value)\n}'
        self.assertIn("E4020", diag_text(src))

    def test_struct_field_named_like_blocked_member_is_allowed(self):
        src = 'type A {\n format: String\n}\napp M {\n let x = A{format: "z"}\n println(x.format)\n}'
        self.assertEqual(out(src), "z\n")

    def test_open_is_unknown(self):
        self.assertFalse(compiles('app A { let o = open("/etc/passwd")\n println("x") }'))


class StructMutationTests(unittest.TestCase):
    def test_invariant_checked_and_rolled_back(self):
        src = (
            'type A {\n n: Int\n invariant n >= 0, "neg"\n}\napp M {\n let a = A{n: 1}\n'
            ' a.n = -5\n}'
        )
        r = run_source(src, filename="t.hpy")
        self.assertFalse(r.ok)

    def test_reassigned_secret_stays_secret(self):
        src = (
            'type A {\n secret pin: String\n}\napp M {\n let a = A{pin: "1"}\n a.pin = "99"\n'
            ' println(str(a))\n}'
        )
        o = out(src)
        self.assertNotIn("99", o)


class FormatterTests(unittest.TestCase):
    EXPRS = [
        "(-2) ** 2", "-2 ** 2", "2 ** 3 ** 2", "(2 ** 3) ** 2", "10 - (3 - 1)", "10 - 3 - 1",
        "(1 + 2) * 3", "1 + 2 * 3", "-(1 + 2)", "-(2 ** 2)", "(1 + 2) % 2", "2 * (3 + 4) * 5",
        "10 / (2 * 5)", "10 / 2 * 5", "10 / (2 / 5)", "1 - -1", "(1 < 2) == (2 < 3)",
        "1 + (2 + 3)", "[1, 2, 3][1 + 1]",
    ]

    def test_formatting_preserves_meaning_and_is_idempotent(self):
        from happy.tools.fmt import format_source

        for e in self.EXPRS:
            src = f"app A {{ println(str({e})) }}"
            once = format_source(src).formatted
            self.assertEqual(out(src), out(once), f"meaning changed for {e}: {once!r}")
            self.assertEqual(format_source(once).formatted, once, f"not idempotent: {e}")


class SemverTests(unittest.TestCase):
    def v(self, s):
        from happy.package.manager import Version

        return Version.parse(s)

    def test_spec_prerelease_ordering(self):
        order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                 "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        parsed = [self.v(x) for x in order]
        self.assertEqual(sorted(reversed(parsed)), parsed)

    def test_numeric_prerelease_identifiers_compare_numerically(self):
        self.assertLess(self.v("1.0.0-alpha.2"), self.v("1.0.0-alpha.10"))

    def test_build_metadata_accepted_and_ignored(self):
        self.assertEqual(self.v("1.0.0+a"), self.v("1.0.0+b"))
        self.assertEqual(str(self.v("1.0.0+build")), "1.0.0+build")

    def test_invalid_versions_rejected(self):
        from happy.package.manager import PackageError

        for bad in ["01.2.3", "1.2", "1.2.3-", "1.2.3-01", "1.2.3+", "", "x.y.z"]:
            with self.assertRaises(PackageError, msg=bad):
                self.v(bad)

    def test_ranges_do_not_match_unrelated_prereleases(self):
        from happy.package.manager import _satisfies

        self.assertFalse(_satisfies(self.v("1.5.0-beta"), "^1.2.3"))
        self.assertFalse(_satisfies(self.v("1.0.0-rc1"), "*"))
        self.assertFalse(_satisfies(self.v("1.2.4-beta"), "~1.2.3"))
        self.assertTrue(_satisfies(self.v("1.2.3-beta.2"), "^1.2.3-beta.1"))
        self.assertTrue(_satisfies(self.v("2.0.0"), "*"))

    def test_registry_prefers_release(self):
        from happy.package.manager import Registry

        r = Registry()
        for ver in ["1.0.0", "1.1.0-beta", "1.0.5"]:
            r.add("x", ver)
        self.assertEqual(r.resolve("x", "^1.0.0"), "1.0.5")
        self.assertEqual(r.resolve("x", "*"), "1.0.5")


class InstallPackageTests(unittest.TestCase):
    def setUp(self):
        from happy.tools.publish import create_package

        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "p", "src"))
        with open(os.path.join(self.d, "p", "src", "main.hpy"), "w") as fh:
            fh.write('app A { println("hi") }\n')
        with open(os.path.join(self.d, "p", "happy.toml"), "w") as fh:
            fh.write('[package]\nname = "p"\nversion = "1.0.0"\n')
        self.archive = os.path.join(self.d, "p.hpyz")
        create_package(os.path.join(self.d, "p"), output=self.archive)

    def _rewrite(self, name, mutate):
        path = os.path.join(self.d, name)
        with zipfile.ZipFile(self.archive) as zin, zipfile.ZipFile(path, "w") as zout:
            items = {i.filename: zin.read(i.filename) for i in zin.infolist()}
            mutate(items)
            for k, v in items.items():
                zout.writestr(k, v)
        return path

    def _install(self, archive, dest="out"):
        from happy.tools.publish import install_package

        return install_package(archive, os.path.join(self.d, dest))

    def test_clean_install(self):
        info = self._install(self.archive)
        self.assertEqual(info.name, "p")
        self.assertTrue(os.path.isfile(os.path.join(self.d, "out", "src", "main.hpy")))

    def test_tampered_file_rejected_and_nothing_written(self):
        from happy.tools.publish import PackageInstallError

        bad = self._rewrite("bad.hpyz", lambda it: it.__setitem__("src/main.hpy", it["src/main.hpy"] + b"//evil\n"))
        with self.assertRaises(PackageInstallError):
            self._install(bad)
        self.assertFalse(os.path.exists(os.path.join(self.d, "out", "src", "main.hpy")))

    def test_unlisted_file_rejected(self):
        from happy.tools.publish import PackageInstallError

        bad = self._rewrite("extra.hpyz", lambda it: it.__setitem__("extra.hpy", b"x"))
        with self.assertRaises(PackageInstallError):
            self._install(bad)
        self.assertFalse(os.path.exists(os.path.join(self.d, "out", "extra.hpy")))

    def test_listed_file_missing_rejected(self):
        from happy.tools.publish import PackageInstallError

        bad = self._rewrite("miss.hpyz", lambda it: it.pop("src/main.hpy"))
        with self.assertRaises(PackageInstallError):
            self._install(bad)

    def test_sibling_prefix_traversal_rejected(self):
        """'../outX/evil' starts with the string 'out' but is outside it."""
        from happy.tools.publish import PackageInstallError

        def mutate(items):
            manifest = json.loads(items["happy.pkg.json"])
            blob = b"evil"
            manifest["checksums"]["../outX/evil.hpy"] = "sha256:" + hashlib.sha256(blob).hexdigest()
            items["happy.pkg.json"] = json.dumps(manifest).encode()
            items["../outX/evil.hpy"] = blob

        bad = self._rewrite("trav.hpyz", mutate)
        with self.assertRaises(PackageInstallError):
            self._install(bad, dest="out")
        self.assertFalse(os.path.exists(os.path.join(self.d, "outX")))

    def test_absolute_member_rejected(self):
        from happy.tools.publish import PackageInstallError

        bad = self._rewrite("abs.hpyz", lambda it: it.__setitem__("/tmp/happy_abs_evil", b"x"))
        with self.assertRaises(PackageInstallError):
            self._install(bad)

    def test_missing_manifest_and_bad_zip_are_clean_errors(self):
        from happy.tools.publish import PackageInstallError

        nomanifest = os.path.join(self.d, "nm.hpyz")
        with zipfile.ZipFile(nomanifest, "w") as z:
            z.writestr("a.hpy", "x")
        with self.assertRaises(PackageInstallError):
            self._install(nomanifest)
        junk = os.path.join(self.d, "junk.hpyz")
        with open(junk, "wb") as fh:
            fh.write(b"not a zip")
        with self.assertRaises(PackageInstallError):
            self._install(junk)

    def test_manifest_without_checksums_rejected(self):
        from happy.tools.publish import PackageInstallError

        def mutate(items):
            manifest = json.loads(items["happy.pkg.json"])
            manifest.pop("checksums")
            items["happy.pkg.json"] = json.dumps(manifest).encode()

        with self.assertRaises(PackageInstallError):
            self._install(self._rewrite("nock.hpyz", mutate))


class ReplAndStrictCompileTests(unittest.TestCase):
    def repl(self):
        from happy.tools.repl import HappyREPL

        return HappyREPL()

    def test_syntax_error_does_not_poison_the_session(self):
        r = self.repl()
        self.assertFalse(r.feed("let x = = 1").ok)
        self.assertTrue(r.feed("function f() -> Int { return 1 }").ok)
        self.assertEqual(r.feed("app A { println(str(f())) }").output, "1\n")

    def test_app_is_not_rerun_by_later_declarations(self):
        r = self.repl()
        r.feed("function f() -> Int { return 1 }")
        self.assertEqual(r.feed('app A { println("hi") }').output, "hi\n")
        later = r.feed("function g() -> Int { return 2 }")
        self.assertFalse(later.ran)
        self.assertEqual(later.output, "")

    def test_multiline_input(self):
        r = self.repl()
        self.assertTrue(r.feed("function h() -> Int {").incomplete)
        self.assertTrue(r.feed("  return 5").incomplete)
        self.assertTrue(r.feed("}").ok)
        self.assertEqual(r.feed("app C { println(str(h())) }").output, "5\n")

    def test_repl_refuses_programs_with_errors(self):
        r = self.repl()
        res = r.feed('app A { let o = open("/etc/hostname")\n println("x") }')
        self.assertFalse(res.ok)
        self.assertIn("E3001", res.output)

    def test_repl_blocks_format_string_leak(self):
        res = self.repl().feed('app A { let x = "{0.__globals__}".format(1)\n println(x) }')
        self.assertFalse(res.ok)

    def test_ill_typed_declaration_is_not_committed(self):
        r = self.repl()
        self.assertFalse(r.feed('function bad() -> Int { return "s" }').ok)
        self.assertEqual(r.buffer, [])

    def test_strict_backend_compile_raises(self):
        from happy.backend import compile_source as backend_compile
        from happy.compiler.errors import HappyError

        with self.assertRaises(HappyError):
            backend_compile('app A { let o = open("x")\n println("x") }', strict=True)


if __name__ == "__main__":
    unittest.main()
