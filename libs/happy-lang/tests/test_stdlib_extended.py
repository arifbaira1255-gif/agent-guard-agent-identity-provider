"""Tests for the extended standard library added in Step 9.

These exercise the new ``std.*`` modules end to end: Happy source -> compiled
Python -> execution inside the Happy runtime, plus direct unit checks of the
pure helper modules.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.backend import compile_source  # noqa: E402
from happy.runtime import RuntimeContext  # noqa: E402


def run_source(source: str, filename: str = "s.hpy", **kwargs):
    program = compile_source(source, filename=filename)
    ctx = RuntimeContext(
        filename=filename,
        source=source,
        module=program.module,
        sourcemap=program.sourcemap,
        **kwargs,
    )
    return program.run(ctx)


class TestStdModulesImport(unittest.TestCase):
    def test_all_std_modules_importable(self):
        import importlib

        for name in (
            "core", "io", "collections", "json", "async", "crypto",
            "net", "fs", "time", "process", "env", "random", "math",
            "regex", "encoding", "logging",
        ):
            with self.subTest(module=name):
                mod = importlib.import_module(f"happy.std.{name}")
                self.assertTrue(hasattr(mod, "PUBLIC") or name == "core")

    def test_public_names_exist(self):
        import importlib

        for name in (
            "io", "collections", "json", "async", "crypto", "net", "fs",
            "time", "process", "env", "random", "math", "regex", "encoding",
            "logging",
        ):
            mod = importlib.import_module(f"happy.std.{name}")
            for symbol in mod.PUBLIC:
                with self.subTest(module=name, symbol=symbol):
                    self.assertTrue(hasattr(mod, symbol), f"{name}.{symbol}")


class TestStdMath(unittest.TestCase):
    def test_sqrt(self):
        src = "module m\nimport std.math { sqrt }\napp A { println(str(sqrt(25.0))) }\n"
        result = run_source(src, filename="m.hpy")
        self.assertTrue(result.ok, result.error)
        self.assertIn("5.0", result.output)

    def test_pow_and_floor(self):
        src = (
            "module m\nimport std.math { pow, floor }\n"
            "app A { println(str(floor(pow(2.0, 5.0)))) }\n"
        )
        result = run_source(src, filename="m.hpy")
        self.assertTrue(result.ok, result.error)
        self.assertIn("32", result.output)


class TestStdRegex(unittest.TestCase):
    def test_is_match(self):
        src = (
            "module m\nimport std.regex { is_match, find_all }\n"
            'app A {\n'
            '    println(str(is_match("[0-9]+", "abc123")))\n'
            '    println(str(len(find_all("[0-9]+", "a1b2c3"))))\n'
            "}\n"
        )
        result = run_source(src, filename="m.hpy")
        self.assertTrue(result.ok, result.error)
        self.assertIn("true", result.output)
        self.assertIn("3", result.output)


class TestStdEncoding(unittest.TestCase):
    def test_base64_roundtrip(self):
        from happy.std import encoding

        encoded = encoding.base64_encode("hello happy")
        self.assertEqual(encoding.base64_decode(encoded), "hello happy")

    def test_hex_roundtrip(self):
        from happy.std import encoding

        self.assertEqual(encoding.hex_decode(encoding.hex_encode("abc")), "abc")

    def test_json_roundtrip(self):
        from happy.std import encoding

        text = encoding.json_encode({"b": 2, "a": 1})
        self.assertEqual(text, '{"a": 1, "b": 2}')
        self.assertEqual(encoding.json_decode(text), {"a": 1, "b": 2})


class TestStdFsAndProcessCapability(unittest.TestCase):
    def test_list_dir_requires_capability(self):
        from happy.std import fs
        from happy.runtime.capability import CapabilityChecker, CapabilityPolicy

        policy = CapabilityPolicy(mode="enforce", default_allow=False)
        checker = CapabilityChecker(policy=policy)
        fs.use_checker(checker)
        try:
            with self.assertRaises(Exception):
                fs.list_dir(".")
        finally:
            fs.use_checker(None)

    def test_list_dir_allowed_with_capability(self):
        from happy.std import fs
        from happy.runtime.capability import CapabilityChecker, CapabilityPolicy

        policy = CapabilityPolicy(mode="enforce", default_allow=True)
        checker = CapabilityChecker(policy=policy)
        fs.use_checker(checker)
        try:
            entries = fs.list_dir(".")
            self.assertIsInstance(entries, list)
        finally:
            fs.use_checker(None)

    def test_process_run_requires_capability(self):
        from happy.std import process
        from happy.runtime.capability import CapabilityChecker, CapabilityPolicy

        policy = CapabilityPolicy(mode="enforce", default_allow=False)
        checker = CapabilityChecker(policy=policy)
        process.use_checker(checker)
        try:
            with self.assertRaises(Exception):
                process.run("echo hi")
        finally:
            process.use_checker(None)


class TestStdRandomAndTime(unittest.TestCase):
    def test_seeded_random_is_deterministic(self):
        from happy.std import random as hr

        hr.seed(42)
        a = [hr.random_int(0, 100) for _ in range(5)]
        hr.seed(42)
        b = [hr.random_int(0, 100) for _ in range(5)]
        self.assertEqual(a, b)

    def test_time_module(self):
        from happy.std import time as ht

        self.assertIsInstance(ht.timestamp(), int)
        self.assertIsInstance(ht.now(), str)
        self.assertGreater(ht.year(), 2000)


class TestStdLogging(unittest.TestCase):
    def test_logging_sink(self):
        from happy.std import logging as hl

        captured = []
        hl.set_sink(captured.append)
        hl.set_level("info")
        try:
            hl.info("hello")
            hl.debug("hidden at info level")
        finally:
            hl.set_sink(None)
            hl.set_level("info")
        self.assertTrue(any("hello" in line for line in captured))
        self.assertFalse(any("hidden" in line for line in captured))

    def test_logging_available_in_source(self):
        src = (
            "module m\nimport std.logging { info }\n"
            'app A { info("from happy") }\n'
        )
        result = run_source(src, filename="m.hpy")
        self.assertTrue(result.ok, result.error)


class TestStdEnv(unittest.TestCase):
    def test_env_get_or(self):
        # Environment access is capability-gated (like file/process access), so
        # the operation must run inside an agent holding an 'env' capability.
        src = (
            "module m\nimport std.env { get_or, has }\n"
            "capability EnvAccess { grants env }\n"
            "agent A {\n"
            "    capability [EnvAccess]\n"
            "    function go() -> Unit {\n"
            '        println(get_or("HAPPY_TEST_MISSING_VAR", "fallback"))\n'
            '        println(str(has("HAPPY_TEST_MISSING_VAR")))\n'
            "    }\n"
            "}\n"
            "app Main { A.go() }\n"
        )
        result = run_source(src, filename="m.hpy")
        self.assertTrue(result.ok, result.error)
        self.assertIn("fallback", result.output)
        self.assertIn("false", result.output)

    def test_env_denied_without_capability(self):
        # Reading an environment variable outside any agent must be refused.
        src = (
            "module m\nimport std.env { get_or }\n"
            'app A { println(get_or("PATH", "x")) }\n'
        )
        result = run_source(src, filename="m.hpy")
        self.assertFalse(result.ok)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
