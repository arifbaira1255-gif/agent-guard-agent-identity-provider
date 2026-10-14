"""Tests for the Step 7 cross-file module system."""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.backend import compile_project  # noqa: E402
from happy.compiler.modules import (  # noqa: E402
    ModuleLoader,
    ModuleResolutionError,
)
from happy.runtime import RuntimeContext  # noqa: E402


assert ModuleResolutionError  # re-exported for callers


def write(path: str, content: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(content).lstrip())
    return path


class _Project:
    """A temporary multi-module project on disk."""

    def __init__(self, files: dict) -> None:
        self.dir = tempfile.mkdtemp(prefix="happy_proj_")
        for name, content in files.items():
            write(os.path.join(self.dir, name), content)

    def path(self, name: str) -> str:
        return os.path.join(self.dir, name)

    def run(self, entry: str = "main.hpy"):
        program = compile_project(self.path(entry), search_paths=[self.dir])
        ctx = RuntimeContext(
            filename=self.path(entry),
            source=None,
            module=program.module,
            sourcemap=program.sourcemap,
        )
        return program.run(ctx), program


MATH = """
    module demo.math

    export PI, square

    let PI = 3.0

    function square(x: Int) -> Int {
        return x * x
    }

    function private_helper() -> Int {
        return 1
    }
"""

MAIN = """
    module demo.main

    import demo.math { square }

    app Main {
        println(str(square(7)))
    }
"""


class TestModuleLoader(unittest.TestCase):
    def test_loads_dependencies_first(self):
        project = _Project({"math.hpy": MATH, "main.hpy": MAIN})
        loaded = ModuleLoader(search_paths=[project.dir]).load(project.path("main.hpy"))
        names = [m.name for m in loaded.modules]
        # The dependency comes before the entry module.
        self.assertLess(names.index("demo.math"), names.index("demo.main"))

    def test_missing_module_raises(self):
        project = _Project({"main.hpy": "module m\nimport nope { x }\napp A { }\n"})
        loaded = ModuleLoader(search_paths=[project.dir]).load(project.path("main.hpy"))
        self.assertIn("nope", loaded.unresolved)

    def test_cycle_detection(self):
        project = _Project(
            {
                "a.hpy": "module a\nimport b { }\napp A { }\n",
                "b.hpy": "module b\nimport a { }\napp B { }\n",
            }
        )
        with self.assertRaises(ModuleResolutionError):
            ModuleLoader(search_paths=[project.dir]).load(project.path("a.hpy"))

    def test_interfaces_built(self):
        project = _Project({"math.hpy": MATH, "main.hpy": MAIN})
        loaded = ModuleLoader(search_paths=[project.dir]).load_project(
            project.path("main.hpy")
        )
        interface = loaded.interfaces["demo.math"]
        self.assertIn("square", interface.functions)
        self.assertIn("PI", interface.values)


class TestMultiModuleExecution(unittest.TestCase):
    def test_cross_module_call(self):
        project = _Project({"math.hpy": MATH, "main.hpy": MAIN})
        result, _ = project.run()
        self.assertTrue(result.ok, result.error)
        self.assertIn("49", result.output)

    def test_module_constant_visible(self):
        project = _Project(
            {
                "math.hpy": MATH,
                "main.hpy": textwrap.dedent(
                    """
                    module demo.main
                    import demo.math { square }

                    function main2() -> Void {
                        println(str(square(3)))
                    }

                    app Main {
                        println(str(PI))
                    }
                    """
                ),
            }
        )
        result, _ = project.run()
        self.assertTrue(result.ok, result.error)
        self.assertIn("3.0", result.output)

    def test_three_modules_chain(self):
        project = _Project(
            {
                "base.hpy": (
                    "module base\nexport twice\n"
                    "function twice(x: Int) -> Int { return x + x }\n"
                ),
                "mid.hpy": (
                    "module mid\nimport base { twice }\nexport quad\n"
                    "function quad(x: Int) -> Int { return twice(twice(x)) }\n"
                ),
                "main.hpy": (
                    "module main\nimport mid { quad }\n"
                    "app A { println(str(quad(3))) }\n"
                ),
            }
        )
        result, _ = project.run()
        self.assertTrue(result.ok, result.error)
        self.assertIn("12", result.output)


class TestConstants(unittest.TestCase):
    def test_module_constant(self):
        project = _Project(
            {
                "main.hpy": textwrap.dedent(
                    """
                    module m
                    let LIMIT = 10
                    app A { println(str(LIMIT)) }
                    """
                )
            }
        )
        result, _ = project.run()
        self.assertTrue(result.ok, result.error)
        self.assertIn("10", result.output)

    def test_typed_constant_mismatch(self):
        from happy.compiler import analyze

        src = 'module m\nlet N: Int = "no"\napp A { }\n'
        res = analyze(src, filename="m.hpy")
        self.assertTrue(res.errors, res.diagnostics)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
