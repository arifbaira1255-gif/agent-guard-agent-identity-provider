"""OS-level isolation: policy, fail-closed behaviour, and real escape probes."""
from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.ai.isolation import (
    IsolationPolicy, IsolationUnavailable, available_backends,
    isolation_status, select_backend, self_test,
)
from happy.ai.sandbox import run_sandboxed_python

HAVE_BACKEND = any(ok for ok, _ in available_backends().values())


class TestPolicy(unittest.TestCase):
    def test_rejects_bad_mode_and_backend(self):
        with self.assertRaises(ValueError):
            IsolationPolicy(mode="yolo")
        with self.assertRaises(ValueError):
            IsolationPolicy(backend="chroot-only")

    def test_network_can_never_be_enabled(self):
        with self.assertRaises(ValueError):
            IsolationPolicy(network=True)

    def test_env_configuration(self):
        old = os.environ.get("HAPPY_ISOLATION")
        os.environ["HAPPY_ISOLATION"] = "required"
        try:
            self.assertEqual(IsolationPolicy.from_env().mode, "required")
        finally:
            if old is None:
                os.environ.pop("HAPPY_ISOLATION")
            else:
                os.environ["HAPPY_ISOLATION"] = old

    def test_off_mode_selects_nothing(self):
        self.assertIsNone(select_backend(IsolationPolicy(mode="off")))


class TestFailClosed(unittest.TestCase):
    def test_explicit_unavailable_backend_never_downgrades(self):
        # podman is not installed in CI/dev images; even in 'auto' mode an
        # explicit backend request must not silently fall back.
        if available_backends()["podman"][0]:
            self.skipTest("podman is available here")
        with self.assertRaises(IsolationUnavailable):
            select_backend(IsolationPolicy(mode="auto", backend="podman"))

    def test_required_mode_refuses_to_run_without_backend(self):
        if available_backends()["podman"][0]:
            self.skipTest("podman is available here")
        ok, out = run_sandboxed_python(
            "print(1)", isolation=IsolationPolicy(mode="required", backend="podman")
        )
        self.assertFalse(ok)
        self.assertIn("sandbox refused", out)

    def test_status_report_shape(self):
        report = isolation_status(IsolationPolicy(mode="auto"))
        self.assertIn("backends", report)
        self.assertIn("os_isolated", report)


@unittest.skipUnless(HAVE_BACKEND, "no OS-level isolation backend on this host")
class TestRealIsolation(unittest.TestCase):
    policy = IsolationPolicy(mode="required")

    def test_escape_self_test_passes(self):
        result = self_test(self.policy)
        self.assertTrue(result["ok"], result)

    def test_python_runs_normally_inside_jail(self):
        self.assertEqual(
            run_sandboxed_python("print(sum(range(10)))", isolation=self.policy),
            (True, "45"),
        )

    def test_timeout_kills_whole_jail(self):
        start = time.time()
        ok, out = run_sandboxed_python("while True: pass", timeout=1, isolation=self.policy)
        self.assertFalse(ok)
        self.assertIn("timed out", out)
        self.assertLess(time.time() - start, 8)

    def test_output_flood_is_capped_in_jail(self):
        ok, out = run_sandboxed_python(
            "while True: print('A' * 1000)", timeout=3, max_output_tokens=50,
            isolation=self.policy,
        )
        self.assertFalse(ok)
        self.assertLessEqual(len(out), 50 * 4 + 5)

    def test_no_host_residue_left_behind(self):
        before = {n for n in os.listdir("/tmp") if n.startswith("happy-jail")}
        run_sandboxed_python("print(1)", isolation=self.policy)
        after = {n for n in os.listdir("/tmp") if n.startswith("happy-jail")}
        self.assertEqual(before, after)

    def test_language_level_scan_still_applies(self):
        ok, out = run_sandboxed_python("import os\nprint(os.listdir('/'))", isolation=self.policy)
        self.assertFalse(ok)
        self.assertIn("sandbox violation", out)


if __name__ == "__main__":
    unittest.main()
