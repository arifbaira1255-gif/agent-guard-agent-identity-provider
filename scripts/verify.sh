#!/usr/bin/env bash
# Runs the checks that need no network and no web stack. Full AQL/AgentGuard/Happy suites need
# their own dependencies installed (pip install -r ...).
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="apps/aql/backend:libs/contract:libs/happy-lang"
python3 - <<'PY'
import sys, types, importlib.util, inspect, traceback
b = "apps/aql/backend"
core = types.ModuleType("core"); core.__path__ = [b + "/core"]; sys.modules["core"] = core
spec = importlib.util.spec_from_file_location("t", b + "/tests/test_secure_tools.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fails = n = 0
for name, fn in inspect.getmembers(m, inspect.isfunction):
    if name.startswith("test_"):
        n += 1
        try: fn(); print("PASS", name)
        except Exception: fails += 1; print("FAIL", name); traceback.print_exc()
print(f"\n{n - fails}/{n} passed"); sys.exit(1 if fails else 0)
PY
