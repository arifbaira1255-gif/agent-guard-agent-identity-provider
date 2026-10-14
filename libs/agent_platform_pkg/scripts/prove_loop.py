"""End-to-end proof that the platform loop works: tools, denial, budgets, sandbox, memory.

Run:  cd integration && PYTHONPATH=contract:platform python3 platform/scripts/prove_loop.py
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent_platform.budget import CancellationToken, RunBudget
from agent_platform.cli import build_agent
from agent_platform.router import DeterministicProvider
from agent_platform.tools import AllowAllGate, CallableGate, DenyAllGate
from agent_platform.types import ToolCall

RESULTS = []


def record(name: str, ok: bool, detail: str) -> None:
    RESULTS.append({"check": name, "ok": ok, "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")


def main() -> int:
    workspace = tempfile.mkdtemp(prefix="ap-ws-")
    Path(workspace, "notes.txt").write_text("hello from the workspace\n", encoding="utf-8")

    # ---- 1. a real tool call, then a final answer -------------------------------
    provider = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
        "done listing the workspace",
    ])
    agent = build_agent(PlatformConfig(True), gate=AllowAllGate(), provider=provider,
                        workspace_root=workspace)
    result = agent.run("List the workspace.")
    called = [t["name"] for r in result.step_records for t in r.tool_results]
    record("tool-call-then-answer", result.ok and "list_dir" in called,
           f"outcome={result.outcome.value} ok={result.ok} tools={called} "
           f"answer={result.final_text!r}")

    # ---- 2. deny-all default gate refuses the protected call -------------------
    provider2 = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
    ])
    agent2 = build_agent(PlatformConfig(True), gate=DenyAllGate(), provider=provider2,
                         workspace_root=workspace)
    result2 = agent2.run("Read notes.txt.")
    denied = [t for r in result2.step_records for t in r.tool_results
              if t.get("error_code") == "authorization_denied"]
    record("deny-all-gate-refuses", (not result2.ok) and result2.outcome.value == "tool_denied"
           and bool(denied),
           f"outcome={result2.outcome.value} denials={len(denied)} "
           f"reason={(denied[0].get('error') if denied else None)!r}")

    # ---- 3. a policy that allows listing but NOT reading -----------------------
    def policy(*, action, resource, tool, context):
        return {"allowed": action == "fs.list", "reason": "policy: read-only listing",
                "decision": "ALLOW" if action == "fs.list" else "DENY"}

    provider3 = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
    ])
    agent3 = build_agent(PlatformConfig(True), gate=CallableGate(policy), provider=provider3,
                         workspace_root=workspace)
    result3 = agent3.run("Read the notes file.")
    record("policy-denies-read", result3.outcome.value == "tool_denied",
           f"outcome={result3.outcome.value} error={result3.error!r}")

    # ---- 4. malformed tool arguments are refused WITH the model's own text, and the
    #         loop gives the model a chance to repair rather than acting on bad input -----
    provider4 = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "read_file", "arguments": {},
                         "raw_arguments": '{"path": 42}'}]},
        {"tool_calls": [{"id": "c2", "name": "read_file", "arguments": {"path": "notes.txt"}}]},
        "recovered and read the file",
    ])
    agent4 = build_agent(PlatformConfig(True), gate=AllowAllGate(), provider=provider4,
                         workspace_root=workspace)
    result4 = agent4.run("Read a file.")
    invalid4 = [t for r in result4.step_records for t in r.tool_results
                if t.get("error_code") == "invalid_tool_arguments"]
    successful = [t for r in result4.step_records for t in r.tool_results if t.get("ok")]
    problems = (invalid4[0].get("metadata") or {}).get("problems") if invalid4 else None
    record("malformed-args-refused-then-repaired",
           bool(invalid4) and bool(successful) and result4.ok,
           f"outcome={result4.outcome.value} invalid_problems={problems} "
           f"later_success={bool(successful)}")

    # ---- 5. step budget stops an unbounded tool loop ---------------------------
    provider5 = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
    ], repeat_last=True)
    agent5 = build_agent(PlatformConfig(True), gate=AllowAllGate(), provider=provider5,
                         workspace_root=workspace)
    result5 = agent5.run("Loop forever.", budget=RunBudget(max_steps=3, max_tool_calls=50))
    record("step-budget-stops-loop", result5.outcome.value == "max_steps" and result5.steps == 3,
           f"outcome={result5.outcome.value} steps={result5.steps} error={result5.error!r}")

    # ---- 6. wall-clock budget ----------------------------------------------------
    provider6 = DeterministicProvider([
        {"tool_calls": [{"id": "c1", "name": "list_dir", "arguments": {"path": "."}}]},
    ])
    agent6 = build_agent(PlatformConfig(True), gate=AllowAllGate(), provider=provider6,
                         workspace_root=workspace)
    result6 = agent6.run("Time out.", budget=RunBudget(wall_clock_s=0.0001, max_steps=10))
    record("wall-clock-budget", result6.outcome.value == "budget_exceeded",
           f"outcome={result6.outcome.value} error={result6.error!r}")

    # ---- 7. cancellation --------------------------------------------------------
    token = CancellationToken()
    token.cancel("operator stop")
    provider7 = DeterministicProvider(["never used"])
    agent7 = build_agent(PlatformConfig(True), gate=AllowAllGate(), provider=provider7,
                         workspace_root=workspace)
    result7 = agent7.run("Cancelled.", token=token)
    record("cancellation", result7.outcome.value == "cancelled",
           f"outcome={result7.outcome.value} error={result7.error!r}")

    # ---- 8. path traversal is blocked below the policy --------------------------
    from agent_platform.builtin_tools import PathJailError, safe_join
    blocked = False
    try:
        safe_join(workspace, "../../etc/passwd")
    except PathJailError:
        blocked = True
    record("path-traversal-blocked", blocked, "safe_join refused ../../etc/passwd")

    # ---- 9. every provider failing is a hard error, never a fabricated answer ----
    from agent_platform.router import ModelRouter, Route
    from agent_platform.errors import ProviderUnavailable

    class Boom:
        name = "boom"

        def complete(self, request):
            raise RuntimeError("upstream down")

    router = ModelRouter(PlatformConfig(True), routes=[Route(Boom(), "m")])
    raised = False
    try:
        router.complete([])
    except ProviderUnavailable:
        raised = True
    record("provider-failure-is-hard-error", raised, "all routes failing raised "
                                                     "ProviderUnavailable (no fake completion)")

    # ---- 10. secrets never reach the transcript or an audit event ---------------
    from agent_platform.events import EventBus, recording_sink
    store: list = []
    bus = EventBus([recording_sink(store)], capacity=1)
    bus.record(event_type="platform.test", outcome="ok",
               metadata={"api_key": "sk-live-SECRET", "safe": "visible"})
    bus.flush()
    leaked = any("sk-live-SECRET" in json.dumps(e) for e in store)
    record("secrets-not-in-events", (not leaked) and bool(store),
           f"events={len(store)} leaked={leaked}")

    # ---- 11. the tool guard records allow and deny in its audit ------------------
    summary = agent2.guard.summary()
    record("guard-audits-denials", summary["denials"] >= 1,
           f"gate={summary['gate']} tool_calls={summary['tool_calls']} "
           f"denials={summary['denials']}")

    # ---- 12. tracing produced evidence ------------------------------------------
    spans = agent.tracer.spans()
    exported = agent.tracer.export()
    record("tracing-evidence", len(spans) >= 3 and bool(exported.get("resourceSpans")),
           f"spans={[s.name for s in spans]}")

    # ---- 13. deny-all is the default posture when nothing is wired ---------------
    from agent_platform.tools import ToolRegistry, ToolGuard
    default_guard = ToolGuard(ToolRegistry())
    d = default_guard.invoke(ToolCall(name="anything", arguments={}))
    record("default-gate-is-deny-all", d.denied and default_guard.gate.name == "DenyAllGate",
           f"gate={default_guard.gate.name} denied={d.denied} reason={d.error!r}")

    # ---- 14. no isolation backend -> untrusted code refuses ----------------------
    from agent_platform.sandbox import SandboxBridge
    bridge = SandboxBridge(runtime=None, require_isolation=True)
    sres = bridge.run("print(1)")
    record("sandbox-refuses-without-isolation",
           (not sres.ok) and sres.kind == "isolation_unavailable",
           f"kind={sres.kind} error={sres.error!r}")

    passed = sum(1 for r in RESULTS if r["ok"])
    print(f"\n{passed}/{len(RESULTS)} proofs passed")
    Path("/tmp/ap_proof.json").write_text(json.dumps(RESULTS, indent=2), encoding="utf-8")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    import sys

    from agent_platform.config import PlatformConfig

    sys.exit(main())
