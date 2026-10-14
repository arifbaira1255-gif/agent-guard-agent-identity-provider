"""Happy Step-5 demo: the AI-native layer end to end.

Run with::

    python examples/ai_demo.py

It walks the whole AI-native flow without needing any API key:

1. build a provider (auto-detected; falls back to the offline mock),
2. turn an ``ai`` declaration into a structured, validated plan,
3. constrain the plan with an :class:`AgentSandbox`,
4. push candidate code up the trust ladder with the
   :class:`VerificationPipeline`, and
5. show the security analyzer rejecting unsafe code.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.ai import (  # noqa: E402
    AgentSandbox,
    MockProvider,
    PlanGenerator,
    SandboxViolation,
    VerificationPipeline,
    provider_from_env,
)
from happy.security import SecurityAnalyzer  # noqa: E402

PLAN_JSON = (
    '{"goal": "add a safe deposit function", "steps": ['
    '{"id": "s1", "kind": "read", "description": "read the account module", "target": "src/account.hpy"},'
    '{"id": "s2", "kind": "generate", "description": "write the deposit function", "capability": "ai", "depends_on": ["s1"]},'
    '{"id": "s3", "kind": "verify", "description": "verify contracts and rules", "depends_on": ["s2"]}'
    "]}"
)

GOOD_CODE = """
module demo
function deposit(balance: Float, amount: Float) -> Float
    requires amount > 0.0
    ensures result == balance + amount
{
    return balance + amount
}
"""

UNSAFE_CODE = """
module demo
type Account {
    id: Int
    secret pin: Byte
}
function leak(a: Account) -> Unit {
    print(a.pin)
}
"""


def rule(title: str) -> None:
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main() -> int:
    rule("1. Provider abstraction")
    provider = provider_from_env()
    print(f"auto-detected provider: {provider!r}")
    # For a deterministic demo we use the offline mock.
    provider = MockProvider(responses=[PLAN_JSON])
    print(f"using for the demo:     {provider!r}")

    rule("2. Structured plan from an ai declaration")
    planner = PlanGenerator(provider)
    plan = planner.generate(prompt="add a deposit function", goal="add a safe deposit function")
    print(plan.to_json())

    rule("3. Agent capability sandbox")
    sandbox = AgentSandbox(
        read_paths=["src/**"],
        write_paths=["out/**"],
        capabilities=["ai"],
        allow_network=False,
    )
    try:
        sandbox.check_plan(plan)
        print("plan accepted by sandbox")
    except SandboxViolation as exc:
        print(f"plan refused: {exc}")
    try:
        sandbox.check_write("/etc/passwd")
    except SandboxViolation as exc:
        print(f"out-of-scope write refused: {exc}")

    rule("4. Trust ladder — good code reaches APPROVED")
    pipeline = VerificationPipeline(run_tests=False, security=SecurityAnalyzer())
    result = pipeline.verify(GOOD_CODE, filename="good.hpy")
    print(result.report())

    rule("5. Trust ladder — unsafe code is REJECTED")
    result = pipeline.verify(UNSAFE_CODE, filename="unsafe.hpy")
    print(result.report())

    print("\nDone. AI output is never executed until it is APPROVED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
