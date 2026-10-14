"""Quickstart: start a run, poll it, and print the result.

Run with::

    export AQL1_API_KEY=sk-...
    python examples/quickstart.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aql1 import AQL1, AQL1Error  # noqa: E402


def main() -> int:
    api_key = os.environ.get("AQL1_API_KEY")
    if not api_key:
        print("Set AQL1_API_KEY first (mint one with `python examples/manage_keys.py`).")
        return 1

    client = AQL1(
        api_key=api_key,
        base_url=os.environ.get("AQL1_BASE_URL", "http://localhost:8000"),
    )

    try:
        # 1. Start the run (async by default — returns a task handle).
        started = client.run_agent(
            prompt="Summarise the top 3 AI news stories from today.",
            allow_human_approval=True,
        )
        print(f"started task {started.task_id} (status={started.status})")

        # 2. Poll until it settles, printing progress as it goes.
        status = client.wait_for_completion(
            started.task_id,
            poll_interval=1.0,
            timeout=120.0,
            on_progress=lambda s: print(
                f"  {s.status:<18} {s.progress.percent:>5.1f}%  "
                f"${s.cost_usd:.4f}  {s.tokens} tokens"
            ),
        )

        # 3. Report the outcome.
        if status.is_pending_approval:
            print(f"\nPaused for human approval: {status.approval_id}")
            print("Approve it with examples/approvals.py")
        elif status.is_success:
            print("\nCompleted.")
            print("Answer:", (status.result or {}).get("answer"))
        else:
            print(f"\nRun ended with status={status.status} error={status.error}")

    except AQL1Error as exc:
        print(f"AQL-1 error: {exc}")
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
