"""Async quickstart: run an agent and stream progress updates.

Run with::

    export AQL1_API_KEY=sk-...
    python examples/async_quickstart.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aql1 import AQL1Error, AsyncAQL1  # noqa: E402


async def main() -> int:
    api_key = os.environ.get("AQL1_API_KEY")
    if not api_key:
        print("Set AQL1_API_KEY first.")
        return 1

    async with AsyncAQL1(
        api_key=api_key,
        base_url=os.environ.get("AQL1_BASE_URL", "http://localhost:8000"),
    ) as client:
        try:
            started = await client.run_agent(
                prompt="Draft a 3-bullet launch plan for a new feature.",
                allow_human_approval=True,
            )
            print(f"started task {started.task_id}")

            # Async-iterate status updates as they arrive.
            async for status in client.stream_progress(
                started.task_id, poll_interval=1.0, timeout=120.0
            ):
                print(
                    f"  {status.status:<18} {status.progress.percent:>5.1f}%  "
                    f"${status.cost_usd:.4f}"
                )
                if status.is_terminal:
                    if status.is_success:
                        print("\nAnswer:", (status.result or {}).get("answer"))
                    elif status.is_pending_approval:
                        print(f"\nPaused for approval: {status.approval_id}")
                    break

        except AQL1Error as exc:
            print(f"AQL-1 error: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
