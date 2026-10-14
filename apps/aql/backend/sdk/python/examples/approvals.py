"""Human-in-the-loop: run a high-risk action, then approve or reject it.

Run with::

    export AQL1_API_KEY=sk-...
    python examples/approvals.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aql1 import AQL1, AQL1Error, ApprovalRequiredError  # noqa: E402


def main() -> int:
    api_key = os.environ.get("AQL1_API_KEY")
    if not api_key:
        print("Set AQL1_API_KEY first.")
        return 1

    client = AQL1(
        api_key=api_key,
        base_url=os.environ.get("AQL1_BASE_URL", "http://localhost:8000"),
    )

    try:
        # A high-risk action (sending an external email) pauses for approval.
        started = client.run_agent(
            prompt="Email the Q3 report to the client.",
            action_type="email.send",
            payload={"to": "client@example.com", "subject": "Q3 report"},
            allow_human_approval=True,
        )

        if not started.is_pending_approval:
            print(f"Run did not pause (status={started.status}).")
            return 0

        print(f"Paused for approval: {started.approval_id}")
        print("A human reviewer would now approve or reject this in the dashboard.")

        # Approve it (use decision="reject" to reject instead).
        result = client.approve(
            started.approval_id or "",
            decision="approve",
            approver="arif",
            note="Verified the recipient and attachment.",
        )
        print(f"Decision recorded: {result.get('status')}")

        # Poll the run to completion after the resume.
        status = client.wait_for_completion(started.task_id, poll_interval=1.0, timeout=120.0)
        print(f"Final status: {status.status}")
        if status.is_success:
            print("Answer:", (status.result or {}).get("answer"))

    except ApprovalRequiredError as exc:
        # Raised when allow_human_approval=False but the action was high-risk.
        print(f"Approval required (id={exc.approval_id}); approve it out of band.")
    except AQL1Error as exc:
        print(f"AQL-1 error: {exc}")
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
