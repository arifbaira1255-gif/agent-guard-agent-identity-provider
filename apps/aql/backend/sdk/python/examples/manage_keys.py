"""Key management: mint, list, and revoke API keys.

Run with::

    export AQL1_API_KEY=sk-...        # an existing key with key-management scope
    python examples/manage_keys.py
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
        print("Set AQL1_API_KEY first.")
        return 1

    client = AQL1(
        api_key=api_key,
        base_url=os.environ.get("AQL1_BASE_URL", "http://localhost:8000"),
    )

    try:
        # 1. Mint a new key. The raw key is returned exactly once.
        created = client.create_key(
            "ci-pipeline",
            owner_id="team-platform",
            scopes=["agent:run", "agent:read"],
            rate_limit_requests=120,
            rate_limit_window_seconds=60,
        )
        print(f"created key_id={created.key.key_id}")
        print(f"RAW KEY (store it now): {created.api_key}")
        print(f"warning: {created.warning}")

        # 2. List key metadata (never the raw key or its hash).
        print("\nkeys:")
        for key in client.list_keys():
            state = "active" if key.active else "revoked"
            print(f"  {key.key_id}  {key.name:<16} {state:<8} scopes={key.scopes}")

        # 3. Revoke the key we just made.
        revoked = client.revoke_key(created.key.key_id)
        print(f"\nrevoked {revoked.key_id} (active={revoked.active})")

    except AQL1Error as exc:
        print(f"AQL-1 error: {exc}")
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
