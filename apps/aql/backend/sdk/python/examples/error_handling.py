"""Error handling: retries, rate limits, and typed exceptions.

Run with::

    export AQL1_API_KEY=sk-...
    python examples/error_handling.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aql1 import (  # noqa: E402
    AQL1,
    APIError,
    APIConnectionError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    ValidationError,
)


def main() -> int:
    api_key = os.environ.get("AQL1_API_KEY", "sk-invalid")
    client = AQL1(
        api_key=api_key,
        base_url=os.environ.get("AQL1_BASE_URL", "http://localhost:8000"),
        timeout=10.0,
        max_retries=3,  # 429/5xx/network failures are retried automatically
    )

    try:
        status = client.get_status("does-not-exist")

    except AuthenticationError as exc:
        # 401 — the key is missing, invalid, or revoked.
        print(f"Auth failed ({exc.code}): {exc.message}")

    except RateLimitError as exc:
        # 429 — back off using the server's own numbers.
        print(f"Rate limited. retry_after={exc.retry_after}s "
              f"limit={exc.limit} remaining={exc.remaining} reset={exc.reset}")

    except NotFoundError as exc:
        # 404 — the task id is unknown.
        print(f"Not found: {exc.message}")

    except ValidationError as exc:
        # 422 — the request body was rejected.
        print(f"Invalid request: {exc.message}")

    except TimeoutError as exc:
        # The request exceeded the configured timeout.
        print(f"Timed out: {exc.message}")

    except APIConnectionError as exc:
        # The request never reached the server (DNS, refused, reset...).
        print(f"Connection problem: {exc.message}")

    except APIError as exc:
        # Any other non-2xx response, with the status code and parsed body.
        print(f"API error {exc.status_code}: {exc.message} body={exc.body}")

    else:
        print(f"OK: {status.status}")

    finally:
        client.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
