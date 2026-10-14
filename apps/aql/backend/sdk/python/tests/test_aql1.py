"""Unit tests for the AQL-1 Python SDK.

Every test mocks the HTTP layer with :class:`MockTransport`, so nothing here
touches the network. Covered:

* a successful run (sync + async)
* async run followed by polling to completion
* the ``pending_approval`` path (allowed and disallowed)
* 401 → ``AuthenticationError``
* 429 → ``RateLimitError`` with retry + ``Retry-After``
* 404 → ``NotFoundError``
* timeout
* key management
* retry/backoff on 5xx and network errors
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping

import pytest

# Make the SDK importable without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aql1 import (  # noqa: E402
    AQL1,
    APIError,
    APIConnectionError,
    ApprovalRequiredError,
    ApprovalRejectedError,
    AsyncAQL1,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    TransportResponse,
    ValidationError,
)


# ══════════════════════════════════════════════════════════════════════════════
# Test doubles
# ══════════════════════════════════════════════════════════════════════════════
class MockTransport:
    """A scripted transport: pops one queued response per request.

    Each queued item is either a :class:`TransportResponse` or an exception
    instance to raise. Records every call for assertions.
    """

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses: list[Any] = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def queue(self, *responses: Any) -> "MockTransport":
        self.responses.extend(responses)
        return self

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "json": json_body,
                "timeout": timeout,
            }
        )
        if not self.responses:
            raise AssertionError(f"MockTransport ran out of responses for {method} {url}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class AsyncMockTransport:
    """Async twin of :class:`MockTransport`."""

    def __init__(self, responses: list[Any] | None = None) -> None:
        self.responses: list[Any] = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def queue(self, *responses: Any) -> "AsyncMockTransport":
        self.responses.extend(responses)
        return self

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "json": json_body,
                "timeout": timeout,
            }
        )
        if not self.responses:
            raise AssertionError(f"AsyncMockTransport ran out of responses for {method} {url}")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def resp(status: int, body: Any = None, headers: Mapping[str, str] | None = None) -> TransportResponse:
    """Build a :class:`TransportResponse` with a JSON body."""
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    return TransportResponse(
        status_code=status,
        headers=dict(headers or {}),
        body=payload,
    )


def make_client(transport: MockTransport, **kwargs: Any) -> AQL1:
    """A sync client wired to a mock transport, with retries disabled by default."""
    kwargs.setdefault("max_retries", 0)
    kwargs.setdefault("backoff_factor", 0.0)
    return AQL1(api_key="sk-test", base_url="http://api.test", transport=transport, **kwargs)


def make_async_client(transport: AsyncMockTransport, **kwargs: Any) -> AsyncAQL1:
    kwargs.setdefault("max_retries", 0)
    kwargs.setdefault("backoff_factor", 0.0)
    return AsyncAQL1(
        api_key="sk-test", base_url="http://api.test", transport=transport, **kwargs
    )


# ══════════════════════════════════════════════════════════════════════════════
# Constructor / config
# ══════════════════════════════════════════════════════════════════════════════
def test_constructor_requires_api_key() -> None:
    with pytest.raises(ValueError):
        AQL1(api_key="")


def test_constructor_defaults() -> None:
    client = AQL1(api_key="sk-test")
    assert client.base_url == "http://localhost:8000"
    assert client.timeout == 30.0
    assert client.max_retries == 2


def test_base_url_trailing_slash_is_normalised() -> None:
    client = AQL1(api_key="sk-test", base_url="http://api.test/")
    assert client.base_url == "http://api.test"


def test_repr_hides_the_key() -> None:
    client = AQL1(api_key="sk-super-secret")
    assert "sk-super-secret" not in repr(client)
    assert "***" in repr(client)


# ══════════════════════════════════════════════════════════════════════════════
# Successful run
# ══════════════════════════════════════════════════════════════════════════════
def test_run_agent_async_returns_task_handle() -> None:
    transport = MockTransport(
        [resp(200, {"task_id": "t-1", "status": "running", "status_url": "/v1/agent/status/t-1"})]
    )
    client = make_client(transport)

    result = client.run_agent(prompt="Do the thing")

    assert result.task_id == "t-1"
    assert result.status == "running"
    assert result.is_terminal is False
    call = transport.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "http://api.test/v1/agent/run"
    assert call["headers"]["Authorization"] == "Bearer sk-test"
    assert call["json"]["task"] == "Do the thing"
    assert call["json"]["wait"] is False


def test_run_agent_sync_returns_full_result() -> None:
    transport = MockTransport(
        [
            resp(
                200,
                {
                    "task_id": "t-2",
                    "status": "completed",
                    "result": {"answer": "42", "steps": [{"tool": "web_search"}]},
                },
            )
        ]
    )
    client = make_client(transport)

    result = client.run_agent(prompt="Answer", wait=True)

    assert result.status == "completed"
    assert result.is_terminal is True
    assert result.result is not None
    assert result.result["answer"] == "42"
    assert transport.calls[0]["json"]["wait"] is True


def test_run_agent_forwards_optional_fields() -> None:
    transport = MockTransport([resp(200, {"task_id": "t-3", "status": "running"})])
    client = make_client(transport)

    client.run_agent(
        prompt="Pay the invoice",
        action_type="payment.transfer",
        payload={"amount": 100},
        user_id="u-9",
        session_id="s-9",
        provider="unorouter",
    )

    body = transport.calls[0]["json"]
    assert body["action_type"] == "payment.transfer"
    assert body["payload"] == {"amount": 100}
    assert body["user_id"] == "u-9"
    assert body["session_id"] == "s-9"
    assert body["provider"] == "unorouter"


# ══════════════════════════════════════════════════════════════════════════════
# Polling to completion
# ══════════════════════════════════════════════════════════════════════════════
def test_wait_for_completion_polls_until_terminal() -> None:
    transport = MockTransport(
        [
            resp(200, {"task_id": "t-4", "status": "running", "progress": {"percent": 25.0}}),
            resp(200, {"task_id": "t-4", "status": "running", "progress": {"percent": 75.0}}),
            resp(
                200,
                {
                    "task_id": "t-4",
                    "status": "completed",
                    "progress": {"steps_completed": 2, "steps_total": 2, "percent": 100.0},
                    "cost_usd": 0.0042,
                    "tokens": 1234,
                    "result": {"answer": "done"},
                },
            ),
        ]
    )
    client = make_client(transport)
    seen: list[str] = []

    status = client.wait_for_completion(
        "t-4", poll_interval=0.0, timeout=5.0, on_progress=lambda s: seen.append(s.status)
    )

    assert status.status == "completed"
    assert status.is_success is True
    assert status.progress.percent == 100.0
    assert status.cost_usd == 0.0042
    assert status.tokens == 1234
    assert seen == ["running", "running", "completed"]
    assert len(transport.calls) == 3


def test_get_status_parses_every_field() -> None:
    transport = MockTransport(
        [
            resp(
                200,
                {
                    "task_id": "t-5",
                    "status": "completed",
                    "progress": {"steps_completed": 3, "steps_total": 3, "percent": 100.0},
                    "created_at": "2026-10-01T00:00:00Z",
                    "started_at": "2026-10-01T00:00:01Z",
                    "finished_at": "2026-10-01T00:00:09Z",
                    "duration_ms": 8000,
                    "cost_usd": 0.01,
                    "tokens": 500,
                    "approval_id": None,
                    "error": None,
                    "result": {"answer": "ok"},
                },
            )
        ]
    )
    client = make_client(transport)

    status = client.get_status("t-5")

    assert status.task_id == "t-5"
    assert status.duration_ms == 8000
    assert status.progress.steps_completed == 3
    assert status.created_at == "2026-10-01T00:00:00Z"
    assert transport.calls[0]["url"] == "http://api.test/v1/agent/status/t-5"


def test_wait_for_completion_times_out() -> None:
    transport = MockTransport(
        [resp(200, {"task_id": "t-6", "status": "running"}) for _ in range(50)]
    )
    client = make_client(transport)

    with pytest.raises(TimeoutError) as excinfo:
        client.wait_for_completion("t-6", poll_interval=0.0, timeout=0.0)

    assert "did not finish" in str(excinfo.value)


# ══════════════════════════════════════════════════════════════════════════════
# Pending approval
# ══════════════════════════════════════════════════════════════════════════════
def test_pending_approval_is_surfaced_when_allowed() -> None:
    transport = MockTransport(
        [resp(200, {"task_id": "t-7", "status": "pending_approval", "approval_id": "ap-1"})]
    )
    client = make_client(transport)

    result = client.run_agent(prompt="Email the client", allow_human_approval=True)

    assert result.status == "pending_approval"
    assert result.is_pending_approval is True
    assert result.approval_id == "ap-1"
    # pending_approval is terminal for polling purposes.
    assert result.is_terminal is True


def test_pending_approval_raises_when_disallowed() -> None:
    transport = MockTransport(
        [resp(200, {"task_id": "t-8", "status": "pending_approval", "approval_id": "ap-2"})]
    )
    client = make_client(transport)

    with pytest.raises(ApprovalRequiredError) as excinfo:
        client.run_agent(prompt="Delete the table", allow_human_approval=False)

    assert excinfo.value.approval_id == "ap-2"
    assert "human approval" in str(excinfo.value)


def test_wait_for_completion_stops_on_pending_approval() -> None:
    transport = MockTransport(
        [resp(200, {"task_id": "t-9", "status": "pending_approval", "approval_id": "ap-3"})]
    )
    client = make_client(transport)

    status = client.wait_for_completion("t-9", poll_interval=0.0, timeout=5.0)

    assert status.is_pending_approval is True
    assert status.approval_id == "ap-3"
    assert len(transport.calls) == 1  # did not spin


def test_approve_posts_the_decision() -> None:
    transport = MockTransport([resp(200, {"status": "approved", "result": {"answer": "sent"}})])
    client = make_client(transport)

    result = client.approve("ap-4", decision="approve", approver="arif", note="looks fine")

    assert result["status"] == "approved"
    body = transport.calls[0]["json"]
    assert body == {
        "approval_id": "ap-4",
        "decision": "approve",
        "note": "looks fine",
        "approver": "arif",
    }


def test_approve_rejects_bad_decision() -> None:
    client = make_client(MockTransport())
    with pytest.raises(ValueError):
        client.approve("ap-5", decision="maybe")


def test_resume_after_approval_raises_on_rejection() -> None:
    transport = MockTransport([resp(200, {"approval_id": "ap-6", "status": "rejected"})])
    client = make_client(transport)

    with pytest.raises(ApprovalRejectedError) as excinfo:
        client.resume_after_approval("ap-6", poll_interval=0.0, timeout=5.0)

    assert excinfo.value.approval_id == "ap-6"


def test_resume_after_approval_returns_record_when_approved() -> None:
    transport = MockTransport(
        [resp(200, {"approval_id": "ap-7", "status": "approved", "result": {"answer": "ok"}})]
    )
    client = make_client(transport)

    record = client.resume_after_approval("ap-7", poll_interval=0.0, timeout=5.0)

    assert record["status"] == "approved"


# ══════════════════════════════════════════════════════════════════════════════
# Error mapping
# ══════════════════════════════════════════════════════════════════════════════
def test_401_raises_authentication_error() -> None:
    transport = MockTransport(
        [resp(401, {"error": "unauthorized", "code": "invalid_api_key", "detail": "bad key"})]
    )
    client = make_client(transport)

    with pytest.raises(AuthenticationError) as excinfo:
        client.get_status("t-1")

    assert excinfo.value.status_code == 401
    assert excinfo.value.code == "invalid_api_key"
    assert "bad key" in str(excinfo.value)


def test_404_raises_not_found_error() -> None:
    transport = MockTransport([resp(404, {"detail": "Unknown task id: nope"})])
    client = make_client(transport)

    with pytest.raises(NotFoundError) as excinfo:
        client.get_status("nope")

    assert excinfo.value.status_code == 404
    assert "Unknown task id" in str(excinfo.value)


def test_422_raises_validation_error() -> None:
    transport = MockTransport([resp(422, {"detail": [{"loc": ["body", "task"], "msg": "required"}]})])
    client = make_client(transport)

    with pytest.raises(ValidationError):
        client.run_agent(prompt="")


def test_500_raises_api_error() -> None:
    transport = MockTransport([resp(500, {"detail": "boom"})])
    client = make_client(transport)

    with pytest.raises(APIError) as excinfo:
        client.get_status("t-1")

    assert excinfo.value.status_code == 500
    assert "boom" in str(excinfo.value)


def test_non_json_error_body_still_raises() -> None:
    transport = MockTransport(
        [TransportResponse(status_code=502, headers={}, body=b"<html>bad gateway</html>")]
    )
    client = make_client(transport)

    with pytest.raises(APIError) as excinfo:
        client.get_status("t-1")

    assert "bad gateway" in str(excinfo.value)


# ══════════════════════════════════════════════════════════════════════════════
# Rate limiting & retries
# ══════════════════════════════════════════════════════════════════════════════
def test_429_raises_rate_limit_error_with_headers() -> None:
    transport = MockTransport(
        [
            resp(
                429,
                {"error": "rate_limited", "code": "rate_limit_exceeded", "detail": "slow down"},
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": "60",
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "1730000000",
                },
            )
        ]
    )
    client = make_client(transport)

    with pytest.raises(RateLimitError) as excinfo:
        client.get_status("t-1")

    err = excinfo.value
    assert err.status_code == 429
    assert err.retry_after == 60.0
    assert err.limit == 60
    assert err.remaining == 0
    assert err.reset == 1730000000


def test_429_is_retried_then_succeeds() -> None:
    transport = MockTransport(
        [
            resp(429, {"detail": "slow down"}, headers={"Retry-After": "0"}),
            resp(200, {"task_id": "t-1", "status": "completed"}),
        ]
    )
    client = make_client(transport, max_retries=1)

    status = client.get_status("t-1")

    assert status.status == "completed"
    assert len(transport.calls) == 2


def test_429_retry_after_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("aql1.time.sleep", lambda s: slept.append(s))

    transport = MockTransport(
        [
            resp(429, {"detail": "slow"}, headers={"Retry-After": "7"}),
            resp(200, {"task_id": "t-1", "status": "completed"}),
        ]
    )
    client = make_client(transport, max_retries=1)

    client.get_status("t-1")

    assert slept == [7.0]


def test_5xx_is_retried_then_succeeds() -> None:
    transport = MockTransport(
        [
            resp(503, {"detail": "unavailable"}),
            resp(200, {"task_id": "t-1", "status": "completed"}),
        ]
    )
    client = make_client(transport, max_retries=1)

    status = client.get_status("t-1")

    assert status.status == "completed"
    assert len(transport.calls) == 2


def test_retries_are_exhausted_then_raise() -> None:
    transport = MockTransport([resp(503, {"detail": "down"}) for _ in range(5)])
    client = make_client(transport, max_retries=2)

    with pytest.raises(APIError):
        client.get_status("t-1")

    assert len(transport.calls) == 3  # 1 initial + 2 retries


def test_network_error_is_retried_then_raises_connection_error() -> None:
    transport = MockTransport([OSError("connection refused") for _ in range(5)])
    client = make_client(transport, max_retries=1)

    with pytest.raises(APIConnectionError):
        client.get_status("t-1")

    assert len(transport.calls) == 2


def test_network_error_recovers_on_retry() -> None:
    transport = MockTransport(
        [OSError("flaky"), resp(200, {"task_id": "t-1", "status": "completed"})]
    )
    client = make_client(transport, max_retries=1)

    status = client.get_status("t-1")

    assert status.status == "completed"


def test_401_is_not_retried() -> None:
    transport = MockTransport([resp(401, {"detail": "nope"}) for _ in range(3)])
    client = make_client(transport, max_retries=2)

    with pytest.raises(AuthenticationError):
        client.get_status("t-1")

    assert len(transport.calls) == 1  # auth failures are terminal


# ══════════════════════════════════════════════════════════════════════════════
# Key management
# ══════════════════════════════════════════════════════════════════════════════
def test_create_key_returns_raw_key_once() -> None:
    transport = MockTransport(
        [
            resp(
                200,
                {
                    "api_key": "sk-new-raw",
                    "key": {
                        "key_id": "k-1",
                        "name": "ci",
                        "owner_id": "u-1",
                        "scopes": ["agent:run"],
                        "active": True,
                        "rate_limit_requests": 60,
                        "rate_limit_window_seconds": 60,
                    },
                    "warning": "Store this key now.",
                },
            )
        ]
    )
    client = make_client(transport)

    created = client.create_key("ci", owner_id="u-1", scopes=["agent:run"])

    assert created.api_key == "sk-new-raw"
    assert created.key.key_id == "k-1"
    assert created.key.scopes == ["agent:run"]
    assert "Store this key" in created.warning
    assert transport.calls[0]["json"]["name"] == "ci"


def test_list_keys_returns_metadata() -> None:
    transport = MockTransport(
        [
            resp(
                200,
                {
                    "keys": [
                        {"key_id": "k-1", "name": "ci", "active": True},
                        {"key_id": "k-2", "name": "old", "active": False},
                    ]
                },
            )
        ]
    )
    client = make_client(transport)

    keys = client.list_keys()

    assert [k.key_id for k in keys] == ["k-1", "k-2"]
    assert keys[1].active is False


def test_revoke_key() -> None:
    transport = MockTransport(
        [resp(200, {"revoked": True, "key": {"key_id": "k-1", "name": "ci", "active": False}})]
    )
    client = make_client(transport)

    key = client.revoke_key("k-1")

    assert key.active is False
    assert transport.calls[0]["method"] == "DELETE"
    assert transport.calls[0]["url"] == "http://api.test/v1/keys/k-1"


# ══════════════════════════════════════════════════════════════════════════════
# Async client
# ══════════════════════════════════════════════════════════════════════════════
async def test_async_run_agent() -> None:
    transport = AsyncMockTransport(
        [resp(200, {"task_id": "a-1", "status": "running", "status_url": "/v1/agent/status/a-1"})]
    )
    client = make_async_client(transport)

    result = await client.run_agent(prompt="Async task")

    assert result.task_id == "a-1"
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer sk-test"


async def test_async_run_and_poll_to_completion() -> None:
    transport = AsyncMockTransport(
        [
            resp(200, {"task_id": "a-2", "status": "running"}),
            resp(200, {"task_id": "a-2", "status": "running", "progress": {"percent": 50.0}}),
            resp(200, {"task_id": "a-2", "status": "completed", "result": {"answer": "done"}}),
        ]
    )
    client = make_async_client(transport)

    started = await client.run_agent(prompt="Async task")
    status = await client.wait_for_completion(started.task_id, poll_interval=0.0, timeout=5.0)

    assert status.status == "completed"
    assert status.result == {"answer": "done"}


async def test_async_stream_progress_yields_updates() -> None:
    transport = AsyncMockTransport(
        [
            resp(200, {"task_id": "a-3", "status": "running", "progress": {"percent": 10.0}}),
            resp(200, {"task_id": "a-3", "status": "running", "progress": {"percent": 60.0}}),
            resp(200, {"task_id": "a-3", "status": "completed", "progress": {"percent": 100.0}}),
        ]
    )
    client = make_async_client(transport)

    percents: list[float] = []
    async for status in client.stream_progress("a-3", poll_interval=0.0, timeout=5.0):
        percents.append(status.progress.percent)

    assert percents == [10.0, 60.0, 100.0]


async def test_async_pending_approval_raises_when_disallowed() -> None:
    transport = AsyncMockTransport(
        [resp(200, {"task_id": "a-4", "status": "pending_approval", "approval_id": "ap-a"})]
    )
    client = make_async_client(transport)

    with pytest.raises(ApprovalRequiredError):
        await client.run_agent(prompt="Risky", allow_human_approval=False)


async def test_async_401_raises_authentication_error() -> None:
    transport = AsyncMockTransport([resp(401, {"detail": "bad key"})])
    client = make_async_client(transport)

    with pytest.raises(AuthenticationError):
        await client.get_status("a-1")


async def test_async_429_retries_then_succeeds() -> None:
    transport = AsyncMockTransport(
        [
            resp(429, {"detail": "slow"}, headers={"Retry-After": "0"}),
            resp(200, {"task_id": "a-5", "status": "completed"}),
        ]
    )
    client = make_async_client(transport, max_retries=1)

    status = await client.get_status("a-5")

    assert status.status == "completed"
    assert len(transport.calls) == 2


async def test_async_404_raises_not_found() -> None:
    transport = AsyncMockTransport([resp(404, {"detail": "Unknown task id"})])
    client = make_async_client(transport)

    with pytest.raises(NotFoundError):
        await client.get_status("missing")


async def test_async_timeout() -> None:
    transport = AsyncMockTransport(
        [resp(200, {"task_id": "a-6", "status": "running"}) for _ in range(50)]
    )
    client = make_async_client(transport)

    with pytest.raises(TimeoutError):
        await client.wait_for_completion("a-6", poll_interval=0.0, timeout=0.0)


async def test_async_key_management() -> None:
    transport = AsyncMockTransport(
        [
            resp(200, {"api_key": "sk-raw", "key": {"key_id": "k-9", "name": "async"}}),
            resp(200, {"keys": [{"key_id": "k-9", "name": "async"}]}),
            resp(200, {"revoked": True, "key": {"key_id": "k-9", "name": "async", "active": False}}),
        ]
    )
    client = make_async_client(transport)

    created = await client.create_key("async")
    keys = await client.list_keys()
    revoked = await client.revoke_key("k-9")

    assert created.api_key == "sk-raw"
    assert len(keys) == 1
    assert revoked.active is False


async def test_async_context_manager_closes() -> None:
    transport = AsyncMockTransport()
    client = make_async_client(transport)
    async with client as c:
        assert c is client
