"""AQL-1 Python SDK — a lightweight client for the AQL-1 REST API.

Two clients are provided:

* :class:`AQL1` — synchronous, blocking calls.
* :class:`AsyncAQL1` — ``async``/``await`` calls built on an async transport.

Both wrap the same versioned REST surface::

    POST   /v1/agent/run              start an autonomous run
    GET    /v1/agent/status/{id}      poll a run's status
    POST   /v1/keys                   mint an API key (raw key returned once)
    GET    /v1/keys                   list key metadata
    DELETE /v1/keys/{key_id}          revoke a key

Quickstart::

    from aql1 import AQL1

    client = AQL1(api_key="sk-...")
    response = client.run_agent(prompt="Summarise today's AI news",
                                allow_human_approval=True)
    print(response.task_id, response.status)

The default transport uses only the standard library (``urllib``), so the SDK
has **no hard dependency**. Install ``httpx`` to use the faster pooled
transport, or pass your own object implementing the transport protocol.

Design notes
------------
* Every non-2xx response becomes a typed exception — errors are never
  swallowed silently.
* ``429`` and ``5xx`` responses (and network failures) are retried with
  exponential backoff plus jitter, honouring ``Retry-After`` when present.
* All request/response shapes are typed with dataclasses; no ``Any`` leaks
  into the public surface.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol, runtime_checkable

__all__ = [
    # clients
    "AQL1",
    "AsyncAQL1",
    # transports
    "BaseTransport",
    "AsyncBaseTransport",
    "UrllibTransport",
    "HttpxTransport",
    "AsyncHttpxTransport",
    "AsyncUrllibTransport",
    "TransportResponse",
    # models
    "RunResponse",
    "TaskStatus",
    "Progress",
    "APIKey",
    "APIKeyCreated",
    # errors
    "AQL1Error",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    "ValidationError",
    "APIError",
    "APIConnectionError",
    "TimeoutError",
    "AQL1TimeoutError",
    "ApprovalRequiredError",
    "ApprovalRejectedError",
    # helpers
    "TERMINAL_STATUSES",
    "DEFAULT_BASE_URL",
]

logger = logging.getLogger("aql1")

DEFAULT_BASE_URL = "http://localhost:8000"
USER_AGENT = "aql1-python/1.0.0"

#: Statuses after which a run will not change again on its own.
#: ``pending_approval`` is included because the run is paused waiting on a
#: human — polling it further would simply spin.
TERMINAL_STATUSES: frozenset[str] = frozenset(
    {"completed", "failed", "rejected", "cancelled", "pending_approval"}
)

#: HTTP statuses worth retrying.
RETRYABLE_STATUSES: frozenset[int] = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


# ══════════════════════════════════════════════════════════════════════════════
# Errors
# ══════════════════════════════════════════════════════════════════════════════
class AQL1Error(Exception):
    """Base class for every error raised by this SDK.

    Attributes
    ----------
    message:
        Human-readable description.
    status_code:
        HTTP status, when the error came from a response.
    body:
        Parsed response body, when available.
    code:
        Machine-readable error code from the API (e.g. ``invalid_api_key``).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: Any = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.body = body
        self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.status_code is not None:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(AQL1Error):
    """401 — the API key is missing, invalid, or revoked."""


class RateLimitError(AQL1Error):
    """429 — the key's rate limit was exceeded.

    Exposes the standard rate-limit headers so callers can back off precisely.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        limit: int | None = None,
        remaining: int | None = None,
        reset: int | None = None,
        status_code: int | None = 429,
        body: Any = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, body=body, code=code)
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining
        self.reset = reset


class NotFoundError(AQL1Error):
    """404 — the requested resource does not exist."""


class ValidationError(AQL1Error):
    """422 — the request body failed validation."""


class APIError(AQL1Error):
    """Any other non-2xx response."""


class APIConnectionError(AQL1Error):
    """The request never produced a response (DNS, refused, reset, TLS...)."""


class TimeoutError(AQL1Error):  # noqa: A001 - the name is part of the public API
    """The request exceeded the configured timeout."""


#: Alias so callers can avoid shadowing the builtin if they prefer.
AQL1TimeoutError = TimeoutError


class ApprovalRequiredError(AQL1Error):
    """A run paused for human approval but ``allow_human_approval`` was False.

    Carries the ``approval_id`` so the caller can still approve it out of band.
    """

    def __init__(self, message: str, *, approval_id: str | None = None, body: Any = None) -> None:
        super().__init__(message, body=body, code="approval_required")
        self.approval_id = approval_id


class ApprovalRejectedError(AQL1Error):
    """A paused run was rejected by a human approver."""

    def __init__(self, message: str, *, approval_id: str | None = None, body: Any = None) -> None:
        super().__init__(message, body=body, code="approval_rejected")
        self.approval_id = approval_id


# ══════════════════════════════════════════════════════════════════════════════
# Response models
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Progress:
    """Step progress for a run."""

    steps_completed: int = 0
    steps_total: int = 0
    percent: float = 0.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "Progress":
        data = data or {}
        return cls(
            steps_completed=int(data.get("steps_completed", 0) or 0),
            steps_total=int(data.get("steps_total", 0) or 0),
            percent=float(data.get("percent", 0.0) or 0.0),
        )


@dataclass(frozen=True)
class RunResponse:
    """The immediate answer to ``POST /v1/agent/run``.

    For an async run only ``task_id``/``status`` are populated; poll with
    :meth:`AQL1.get_status` or :meth:`AQL1.wait_for_completion`.
    """

    task_id: str
    status: str
    approval_id: str | None = None
    result: dict[str, Any] | None = None
    status_url: str | None = None
    api_key: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_pending_approval(self) -> bool:
        return self.status == "pending_approval"

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RunResponse":
        return cls(
            task_id=str(data.get("task_id", "")),
            status=str(data.get("status", "unknown")),
            approval_id=data.get("approval_id"),
            result=data.get("result"),
            status_url=data.get("status_url"),
            api_key=data.get("api_key"),
            raw=dict(data),
        )


@dataclass(frozen=True)
class TaskStatus:
    """The answer to ``GET /v1/agent/status/{task_id}``."""

    task_id: str
    status: str
    progress: Progress = field(default_factory=Progress)
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    duration_ms: int = 0
    cost_usd: float = 0.0
    tokens: int = 0
    approval_id: str | None = None
    error: str | None = None
    result: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def is_pending_approval(self) -> bool:
        return self.status == "pending_approval"

    @property
    def is_success(self) -> bool:
        return self.status == "completed"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TaskStatus":
        return cls(
            task_id=str(data.get("task_id", "")),
            status=str(data.get("status", "unknown")),
            progress=Progress.from_dict(data.get("progress")),
            created_at=data.get("created_at"),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            duration_ms=int(data.get("duration_ms", 0) or 0),
            cost_usd=float(data.get("cost_usd", 0.0) or 0.0),
            tokens=int(data.get("tokens", 0) or 0),
            approval_id=data.get("approval_id"),
            error=data.get("error"),
            result=data.get("result"),
            raw=dict(data),
        )


@dataclass(frozen=True)
class APIKey:
    """Metadata for an API key. The raw key and its hash are never included."""

    key_id: str
    name: str
    owner_id: str = "anonymous"
    scopes: list[str] = field(default_factory=list)
    active: bool = True
    created_at: str | None = None
    last_used_at: str | None = None
    rate_limit_requests: int = 0
    rate_limit_window_seconds: int = 0
    prefix: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "APIKey":
        return cls(
            key_id=str(data.get("key_id", "")),
            name=str(data.get("name", "")),
            owner_id=str(data.get("owner_id", "anonymous")),
            scopes=list(data.get("scopes") or []),
            active=bool(data.get("active", True)),
            created_at=data.get("created_at"),
            last_used_at=data.get("last_used_at"),
            rate_limit_requests=int(data.get("rate_limit_requests", 0) or 0),
            rate_limit_window_seconds=int(data.get("rate_limit_window_seconds", 0) or 0),
            prefix=data.get("prefix"),
        )


@dataclass(frozen=True)
class APIKeyCreated:
    """The one-time result of minting a key — ``api_key`` is shown only here."""

    api_key: str
    key: APIKey
    warning: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "APIKeyCreated":
        return cls(
            api_key=str(data.get("api_key", "")),
            key=APIKey.from_dict(data.get("key") or {}),
            warning=str(data.get("warning", "")),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Transports
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class TransportResponse:
    """A raw HTTP response, transport-agnostic."""

    status_code: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        """Parse the body as JSON, returning ``None`` for an empty body."""
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@runtime_checkable
class BaseTransport(Protocol):
    """The synchronous transport contract.

    Implement this to plug in a custom HTTP client::

        class MyTransport:
            def request(self, method, url, *, headers, json_body, timeout):
                ...
    """

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse: ...


@runtime_checkable
class AsyncBaseTransport(Protocol):
    """The asynchronous transport contract."""

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse: ...


class UrllibTransport:
    """Default transport — standard library only, zero dependencies."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        request = urllib.request.Request(url, data=data, headers=dict(headers), method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return TransportResponse(
                    status_code=int(response.status),
                    headers={k: v for k, v in response.headers.items()},
                    body=response.read(),
                )
        except urllib.error.HTTPError as exc:
            # An HTTP error is still a valid response — let the retry/error
            # layer decide what to do with it.
            return TransportResponse(
                status_code=int(exc.code),
                headers={k: v for k, v in (exc.headers or {}).items()},
                body=exc.read() or b"",
            )
        except urllib.error.URLError as exc:
            raise APIConnectionError(f"Request to {url} failed: {exc.reason}") from exc
        except OSError as exc:  # socket timeouts, connection resets, ...
            raise APIConnectionError(f"Request to {url} failed: {exc}") from exc


class HttpxTransport:
    """Optional transport backed by ``httpx`` (connection pooling, HTTP/2)."""

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            try:
                import httpx  # noqa: PLC0415 - optional dependency
            except ImportError as exc:  # pragma: no cover - depends on env
                raise ImportError(
                    "HttpxTransport requires httpx. Install it with `pip install httpx`."
                ) from exc
            client = httpx.Client()
        self._client = client

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        try:
            response = self._client.request(
                method, url, headers=dict(headers), json=json_body, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001 - normalise to a typed error
            raise APIConnectionError(f"Request to {url} failed: {exc}") from exc
        return TransportResponse(
            status_code=int(response.status_code),
            headers={k: v for k, v in response.headers.items()},
            body=response.content,
        )

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


class AsyncUrllibTransport:
    """Async transport that runs the stdlib transport in a worker thread.

    Keeps the SDK dependency-free while still offering a real ``async`` API.
    """

    def __init__(self) -> None:
        self._inner = UrllibTransport()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        return await asyncio.to_thread(
            self._inner.request,
            method,
            url,
            headers=headers,
            json_body=json_body,
            timeout=timeout,
        )


class AsyncHttpxTransport:
    """Optional async transport backed by ``httpx.AsyncClient``."""

    def __init__(self, client: Any | None = None) -> None:
        if client is None:
            try:
                import httpx  # noqa: PLC0415 - optional dependency
            except ImportError as exc:  # pragma: no cover - depends on env
                raise ImportError(
                    "AsyncHttpxTransport requires httpx. Install it with `pip install httpx`."
                ) from exc
            client = httpx.AsyncClient()
        self._client = client

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        json_body: Any | None,
        timeout: float,
    ) -> TransportResponse:
        try:
            response = await self._client.request(
                method, url, headers=dict(headers), json=json_body, timeout=timeout
            )
        except Exception as exc:  # noqa: BLE001 - normalise to a typed error
            raise APIConnectionError(f"Request to {url} failed: {exc}") from exc
        return TransportResponse(
            status_code=int(response.status_code),
            headers={k: v for k, v in response.headers.items()},
            body=response.content,
        )

    async def aclose(self) -> None:
        close = getattr(self._client, "aclose", None)
        if callable(close):
            await close()


# ══════════════════════════════════════════════════════════════════════════════
# Shared helpers
# ══════════════════════════════════════════════════════════════════════════════
def _parse_retry_after(headers: Mapping[str, str]) -> float | None:
    """Parse ``Retry-After`` (seconds or an HTTP date) into seconds."""
    raw = None
    for key, value in headers.items():
        if key.lower() == "retry-after":
            raw = value
            break
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        pass
    # HTTP-date form, e.g. "Wed, 21 Oct 2026 07:28:00 GMT".
    try:
        from email.utils import parsedate_to_datetime  # noqa: PLC0415

        target = parsedate_to_datetime(raw)
        return max(0.0, target.timestamp() - time.time())
    except Exception:  # noqa: BLE001 - a malformed header is not fatal
        return None


def _header_int(headers: Mapping[str, str], name: str) -> int | None:
    """Read an integer header case-insensitively."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


def _backoff_delay(attempt: int, factor: float, cap: float) -> float:
    """Exponential backoff with full jitter, capped."""
    return min(cap, factor * (2**attempt)) * (0.5 + random.random() / 2)


def _error_from_response(response: TransportResponse) -> AQL1Error:
    """Map a non-2xx response onto the right typed exception."""
    body = response.json()
    detail: str
    code: str | None = None
    if isinstance(body, Mapping):
        detail = str(body.get("detail") or body.get("error") or body.get("message") or "")
        code = body.get("code") if isinstance(body.get("code"), str) else None
    else:
        detail = response.text()[:500]
    if not detail:
        detail = f"HTTP {response.status_code}"

    status = response.status_code
    if status == 401:
        return AuthenticationError(detail, status_code=status, body=body, code=code)
    if status == 404:
        return NotFoundError(detail, status_code=status, body=body, code=code)
    if status == 422:
        return ValidationError(detail, status_code=status, body=body, code=code)
    if status == 429:
        return RateLimitError(
            detail,
            retry_after=_parse_retry_after(response.headers),
            limit=_header_int(response.headers, "X-RateLimit-Limit"),
            remaining=_header_int(response.headers, "X-RateLimit-Remaining"),
            reset=_header_int(response.headers, "X-RateLimit-Reset"),
            status_code=status,
            body=body,
            code=code,
        )
    return APIError(detail, status_code=status, body=body, code=code)


def _build_run_body(
    prompt: str,
    *,
    wait: bool,
    action_type: str | None,
    payload: Mapping[str, Any] | None,
    user_id: str,
    session_id: str,
    provider: str | None,
) -> dict[str, Any]:
    """Assemble the ``POST /v1/agent/run`` request body."""
    body: dict[str, Any] = {
        "task": prompt,
        "wait": bool(wait),
        "user_id": user_id,
        "session_id": session_id,
        "payload": dict(payload or {}),
    }
    if action_type is not None:
        body["action_type"] = action_type
    if provider is not None:
        body["provider"] = provider
    return body


def _check_approval_policy(
    status: str, approval_id: str | None, allow_human_approval: bool
) -> None:
    """Raise when a run paused for approval but the caller disallowed it."""
    if status == "pending_approval" and not allow_human_approval:
        raise ApprovalRequiredError(
            "The action was classified as high-risk and requires human approval, "
            "but allow_human_approval=False. Approve it via approve(approval_id) "
            "or re-run with allow_human_approval=True.",
            approval_id=approval_id,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Synchronous client
# ══════════════════════════════════════════════════════════════════════════════
class AQL1:
    """Synchronous AQL-1 API client.

    Parameters
    ----------
    api_key:
        Required. Sent as ``Authorization: Bearer <key>``.
    base_url:
        API root, default ``http://localhost:8000``.
    timeout:
        Per-request timeout in seconds (default 30).
    max_retries:
        Retries for 429/5xx/network failures (default 2 → 3 attempts total).
    transport:
        Custom transport implementing :class:`BaseTransport`. Defaults to
        :class:`UrllibTransport` (stdlib only).
    backoff_factor / max_backoff:
        Tuning for the exponential backoff.
    default_headers:
        Extra headers merged into every request.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        transport: BaseTransport | None = None,
        backoff_factor: float = 0.5,
        max_backoff: float = 30.0,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = float(backoff_factor)
        self.max_backoff = float(max_backoff)
        self._transport: BaseTransport = transport or UrllibTransport()
        self._default_headers = dict(default_headers or {})

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"AQL1(base_url={self.base_url!r}, api_key='***')"

    # ── internals ────────────────────────────────────────────────────────────
    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        headers.update(self._default_headers)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Perform a request with retries, returning the parsed JSON body."""
        url = f"{self.base_url}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url = f"{url}?{urllib.parse.urlencode(clean)}"

        attempt = 0
        while True:
            try:
                response = self._transport.request(
                    method,
                    url,
                    headers=self._headers(),
                    json_body=json_body,
                    timeout=self.timeout,
                )
            except AQL1Error:
                raise
            except Exception as exc:  # noqa: BLE001 - normalise transport failures
                if attempt < self.max_retries:
                    delay = _backoff_delay(attempt, self.backoff_factor, self.max_backoff)
                    logger.warning(
                        "AQL-1 request %s %s failed (%s); retrying in %.2fs",
                        method,
                        path,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise APIConnectionError(f"Request to {url} failed: {exc}") from exc

            if response.status_code >= 400:
                if response.status_code in RETRYABLE_STATUSES and attempt < self.max_retries:
                    retry_after = _parse_retry_after(response.headers)
                    delay = (
                        retry_after
                        if retry_after is not None
                        else _backoff_delay(attempt, self.backoff_factor, self.max_backoff)
                    )
                    logger.warning(
                        "AQL-1 request %s %s returned %s; retrying in %.2fs",
                        method,
                        path,
                        response.status_code,
                        delay,
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue
                raise _error_from_response(response)

            return response.json()

    # ── agent runs ───────────────────────────────────────────────────────────
    def run_agent(
        self,
        prompt: str,
        *,
        allow_human_approval: bool = True,
        wait: bool = False,
        poll_interval: float = 1.0,
        timeout: float | None = None,
        on_progress: Callable[[TaskStatus], None] | None = None,
        action_type: str | None = None,
        payload: Mapping[str, Any] | None = None,
        user_id: str = "anonymous",
        session_id: str = "default",
        provider: str | None = None,
    ) -> RunResponse:
        """Start an autonomous agent run.

        By default the call is **asynchronous**: it returns a
        :class:`RunResponse` carrying the ``task_id`` immediately. Pass
        ``wait=True`` to block until the run settles (server-side sync), or
        call :meth:`wait_for_completion` afterwards to poll client-side.

        When the action is high-risk the run pauses and the response carries
        ``status="pending_approval"`` plus an ``approval_id``. If
        ``allow_human_approval`` is False, :class:`ApprovalRequiredError` is
        raised instead.
        """
        body = _build_run_body(
            prompt,
            wait=wait,
            action_type=action_type,
            payload=payload,
            user_id=user_id,
            session_id=session_id,
            provider=provider,
        )
        data = self._request("POST", "/v1/agent/run", json_body=body)
        response = RunResponse.from_dict(data or {})
        _check_approval_policy(response.status, response.approval_id, allow_human_approval)

        if wait or response.is_terminal:
            return response

        # Async handle: optionally block until it settles.
        if poll_interval is not None and timeout is not None:
            status = self.wait_for_completion(
                response.task_id,
                poll_interval=poll_interval,
                timeout=timeout,
                on_progress=on_progress,
            )
            return RunResponse(
                task_id=status.task_id,
                status=status.status,
                approval_id=status.approval_id,
                result=status.result,
                status_url=response.status_url,
                api_key=response.api_key,
                raw=status.raw,
            )
        return response

    def get_status(self, task_id: str) -> TaskStatus:
        """Fetch the current status of a run. Raises :class:`NotFoundError`."""
        data = self._request("GET", f"/v1/agent/status/{urllib.parse.quote(task_id)}")
        return TaskStatus.from_dict(data or {})

    def wait_for_completion(
        self,
        task_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
        on_progress: Callable[[TaskStatus], None] | None = None,
    ) -> TaskStatus:
        """Poll until the run reaches a terminal status.

        ``pending_approval`` counts as terminal — the run is paused on a human,
        so polling further would spin forever. Raises :class:`TimeoutError`
        when ``timeout`` elapses first.
        """
        deadline = time.monotonic() + float(timeout)
        last: TaskStatus | None = None
        while True:
            last = self.get_status(task_id)
            if on_progress is not None:
                on_progress(last)
            if last.is_terminal:
                return last
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Run {task_id} did not finish within {timeout}s "
                    f"(last status: {last.status})",
                    body=last.raw,
                )
            time.sleep(max(0.0, poll_interval))

    def wait_for_approval(
        self,
        approval_id: str,
        *,
        poll_interval: float = 2.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Poll ``GET /agent/approvals/{id}`` until a human decides.

        Returns the approval record once its status is no longer ``pending``.
        """
        deadline = time.monotonic() + float(timeout)
        while True:
            record = self._request(
                "GET", f"/agent/approvals/{urllib.parse.quote(approval_id)}"
            )
            if isinstance(record, Mapping) and record.get("status") != "pending":
                return dict(record)
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Approval {approval_id} was not decided within {timeout}s"
                )
            time.sleep(max(0.0, poll_interval))

    def approve(
        self,
        approval_id: str,
        *,
        decision: str = "approve",
        approver: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Approve or reject a paused run, resuming it when approved."""
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        body: dict[str, Any] = {"approval_id": approval_id, "decision": decision, "note": note}
        if approver is not None:
            body["approver"] = approver
        return dict(self._request("POST", "/agent/approve", json_body=body) or {})

    def resume_after_approval(
        self,
        approval_id: str,
        *,
        approver: str | None = None,
        note: str = "",
        poll_interval: float = 2.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Wait for a human decision, then return the resumed run's result.

        Raises :class:`ApprovalRejectedError` when the decision was a rejection.
        """
        record = self.wait_for_approval(
            approval_id, poll_interval=poll_interval, timeout=timeout
        )
        if record.get("status") == "rejected":
            raise ApprovalRejectedError(
                f"Approval {approval_id} was rejected", approval_id=approval_id, body=record
            )
        return record

    # ── key management ───────────────────────────────────────────────────────
    def create_key(
        self,
        name: str,
        *,
        owner_id: str = "anonymous",
        scopes: Iterable[str] | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_window_seconds: int | None = None,
    ) -> APIKeyCreated:
        """Mint a new API key. The raw key is returned **once**."""
        body: dict[str, Any] = {
            "name": name,
            "owner_id": owner_id,
            "scopes": list(scopes or []),
        }
        if rate_limit_requests is not None:
            body["rate_limit_requests"] = rate_limit_requests
        if rate_limit_window_seconds is not None:
            body["rate_limit_window_seconds"] = rate_limit_window_seconds
        data = self._request("POST", "/v1/keys", json_body=body)
        return APIKeyCreated.from_dict(data or {})

    def list_keys(self) -> list[APIKey]:
        """List API key metadata (never the raw key or its hash)."""
        data = self._request("GET", "/v1/keys") or {}
        return [APIKey.from_dict(item) for item in (data.get("keys") or [])]

    def revoke_key(self, key_id: str) -> APIKey:
        """Revoke (deactivate) a key by its ``key_id``."""
        data = self._request("DELETE", f"/v1/keys/{urllib.parse.quote(key_id)}") or {}
        return APIKey.from_dict(data.get("key") or {})

    # ── lifecycle ────────────────────────────────────────────────────────────
    def close(self) -> None:
        """Close the underlying transport, if it holds resources."""
        close = getattr(self._transport, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "AQL1":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


# ══════════════════════════════════════════════════════════════════════════════
# Asynchronous client
# ══════════════════════════════════════════════════════════════════════════════
class AsyncAQL1:
    """Asynchronous AQL-1 API client — mirrors :class:`AQL1` with ``await``.

    Defaults to :class:`AsyncUrllibTransport` (stdlib, thread-backed) so it
    works with no extra dependencies; pass :class:`AsyncHttpxTransport` for a
    native async HTTP stack.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        transport: AsyncBaseTransport | None = None,
        backoff_factor: float = 0.5,
        max_backoff: float = 30.0,
        default_headers: Mapping[str, str] | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self.backoff_factor = float(backoff_factor)
        self.max_backoff = float(max_backoff)
        self._transport: AsyncBaseTransport = transport or AsyncUrllibTransport()
        self._default_headers = dict(default_headers or {})

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"AsyncAQL1(base_url={self.base_url!r}, api_key='***')"

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        headers.update(self._default_headers)
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url = f"{url}?{urllib.parse.urlencode(clean)}"

        attempt = 0
        while True:
            try:
                response = await self._transport.request(
                    method,
                    url,
                    headers=self._headers(),
                    json_body=json_body,
                    timeout=self.timeout,
                )
            except AQL1Error:
                raise
            except Exception as exc:  # noqa: BLE001 - normalise transport failures
                if attempt < self.max_retries:
                    delay = _backoff_delay(attempt, self.backoff_factor, self.max_backoff)
                    logger.warning(
                        "AQL-1 request %s %s failed (%s); retrying in %.2fs",
                        method,
                        path,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise APIConnectionError(f"Request to {url} failed: {exc}") from exc

            if response.status_code >= 400:
                if response.status_code in RETRYABLE_STATUSES and attempt < self.max_retries:
                    retry_after = _parse_retry_after(response.headers)
                    delay = (
                        retry_after
                        if retry_after is not None
                        else _backoff_delay(attempt, self.backoff_factor, self.max_backoff)
                    )
                    logger.warning(
                        "AQL-1 request %s %s returned %s; retrying in %.2fs",
                        method,
                        path,
                        response.status_code,
                        delay,
                    )
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise _error_from_response(response)

            return response.json()

    async def run_agent(
        self,
        prompt: str,
        *,
        allow_human_approval: bool = True,
        wait: bool = False,
        action_type: str | None = None,
        payload: Mapping[str, Any] | None = None,
        user_id: str = "anonymous",
        session_id: str = "default",
        provider: str | None = None,
    ) -> RunResponse:
        """Start a run. Async by default; ``wait=True`` blocks server-side."""
        body = _build_run_body(
            prompt,
            wait=wait,
            action_type=action_type,
            payload=payload,
            user_id=user_id,
            session_id=session_id,
            provider=provider,
        )
        data = await self._request("POST", "/v1/agent/run", json_body=body)
        response = RunResponse.from_dict(data or {})
        _check_approval_policy(response.status, response.approval_id, allow_human_approval)
        return response

    async def get_status(self, task_id: str) -> TaskStatus:
        """Fetch a run's status."""
        data = await self._request("GET", f"/v1/agent/status/{urllib.parse.quote(task_id)}")
        return TaskStatus.from_dict(data or {})

    async def wait_for_completion(
        self,
        task_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
        on_progress: Callable[[TaskStatus], None] | None = None,
    ) -> TaskStatus:
        """Poll until terminal, awaiting between attempts."""
        deadline = time.monotonic() + float(timeout)
        last: TaskStatus | None = None
        while True:
            last = await self.get_status(task_id)
            if on_progress is not None:
                on_progress(last)
            if last.is_terminal:
                return last
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Run {task_id} did not finish within {timeout}s "
                    f"(last status: {last.status})",
                    body=last.raw,
                )
            await asyncio.sleep(max(0.0, poll_interval))

    async def stream_progress(
        self,
        task_id: str,
        *,
        poll_interval: float = 1.0,
        timeout: float = 300.0,
    ):
        """Async-iterate status updates until the run reaches a terminal state.

        Usage::

            async for status in client.stream_progress(task_id):
                print(status.status, status.progress.percent)
        """
        deadline = time.monotonic() + float(timeout)
        while True:
            status = await self.get_status(task_id)
            yield status
            if status.is_terminal:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Run {task_id} did not finish within {timeout}s "
                    f"(last status: {status.status})",
                    body=status.raw,
                )
            await asyncio.sleep(max(0.0, poll_interval))

    async def wait_for_approval(
        self,
        approval_id: str,
        *,
        poll_interval: float = 2.0,
        timeout: float = 600.0,
    ) -> dict[str, Any]:
        """Await a human decision on a paused run."""
        deadline = time.monotonic() + float(timeout)
        while True:
            record = await self._request(
                "GET", f"/agent/approvals/{urllib.parse.quote(approval_id)}"
            )
            if isinstance(record, Mapping) and record.get("status") != "pending":
                return dict(record)
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Approval {approval_id} was not decided within {timeout}s"
                )
            await asyncio.sleep(max(0.0, poll_interval))

    async def approve(
        self,
        approval_id: str,
        *,
        decision: str = "approve",
        approver: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Approve or reject a paused run."""
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        body: dict[str, Any] = {"approval_id": approval_id, "decision": decision, "note": note}
        if approver is not None:
            body["approver"] = approver
        return dict(await self._request("POST", "/agent/approve", json_body=body) or {})

    async def create_key(
        self,
        name: str,
        *,
        owner_id: str = "anonymous",
        scopes: Iterable[str] | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_window_seconds: int | None = None,
    ) -> APIKeyCreated:
        """Mint a new API key (raw key returned once)."""
        body: dict[str, Any] = {
            "name": name,
            "owner_id": owner_id,
            "scopes": list(scopes or []),
        }
        if rate_limit_requests is not None:
            body["rate_limit_requests"] = rate_limit_requests
        if rate_limit_window_seconds is not None:
            body["rate_limit_window_seconds"] = rate_limit_window_seconds
        data = await self._request("POST", "/v1/keys", json_body=body)
        return APIKeyCreated.from_dict(data or {})

    async def list_keys(self) -> list[APIKey]:
        """List API key metadata."""
        data = await self._request("GET", "/v1/keys") or {}
        return [APIKey.from_dict(item) for item in (data.get("keys") or [])]

    async def revoke_key(self, key_id: str) -> APIKey:
        """Revoke a key by its ``key_id``."""
        data = await self._request("DELETE", f"/v1/keys/{urllib.parse.quote(key_id)}") or {}
        return APIKey.from_dict(data.get("key") or {})

    async def aclose(self) -> None:
        """Close the underlying async transport, if it holds resources."""
        close = getattr(self._transport, "aclose", None)
        if callable(close):
            await close()

    async def __aenter__(self) -> "AsyncAQL1":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()
