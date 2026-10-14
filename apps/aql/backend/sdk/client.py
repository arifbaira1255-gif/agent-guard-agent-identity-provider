"""Python client SDK for the AQL-1 API.

Usage:
    from sdk import AQL1Client

    client = AQL1Client("http://localhost:8000")
    run = client.run("Summarize today's AI news")
    print(run.answer)

    # Production REST API (API-key authenticated)
    client = AQL1Client("http://localhost:8000", api_key="aql1_…")
    task = client.run_task("Draft the weekly report")   # async by default
    print(client.task_status(task["task_id"]))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class AgentRunResult:
    run_id: str
    status: str
    answer: str | None
    duration_ms: int
    raw: dict[str, Any]


class AQL1Client:
    """Synchronous client for the AQL-1 backend."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 120.0,
        api_key: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        # The key is sent on every request as a Bearer token; the middleware
        # also accepts X-API-Key, but Bearer is the conventional choice.
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(
            base_url=self.base_url, timeout=timeout, headers=headers
        )

    # ── meta ────────────────────────────────────────────────────────────────
    def health(self) -> dict[str, Any]:
        return self._client.get("/health").json()

    def tools(self) -> list[dict[str, Any]]:
        return self._client.get("/tools").json()["tools"]

    def route(self, task: str, provider: str | None = None) -> dict[str, Any]:
        return self._client.post(
            "/route", json={"task": task, "provider": provider}
        ).json()

    # ── agent ───────────────────────────────────────────────────────────────
    def run(self, task: str, provider: str | None = None) -> AgentRunResult:
        data = self._client.post(
            "/agent/run", json={"task": task, "provider": provider}
        ).json()
        return AgentRunResult(
            run_id=data["run_id"],
            status=data["status"],
            answer=data.get("answer"),
            duration_ms=data.get("duration_ms", 0),
            raw=data,
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._client.get(f"/agent/runs/{run_id}").json()

    # ── safety & human approval ──────────────────────────────────────────────
    def check_risk(self, action_type: str, payload: dict | None = None) -> dict[str, Any]:
        """Classify an action's risk without running anything."""
        return self._client.post(
            "/agent/risk-check",
            json={"action_type": action_type, "payload": payload or {}},
        ).json()

    def approve(
        self,
        approval_id: str,
        decision: str = "approve",
        *,
        approver: str | None = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Approve or reject a paused run and resume it."""
        return self._client.post(
            "/agent/approve",
            json={
                "approval_id": approval_id,
                "decision": decision,
                "approver": approver,
                "note": note,
            },
        ).json()

    def approvals(self, status: str | None = "pending", limit: int = 50) -> list[dict[str, Any]]:
        """List approvals (newest first). Pass status='all' for everything."""
        return self._client.get(
            "/agent/approvals", params={"status": status, "limit": limit}
        ).json()["approvals"]

    def approval(self, approval_id: str) -> dict[str, Any]:
        """Fetch one approval by id."""
        return self._client.get(f"/agent/approvals/{approval_id}").json()

    # ── orchestrator ─────────────────────────────────────────────────────────
    def orchestrate(
        self,
        task: str,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        max_iterations: int | None = None,
    ) -> dict[str, Any]:
        """Run the multi-agent orchestrator (plan → execute → review)."""
        return self._client.post(
            "/orchestrate",
            json={
                "task": task,
                "user_id": user_id,
                "session_id": session_id,
                "max_iterations": max_iterations,
            },
        ).json()

    # ── memory ──────────────────────────────────────────────────────────────
    def remember(
        self,
        text: str,
        metadata: dict | None = None,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        role: str = "user",
    ) -> dict[str, Any]:
        """Store one memory (embeds the text + metadata)."""
        return self._client.post(
            "/memory",
            json={
                "text": text,
                "metadata": metadata or {},
                "user_id": user_id,
                "session_id": session_id,
                "role": role,
            },
        ).json()

    def recall(self, text: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Fetch the top-K relevant memories (scored)."""
        return self._client.post(
            "/memory/query", json={"text": text, "top_k": top_k}
        ).json()["results"]

    def fetch_memories(
        self,
        query: str,
        *,
        top_k: int = 5,
        user_id: str | None = None,
        session_id: str | None = None,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch memories with optional user/session/role filtering."""
        return self._client.post(
            "/memory/recall",
            json={
                "query": query,
                "top_k": top_k,
                "user_id": user_id,
                "session_id": session_id,
                "role": role,
            },
        ).json()["results"]

    def memory_context(self, query: str, **kwargs: Any) -> str:
        """Return a prompt-ready context block of relevant memories."""
        return self._client.post(
            "/memory/build-context", json={"query": query, **kwargs}
        ).json()["context"]

    def log_run(
        self,
        prompt: str,
        response: str,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        model: str = "",
        latency_ms: int = 0,
    ) -> dict[str, Any]:
        """Append a session/run audit record."""
        return self._client.post(
            "/memory/logs",
            json={
                "prompt": prompt,
                "response": response,
                "user_id": user_id,
                "session_id": session_id,
                "model": model,
                "latency_ms": latency_ms,
            },
        ).json()

    def history(self, **kwargs: Any) -> list[dict[str, Any]]:
        """List past audit rows (newest first)."""
        return self._client.get("/memory/logs", params=kwargs).json()["logs"]

    # ── Observability ────────────────────────────────────────────────────────
    def logs(
        self,
        *,
        run_id: str | None = None,
        status: str | None = None,
        agent: str | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Fetch structured execution logs for the observability dashboard.

        Returns the full payload: ``summary``, ``routing`` (cost saved by model
        routing), ``success`` (rate + trend series) and ``traces`` (one row per
        agent call).
        """
        params: dict[str, Any] = {"limit": limit}
        if run_id:
            params["run_id"] = run_id
        if status:
            params["status"] = status
        if agent:
            params["agent"] = agent
        return self._client.get("/api/logs", params=params).json()

    def traces(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Convenience: just the flat trace rows from :meth:`logs`."""
        return list(self.logs(**kwargs).get("traces", []))

    def savings(self) -> dict[str, Any]:
        """Convenience: just the model-routing cost-savings block."""
        return dict(self.logs().get("routing", {}))

    # ── v1 production REST API (API-key authenticated) ───────────────────────
    def run_task(
        self,
        task: str,
        *,
        provider: str | None = None,
        action_type: str | None = None,
        payload: dict | None = None,
        user_id: str = "anonymous",
        session_id: str = "default",
        wait: bool = False,
    ) -> dict[str, Any]:
        """Start a run via ``POST /v1/agent/run``.

        Async by default — returns ``{task_id, status, status_url}``. Pass
        ``wait=True`` to run synchronously and get the full result back.
        A high-risk action returns ``status='pending_approval'`` with an
        ``approval_id`` instead of executing.
        """
        return self._client.post(
            "/v1/agent/run",
            json={
                "task": task,
                "provider": provider,
                "action_type": action_type,
                "payload": payload or {},
                "user_id": user_id,
                "session_id": session_id,
                "wait": wait,
            },
        ).json()

    def task_status(self, task_id: str) -> dict[str, Any]:
        """Fetch a run's status via ``GET /v1/agent/status/{task_id}``.

        Returns status, progress, timestamps, cost/tokens, the pending-approval
        id when paused, and the final result once finished.
        """
        return self._client.get(f"/v1/agent/status/{task_id}").json()

    # ── API-key management ───────────────────────────────────────────────────
    def create_key(
        self,
        name: str,
        *,
        owner_id: str = "anonymous",
        scopes: list[str] | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_window_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Mint a new API key. The raw key is returned ONCE — store it now."""
        return self._client.post(
            "/v1/keys",
            json={
                "name": name,
                "owner_id": owner_id,
                "scopes": scopes or [],
                "rate_limit_requests": rate_limit_requests,
                "rate_limit_window_seconds": rate_limit_window_seconds,
            },
        ).json()

    def list_keys(self) -> list[dict[str, Any]]:
        """List API keys (metadata only — never the raw key or its hash)."""
        return self._client.get("/v1/keys").json()["keys"]

    def revoke_key(self, key_id: str) -> dict[str, Any]:
        """Revoke (deactivate) an API key by its ``key_id``."""
        return self._client.delete(f"/v1/keys/{key_id}").json()

    # ── billing ──────────────────────────────────────────────────────────────
    def plans(self) -> list[dict[str, Any]]:
        """List the Free / Pro / Team tiers with prices, limits and features."""
        return self._client.get("/v1/billing/plans").json()["plans"]

    def subscription(self, user_id: str | None = None) -> dict[str, Any]:
        """Fetch a user's tier, status, usage vs limit, renewal and features."""
        params = {"user_id": user_id} if user_id else None
        return self._client.get("/v1/billing/subscription", params=params).json()

    def payment_info(self) -> dict[str, Any]:
        """Payoneer email + bank-transfer details for manual payment."""
        return self._client.get("/v1/billing/payment-info").json()

    def close(self) -> None:
        self._client.close()
