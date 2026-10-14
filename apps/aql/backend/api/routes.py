"""REST endpoints for the AQL-1 operating layer."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import (
    APIKeyError,
    APIKeyStoreError,
    AuthError,
    get_api_key_store,
)
from core.engine import AgentEngine
from core.guardrails import (
    ApprovalNotFoundError,
    ApprovalStateError,
    ApprovalStore,
    GuardrailError,
    check_action_risk,
)
from core.observability import LogBuildError, build_logs
from core.orchestrator import MultiAgentOrchestrator
from core.router import ModelRouter
from memory.manager import MemoryManager
from memory.state import StateManager
from tools.registry import registry

logger = logging.getLogger(__name__)

router = APIRouter()

# One shared state + approval store, so a run paused by the engine is the same
# record the /agent/approve webhook later resumes.
_state = StateManager()
_approvals = ApprovalStore(state=_state)
_engine = AgentEngine(guardrails=_approvals)
_memory = MemoryManager()
_orchestrator = MultiAgentOrchestrator(guardrails=_approvals)


def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _identity(request: Request) -> dict:
    """Read the authenticated key identity the middleware attached.

    Returns an empty dict when auth is disabled, so endpoints never have to
    guard against a missing ``request.state`` attribute.
    """
    record = getattr(request.state, "api_key", None)
    if record is None:
        return {}
    return {
        "key_id": record.key_id,
        "name": record.name,
        "owner_id": record.owner_id,
        "scopes": list(record.scopes),
    }


# ── Schemas ─────────────────────────────────────────────────────────────────
class RunRequest(BaseModel):
    task: str = Field(..., min_length=1, description="The task for the agent.")
    provider: str | None = Field(None, description="'openai' or 'anthropic'.")
    action_type: str | None = Field(
        None,
        description="Action the agent will take (e.g. 'email.send'). "
        "High-risk actions pause for human approval.",
    )
    payload: dict = Field(default_factory=dict, description="Action payload.")
    user_id: str = "anonymous"
    session_id: str = "default"


class RiskCheckRequest(BaseModel):
    action_type: str = Field(..., min_length=1)
    payload: dict = Field(default_factory=dict)


class ApprovalDecisionRequest(BaseModel):
    approval_id: str = Field(..., min_length=1, description="The approval id.")
    decision: str = Field(
        "approve", description="'approve' or 'reject'."
    )
    approver: str | None = Field(None, description="Who approved/rejected.")
    note: str = Field("", description="Optional note from the approver.")


class OrchestrateRequest(BaseModel):
    task: str = Field(..., min_length=1, description="The goal for the agent team.")
    user_id: str = "anonymous"
    session_id: str = "default"
    max_iterations: int | None = Field(None, ge=1, le=10)


class MemoryWriteRequest(BaseModel):
    text: str = Field(..., min_length=1)
    metadata: dict = Field(default_factory=dict)
    user_id: str = "anonymous"
    session_id: str = "default"
    role: str = "user"


class MemoryQueryRequest(BaseModel):
    text: str = Field(..., min_length=1)
    top_k: int = Field(5, ge=1, le=50)


class MemoryRecallRequest(BaseModel):
    query: str = Field(..., min_length=1)
    top_k: int = Field(5, ge=1, le=50)
    user_id: str | None = None
    session_id: str | None = None
    role: str | None = None
    min_score: float | None = None


class AuditLogRequest(BaseModel):
    prompt: str = Field("", description="The user prompt that produced this run.")
    response: str = Field("", description="The assistant response.")
    user_id: str = "anonymous"
    session_id: str = "default"
    role: str = "assistant"
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0


# ── v1 (production REST API) schemas ─────────────────────────────────────────
class V1RunRequest(BaseModel):
    """Body for ``POST /v1/agent/run``."""

    task: str = Field(..., min_length=1, description="The task for the agent.")
    provider: str | None = Field(None, description="Preferred provider, if any.")
    action_type: str | None = Field(
        None,
        description="Action the agent will take (e.g. 'email.send'). "
        "High-risk actions pause for human approval.",
    )
    payload: dict = Field(default_factory=dict, description="Action payload.")
    user_id: str = "anonymous"
    session_id: str = "default"
    wait: bool = Field(
        False,
        description="True runs synchronously and returns the full result; "
        "False (default) returns the task id immediately.",
    )


class APIKeyCreateRequest(BaseModel):
    """Body for ``POST /v1/keys``."""

    name: str = Field(..., min_length=1, description="Label for the key.")
    owner_id: str = "anonymous"
    scopes: list[str] = Field(default_factory=list)
    rate_limit_requests: int | None = Field(None, ge=1, le=100000)
    rate_limit_window_seconds: int | None = Field(None, ge=1, le=86400)


# ── Health & meta ───────────────────────────────────────────────────────────
@router.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "service": "aql-1"}


@router.get("/tools", tags=["meta"])
def list_tools() -> dict:
    return {"tools": registry.schemas()}


@router.get("/v1/security/posture", tags=["meta"])
def security_posture() -> dict:
    """Live view of the tool gate, recent decisions and code-execution isolation."""
    return registry.posture()


# ── Observability ─────────────────────────────────────────────────────────────
@router.get("/api/logs", tags=["observability"])
def observability_logs(
    run_id: str | None = None,
    status: str | None = None,
    agent: str | None = None,
    limit: int = 500,
) -> dict:
    """Structured execution logs for the Observability dashboard.

    Returns three joined views over the persisted runs:

    * ``routing`` — what ModelRouter actually spent vs. the all-premium
      counterfactual, split by complexity tier (the cost-saved headline).
    * ``success`` — overall success rate plus a time-bucketed trend series.
    * ``traces``  — one flat row per agent call (agent, tool, status, latency,
      tokens, cost, model, complexity).

    Filterable by run id, status and agent, so the client can narrow without a
    second round trip.
    """
    try:
        runs = _state.list_runs_detailed(limit=500)
        return build_logs(
            runs,
            router=ModelRouter(use_llm_classifier=False),
            run_id=run_id,
            status=status,
            agent=agent,
            limit=limit,
        )
    except LogBuildError as exc:
        raise HTTPException(
            status_code=500, detail=f"Could not build execution logs: {exc}"
        ) from exc


@router.post("/route", tags=["meta"])
def preview_route(req: RunRequest) -> dict:
    """Preview the routing decision (complexity, model, cost, fallback chain)."""
    decision = ModelRouter().route(req.task, prefer=req.provider)
    return decision.to_dict()


# ── Agent runs ──────────────────────────────────────────────────────────────
@router.post("/agent/run", tags=["agent"])
def run_agent(req: RunRequest) -> dict:
    """Run the agent. High-risk actions pause for human approval."""
    run = _engine.run(
        req.task,
        prefer_provider=req.provider,
        action_type=req.action_type,
        payload=req.payload,
        user_id=req.user_id,
        session_id=req.session_id,
    )
    payload = run.to_dict()
    _state.save_run(run.run_id, payload)
    return payload


@router.get("/agent/runs", tags=["agent"])
def list_runs(limit: int = 50) -> dict:
    return {"runs": _state.list_runs(limit=limit)}


@router.get("/agent/runs/{run_id}", tags=["agent"])
def get_run(run_id: str) -> dict:
    payload = _state.get_run(run_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return payload


# ── Safety & human approval ──────────────────────────────────────────────────
@router.post("/agent/risk-check", tags=["safety"])
def risk_check(req: RiskCheckRequest) -> dict:
    """Classify an action's risk without running anything."""
    return check_action_risk(req.action_type, req.payload).to_dict()


@router.post("/agent/approve", tags=["safety"])
def approve_action(req: ApprovalDecisionRequest) -> dict:
    """Webhook: resume (or reject) a run paused for human approval.

    Looks up the paused run by approval id, records the decision, and — when
    approved — resumes execution and returns the resumed run's result.
    """
    try:
        approval = _approvals.get(req.approval_id)
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GuardrailError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        if approval.kind == "orchestrator":
            state = _orchestrator.resume(
                approval.run_id,
                req.decision,
                approver=req.approver,
                note=req.note,
            )
            payload = state.to_dict()
        else:
            run = _engine.resume(
                approval.run_id,
                req.decision,
                approver=req.approver,
                note=req.note,
            )
            payload = run.to_dict()
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GuardrailError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    _state.save_run(approval.run_id, payload)
    return {
        "approval_id": req.approval_id,
        "decision": req.decision,
        "status": payload.get("status"),
        "result": payload,
    }


@router.get("/agent/approvals", tags=["safety"])
def list_approvals(status: str | None = "pending", limit: int = 50) -> dict:
    """List pending approvals (newest first). Pass status=all for everything."""
    wanted = None if status in (None, "all", "") else status
    return {"approvals": [a.to_dict() for a in _approvals.list(wanted, limit)]}


@router.get("/agent/approvals/{approval_id}", tags=["safety"])
def get_approval(approval_id: str) -> dict:
    """Fetch one approval by id."""
    try:
        return _approvals.get(approval_id).to_dict()
    except ApprovalNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GuardrailError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ── Multi-agent orchestration ────────────────────────────────────────────────
@router.post("/orchestrate", tags=["orchestrator"])
def orchestrate(req: OrchestrateRequest) -> dict:
    """Run the planner → executor → reviewer loop and return the final state."""
    state = _orchestrator.run(
        req.task,
        user_id=req.user_id,
        session_id=req.session_id,
        max_iterations=req.max_iterations,
    )
    payload = state.to_dict()
    _state.save_run(state.run_id, payload)
    return payload


# ── Memory ──────────────────────────────────────────────────────────────────
@router.post("/memory", tags=["memory"])
def write_memory(req: MemoryWriteRequest) -> dict:
    """Store one memory: embed the text and upsert it with metadata."""
    return _memory.store(
        req.text,
        user_id=req.user_id,
        session_id=req.session_id,
        role=req.role,
        metadata=req.metadata,
    )


@router.post("/memory/query", tags=["memory"])
def query_memory(req: MemoryQueryRequest) -> dict:
    """Semantic search over stored memories (top-K by relevance)."""
    return {"results": _memory.fetch(req.text, top_k=req.top_k)}


@router.post("/memory/recall", tags=["memory"])
def recall_memory(req: MemoryRecallRequest) -> dict:
    """Fetch the top-K relevant past memories, optionally filtered by user/session/role."""
    results = _memory.fetch(
        req.query,
        top_k=req.top_k,
        user_id=req.user_id,
        session_id=req.session_id,
        role=req.role,
        min_score=req.min_score,
    )
    return {"query": req.query, "results": results}


@router.post("/memory/build-context", tags=["memory"])
def memory_context(req: MemoryRecallRequest) -> dict:
    """Return a prompt-ready context block built from relevant memories."""
    context = _memory.build_context(
        req.query,
        top_k=req.top_k,
        user_id=req.user_id,
        session_id=req.session_id,
        min_score=req.min_score,
    )
    return {"query": req.query, "context": context}


@router.post("/memory/logs", tags=["memory"])
def log_audit(req: AuditLogRequest) -> dict:
    """Append a session/run audit record (Supabase, in-memory fallback)."""
    return _memory.log(
        user_id=req.user_id,
        session_id=req.session_id,
        role=req.role,
        prompt=req.prompt,
        response=req.response,
        model=req.model,
        provider=req.provider,
        input_tokens=req.input_tokens,
        output_tokens=req.output_tokens,
        cost_usd=req.cost_usd,
        latency_ms=req.latency_ms,
    )


@router.get("/memory/logs", tags=["memory"])
def list_audit(
    user_id: str | None = None,
    session_id: str | None = None,
    limit: int = 50,
) -> dict:
    """List past audit rows, newest first, optionally filtered."""
    return {
        "logs": _memory.history(
            user_id=user_id, session_id=session_id, limit=limit
        )
    }


# ══════════════════════════════════════════════════════════════════════════════
# v1 — production REST API (API-key authenticated)
# ══════════════════════════════════════════════════════════════════════════════
# These endpoints are the stable, versioned surface for programmatic clients.
# Every route here sits behind ``APIKeyMiddleware`` (see ``core/auth.py``), so
# by the time a handler runs the caller's identity is already on
# ``request.state.api_key``.


def _run_agent_task(
    run_id: str,
    task: str,
    *,
    provider: str | None,
    action_type: str | None,
    payload: dict,
    user_id: str,
    session_id: str,
) -> None:
    """Execute one agent run and persist it (used as a background task).

    Runs the same guardrail-gated engine path as the synchronous route, so a
    high-risk action still pauses for approval instead of executing.
    """
    try:
        run = _engine.run(
            task,
            prefer_provider=provider,
            action_type=action_type,
            payload=payload,
            user_id=user_id,
            session_id=session_id,
            run_id=run_id,
        )
        _state.save_run(run_id, run.to_dict())
    except Exception as exc:  # noqa: BLE001 — a background failure must be recorded
        logger.warning("Background agent run %s failed (%s)", run_id, exc)
        _state.save_run(
            run_id,
            {
                "run_id": run_id,
                "task": task,
                "status": "failed",
                "error": str(exc),
                "answer": None,
                "steps": [],
                "created_at": _utcnow_iso(),
            },
        )


def _progress(payload: dict) -> tuple[int, int]:
    """Return ``(completed, total)`` steps for either run shape.

    Orchestrator runs carry a ``plan`` plus per-step ``results``; single-agent
    runs carry a flat ``steps`` list. Both are normalised here so the status
    endpoint has one code path.
    """
    plan = payload.get("plan") or []
    results = payload.get("results") or []
    steps = payload.get("steps") or []
    if plan or results:
        return len(results), len(plan) or len(results)
    return len(steps), len(steps)


def _usage(payload: dict) -> tuple[float, int]:
    """Return ``(cost_usd, total_tokens)`` for either run shape."""
    cost = payload.get("total_cost_usd")
    if cost is None:
        cost = (payload.get("route") or {}).get("estimated_cost_usd", 0.0)
    route = payload.get("route") or {}
    tokens = int(route.get("estimated_input_tokens", 0)) + int(
        route.get("estimated_output_tokens", 0)
    )
    return float(cost or 0.0), tokens


def _status_payload(run_id: str, payload: dict) -> dict:
    """Shape a stored run into the ``GET /v1/agent/status`` response."""
    completed, total = _progress(payload)
    cost, tokens = _usage(payload)
    status = payload.get("status", "unknown")
    return {
        "task_id": run_id,
        "status": status,
        "progress": {
            "steps_completed": completed,
            "steps_total": total,
            "percent": round((completed / total) * 100, 1) if total else 0.0,
        },
        "created_at": payload.get("created_at"),
        "started_at": payload.get("started_at"),
        "finished_at": payload.get("finished_at"),
        "duration_ms": payload.get("duration_ms", 0),
        "cost_usd": round(cost, 6),
        "tokens": tokens,
        "approval_id": payload.get("approval_id"),
        "error": payload.get("error"),
        # The full record is only meaningful once the run has settled.
        "result": payload if status not in ("running", "pending") else None,
    }


@router.post("/v1/agent/run", tags=["v1"])
def v1_run_agent(
    req: V1RunRequest, request: Request, background: BackgroundTasks
) -> dict:
    """Start an autonomous agent run.

    Async by default: the task id is returned immediately and the run proceeds
    in the background. Pass ``wait: true`` to run synchronously and receive the
    full result in the response.

    The run goes through the guardrail gate, so a high-risk action returns
    ``status: "pending_approval"`` with an ``approval_id`` instead of executing.
    """
    task_id = str(uuid.uuid4())
    identity = _identity(request)

    if req.wait:
        run = _engine.run(
            req.task,
            prefer_provider=req.provider,
            action_type=req.action_type,
            payload=req.payload,
            user_id=req.user_id,
            session_id=req.session_id,
            run_id=task_id,
        )
        payload = run.to_dict()
        _state.save_run(task_id, payload)
        return {
            "task_id": task_id,
            "status": payload["status"],
            "approval_id": payload.get("approval_id"),
            "api_key": identity,
            "result": payload,
        }

    # Async: record a placeholder so the status endpoint answers immediately,
    # then hand the real work to a background task.
    _state.save_run(
        task_id,
        {
            "run_id": task_id,
            "task": req.task,
            "status": "running",
            "answer": None,
            "steps": [],
            "created_at": _utcnow_iso(),
            "started_at": _utcnow_iso(),
        },
    )
    background.add_task(
        _run_agent_task,
        task_id,
        req.task,
        provider=req.provider,
        action_type=req.action_type,
        payload=req.payload,
        user_id=req.user_id,
        session_id=req.session_id,
    )
    return {
        "task_id": task_id,
        "status": "running",
        "approval_id": None,
        "api_key": identity,
        "status_url": f"/v1/agent/status/{task_id}",
    }


@router.get("/v1/agent/status/{task_id}", tags=["v1"])
def v1_agent_status(task_id: str) -> dict:
    """Return the current status of a run started via ``POST /v1/agent/run``.

    Includes progress, timestamps, cost/tokens so far, the pending-approval id
    when paused, and the final result once the run has finished. 404 when the
    task id is unknown.
    """
    payload = _state.get_run(task_id)
    if payload is None:
        raise HTTPException(status_code=404, detail=f"Unknown task id: {task_id}")
    return _status_payload(task_id, payload)


# ── API-key management ───────────────────────────────────────────────────────
@router.post("/v1/keys", tags=["v1"])
def v1_create_key(req: APIKeyCreateRequest) -> dict:
    """Mint a new API key.

    The **raw key is returned exactly once** in ``api_key`` — only its SHA-256
    hash is stored, so it can never be recovered afterwards. Store it now.
    """
    try:
        raw_key, record = get_api_key_store().create(
            req.name,
            owner_id=req.owner_id,
            scopes=req.scopes,
            rate_limit_requests=req.rate_limit_requests,
            rate_limit_window_seconds=req.rate_limit_window_seconds,
        )
    except APIKeyStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "api_key": raw_key,
        "key": record.to_dict(),
        "warning": "Store this key now — it cannot be retrieved again.",
    }


@router.get("/v1/keys", tags=["v1"])
def v1_list_keys() -> dict:
    """List API keys (metadata only — hashes and raw keys are never returned)."""
    try:
        keys = get_api_key_store().list()
    except APIKeyStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"keys": [k.to_dict() for k in keys]}


@router.delete("/v1/keys/{key_id}", tags=["v1"])
def v1_revoke_key(key_id: str) -> dict:
    """Revoke (deactivate) an API key by its ``key_id``."""
    try:
        record = get_api_key_store().revoke(key_id)
    except APIKeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AuthError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"revoked": True, "key": record.to_dict()}
