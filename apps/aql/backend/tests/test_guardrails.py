"""Tests for the AQL-1 safety layer (guardrails + human approval).

Covers: high-risk detection for every dangerous category (email send, DB
delete, financial action, shell exec, file delete, credential access, bulk
export), low-risk pass-through, the pause-and-persist path, the approve webhook
resuming execution, the reject path, and the no-keys in-memory fallback.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.engine import AgentEngine
from core.guardrails import (
    APPROVAL_APPROVED,
    APPROVAL_PENDING,
    APPROVAL_REJECTED,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    ApprovalNotFoundError,
    ApprovalStateError,
    ApprovalStore,
    PendingApproval,
    RiskAssessment,
    check_action_risk,
)
from core.orchestrator import (
    MultiAgentOrchestrator,
    OrchestrationState,
    PlannerAgent,
    SubTask,
)
from main import app
from memory.state import StateManager

client = TestClient(app)


# ── helpers ──────────────────────────────────────────────────────────────────
def _fresh_store() -> ApprovalStore:
    """An isolated in-memory approval store (no Supabase, no shared state)."""
    return ApprovalStore(state=StateManager())


class _HighRiskPlanner(PlannerAgent):
    """Plans a single sub-task whose *tool* is a high-risk action type."""

    def __init__(self, tool: str = "email.send", description: str = "send the email") -> None:
        super().__init__()
        self._tool = tool
        self._description = description

    def plan(self, prompt: str, context: str = "") -> list[SubTask]:  # type: ignore[override]
        return [SubTask(id="t1", description=self._description, tool=self._tool)]


# ══════════════════════════════════════════════════════════════════════════════
# 1. High-risk detection — one test per dangerous category
# ══════════════════════════════════════════════════════════════════════════════
def test_email_send_is_high_risk():
    a = check_action_risk(
        "email.send", {"to": "customer@example.com", "subject": "Invoice"}
    )
    assert a.is_high_risk
    assert a.risk_level == RISK_HIGH
    assert a.requires_approval
    assert "external_communication.send" in a.matched_rules
    assert a.reasons


def test_message_send_is_high_risk():
    a = check_action_risk("message.send", {"recipient": "user-42", "text": "hi"})
    assert a.is_high_risk
    assert "external_communication" in a.categories


def test_db_delete_is_high_risk():
    a = check_action_risk("db.delete", {"table": "users", "where": "id=1"})
    assert a.is_high_risk
    assert "data_deletion.records" in a.matched_rules


def test_sql_delete_statement_is_high_risk():
    a = check_action_risk("sql.delete", {"query": "DELETE FROM orders WHERE id = 5"})
    assert a.is_high_risk
    assert "data_deletion" in a.categories


def test_financial_payment_is_high_risk():
    a = check_action_risk("payment.transfer", {"amount": 250, "currency": "USD"})
    assert a.is_high_risk
    assert "financial.money_movement" in a.matched_rules


def test_financial_refund_is_high_risk():
    a = check_action_risk("refund.create", {"charge_id": "ch_123", "amount": 10})
    assert a.is_high_risk
    assert "financial" in a.categories


def test_shell_exec_is_high_risk():
    a = check_action_risk("shell.exec", {"command": "rm -rf /tmp/data"})
    assert a.is_high_risk
    assert "shell.execution" in a.matched_rules


def test_file_delete_is_high_risk():
    a = check_action_risk("file.delete", {"path": "/data/report.csv"})
    assert a.is_high_risk
    assert "file_deletion" in a.categories


def test_credential_access_is_high_risk():
    a = check_action_risk("secret.read", {"name": "OPENAI_API_KEY"})
    assert a.is_high_risk
    assert "credential_access" in a.categories


def test_bulk_export_is_high_risk():
    a = check_action_risk("data.export", {"scope": "all users", "format": "csv"})
    assert a.is_high_risk
    assert "bulk_export" in a.categories


# ══════════════════════════════════════════════════════════════════════════════
# 2. Low / medium pass-through
# ══════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize(
    "action_type",
    ["web_search", "echo", "now", "python_exec", "file_generator", "db.read"],
)
def test_read_only_actions_are_low_risk(action_type):
    a = check_action_risk(action_type, {"query": "anything"})
    assert a.risk_level == RISK_LOW
    assert a.is_high_risk is False
    assert a.requires_approval is False


def test_unknown_action_defaults_to_medium():
    a = check_action_risk("some.unknown.capability", {})
    assert a.risk_level == RISK_MEDIUM
    assert a.is_high_risk is False
    assert a.requires_approval is False


def test_medium_write_is_not_high_risk():
    a = check_action_risk("db.write", {"table": "notes"})
    assert a.risk_level == RISK_MEDIUM
    assert a.requires_approval is False


def test_action_type_normalisation():
    # "Send_Email" and "send.email" must classify identically.
    assert check_action_risk("Send_Email", {"to": "x@y.com"}).is_high_risk
    assert check_action_risk("send.email", {"to": "x@y.com"}).is_high_risk


def test_assessment_schema_and_serialisation():
    a = check_action_risk("db.delete", {"table": "users"})
    assert isinstance(a, RiskAssessment)
    payload = a.to_dict()
    for key in (
        "action_type", "risk_level", "is_high_risk", "reasons",
        "matched_rules", "requires_approval", "categories", "checked_at",
    ):
        assert key in payload
    assert payload["action_type"] == "db.delete"
    assert isinstance(payload["reasons"], list)


def test_risk_check_is_deterministic():
    first = check_action_risk("payment.create", {"amount": 5}).to_dict()
    second = check_action_risk("payment.create", {"amount": 5}).to_dict()
    first.pop("checked_at")
    second.pop("checked_at")
    assert first == second


# ══════════════════════════════════════════════════════════════════════════════
# 3. Approval store — pause / persist / resume primitives
# ══════════════════════════════════════════════════════════════════════════════
def test_store_falls_back_to_memory_without_keys():
    store = _fresh_store()
    assert store.is_local is True  # no Supabase configured


def test_pause_persists_and_returns_pending():
    store = _fresh_store()
    approval = store.pause(
        run_id="run-1",
        action_type="email.send",
        payload={"to": "a@b.com"},
        user_id="u1",
        session_id="s1",
    )
    assert isinstance(approval, PendingApproval)
    assert approval.status == APPROVAL_PENDING
    assert approval.is_pending
    assert approval.risk["is_high_risk"] is True

    # It is retrievable by id and by run id.
    assert store.get(approval.approval_id).run_id == "run-1"
    assert store.find_by_run("run-1").approval_id == approval.approval_id
    assert any(a.approval_id == approval.approval_id for a in store.list())


def test_get_unknown_approval_raises_typed_error():
    store = _fresh_store()
    with pytest.raises(ApprovalNotFoundError):
        store.get("does-not-exist")


def test_decide_twice_raises_state_error():
    store = _fresh_store()
    approval = store.pause(run_id="run-2", action_type="db.delete", payload={})
    store.decide(approval.approval_id, "approve", approver="arif")
    with pytest.raises(ApprovalStateError):
        store.decide(approval.approval_id, "reject")


def test_list_filters_by_status():
    store = _fresh_store()
    a1 = store.pause(run_id="r-a", action_type="email.send", payload={})
    store.pause(run_id="r-b", action_type="db.delete", payload={})
    store.decide(a1.approval_id, "approve")

    pending = store.list(status=APPROVAL_PENDING)
    approved = store.list(status=APPROVAL_APPROVED)
    assert len(pending) == 1 and pending[0].run_id == "r-b"
    assert len(approved) == 1 and approved[0].run_id == "r-a"
    assert len(store.list(status=None)) == 2


# ══════════════════════════════════════════════════════════════════════════════
# 4. Engine integration — pause, approve, reject
# ══════════════════════════════════════════════════════════════════════════════
def test_engine_pauses_high_risk_action():
    engine = AgentEngine(guardrails=_fresh_store())
    run = engine.run(
        "Send the weekly newsletter to all customers",
        action_type="email.send",
        payload={"to": "all-customers@example.com"},
    )
    assert run.status == "pending_approval"
    assert run.approval_id
    assert "approval" in (run.answer or "").lower()
    # Nothing was executed while paused.
    assert run.steps == []


def test_engine_runs_low_risk_action_normally():
    engine = AgentEngine(guardrails=_fresh_store())
    run = engine.run("Summarize the news", action_type="web_search")
    assert run.status == "completed"
    assert run.approval_id is None


def test_engine_resume_approve_executes():
    store = _fresh_store()
    engine = AgentEngine(guardrails=store)
    run = engine.run(
        "Send the invoice email",
        action_type="email.send",
        payload={"to": "client@example.com"},
    )
    assert run.status == "pending_approval"

    resumed = engine.resume(run.run_id, "approve", approver="arif", note="ok")
    assert resumed.status == "completed"
    assert resumed.answer
    assert store.get(run.approval_id).status == APPROVAL_APPROVED


def test_engine_resume_reject_marks_rejected():
    store = _fresh_store()
    engine = AgentEngine(guardrails=store)
    run = engine.run(
        "Delete all user records",
        action_type="db.delete",
        payload={"table": "users"},
    )
    assert run.status == "pending_approval"

    rejected = engine.resume(run.run_id, "reject", approver="arif", note="too risky")
    assert rejected.status == "rejected"
    assert "rejected" in (rejected.answer or "").lower()
    assert store.get(run.approval_id).status == APPROVAL_REJECTED


def test_engine_resume_unknown_run_raises():
    engine = AgentEngine(guardrails=_fresh_store())
    with pytest.raises(ApprovalNotFoundError):
        engine.resume("no-such-run", "approve")


# ══════════════════════════════════════════════════════════════════════════════
# 5. Orchestrator integration — pause on a high-risk sub-task
# ══════════════════════════════════════════════════════════════════════════════
def test_orchestrator_pauses_on_high_risk_subtask():
    store = _fresh_store()
    orch = MultiAgentOrchestrator(
        planner=_HighRiskPlanner("email.send", "send the email to the customer"),
        guardrails=store,
        use_memory=False,
    )
    state = orch.run("Email the customer about the invoice")
    assert state.status == "pending_approval"
    assert state.approval_id
    assert state.results == []  # nothing executed while paused


def test_orchestrator_resume_approve_completes():
    store = _fresh_store()
    orch = MultiAgentOrchestrator(
        planner=_HighRiskPlanner("email.send", "send the email to the customer"),
        guardrails=store,
        use_memory=False,
    )
    state = orch.run("Email the customer about the invoice")
    assert state.status == "pending_approval"

    resumed = orch.resume(state.run_id, "approve", approver="arif")
    assert resumed.status == "completed"
    assert resumed.all_approved


def test_orchestrator_resume_reject():
    store = _fresh_store()
    orch = MultiAgentOrchestrator(
        planner=_HighRiskPlanner("db.delete", "delete all user records"),
        guardrails=store,
        use_memory=False,
    )
    state = orch.run("Clean up the database")
    assert state.status == "pending_approval"

    rejected = orch.resume(state.run_id, "reject", approver="arif", note="no")
    assert rejected.status == "rejected"


def test_orchestrator_low_risk_run_unaffected():
    orch = MultiAgentOrchestrator(use_memory=False)
    state = orch.run("First search the web, then write a summary file")
    assert state.status == "completed"
    assert state.approval_id is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. API surface — risk-check, pause, list, approve, reject
# ══════════════════════════════════════════════════════════════════════════════
def test_api_risk_check_endpoint():
    r = client.post(
        "/agent/risk-check",
        json={"action_type": "payment.transfer", "payload": {"amount": 100}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["is_high_risk"] is True
    assert body["requires_approval"] is True


def test_api_run_pauses_then_approve_resumes():
    # 1) a high-risk run pauses
    r = client.post(
        "/agent/run",
        json={
            "task": "Send the newsletter to all customers",
            "action_type": "email.send",
            "payload": {"to": "all@example.com"},
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "pending_approval"
    approval_id = body["approval_id"]
    assert approval_id

    # 2) it shows up in the pending list
    r = client.get("/agent/approvals")
    assert r.status_code == 200
    ids = [a["approval_id"] for a in r.json()["approvals"]]
    assert approval_id in ids

    # 3) it can be fetched by id
    r = client.get(f"/agent/approvals/{approval_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "pending"

    # 4) the approve webhook resumes it
    r = client.post(
        "/agent/approve",
        json={
            "approval_id": approval_id,
            "decision": "approve",
            "approver": "arif",
            "note": "looks fine",
        },
    )
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "completed"
    assert out["result"]["status"] == "completed"


def test_api_reject_path():
    r = client.post(
        "/agent/run",
        json={
            "task": "Delete all user records",
            "action_type": "db.delete",
            "payload": {"table": "users"},
        },
    )
    approval_id = r.json()["approval_id"]

    r = client.post(
        "/agent/approve",
        json={"approval_id": approval_id, "decision": "reject", "approver": "arif"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "rejected"


def test_api_approve_unknown_id_returns_404():
    r = client.post(
        "/agent/approve", json={"approval_id": "nope", "decision": "approve"}
    )
    assert r.status_code == 404


def test_api_approve_twice_returns_409():
    r = client.post(
        "/agent/run",
        json={
            "task": "Wire the funds",
            "action_type": "payment.transfer",
            "payload": {"amount": 500},
        },
    )
    approval_id = r.json()["approval_id"]
    first = client.post(
        "/agent/approve", json={"approval_id": approval_id, "decision": "approve"}
    )
    assert first.status_code == 200
    second = client.post(
        "/agent/approve", json={"approval_id": approval_id, "decision": "approve"}
    )
    assert second.status_code == 409


def test_api_low_risk_run_is_unaffected():
    r = client.post("/agent/run", json={"task": "Say hello"})
    assert r.status_code == 200
    assert r.json()["status"] == "completed"
