"""Tests for the long-term MemoryManager: store / fetch / log / fallback."""

import zlib

import pytest
from fastapi.testclient import TestClient

from main import app
from memory.manager import (
    MemoryAuditError,
    MemoryFetchError,
    MemoryManager,
    MemoryStoreError,
)
from memory.state import StateManager
from memory.vector_store import VectorStore

client = TestClient(app)


# ── fixtures & helpers ────────────────────────────────────────────────────────
def _bow_embed(text: str, dim: int = 64) -> list[float]:
    """Deterministic bag-of-words embedding so relevance is predictable."""
    vec = [0.0] * dim
    for word in (text or "").lower().split():
        vec[zlib.crc32(word.encode()) % dim] += 1.0
    norm = sum(v * v for v in vec) ** 0.5 or 1.0
    return [v / norm for v in vec]


@pytest.fixture
def manager() -> MemoryManager:
    """A manager wired to local (no-key) stores with a deterministic embedder."""
    return MemoryManager(
        vector_store=VectorStore(embedder=_bow_embed),
        state_manager=StateManager(),
    )


# ── store + fetch roundtrip ──────────────────────────────────────────────────
def test_store_and_fetch_roundtrip(manager):
    manager.store("the user prefers answers in Urdu", user_id="u1", session_id="s1")
    hits = manager.fetch("answers in Urdu", user_id="u1")
    assert len(hits) >= 1
    assert "Urdu" in hits[0]["text"]


def test_store_sets_expected_metadata(manager):
    res = manager.store("remember this fact", user_id="u9", session_id="s9", role="user")
    meta = res["metadata"]
    for key in ("user_id", "session_id", "role", "timestamp", "text"):
        assert key in meta
    assert meta["user_id"] == "u9"
    assert meta["session_id"] == "s9"
    assert meta["role"] == "user"
    assert meta["text"] == "remember this fact"
    assert res["degraded"] is False


def test_store_keeps_extra_metadata(manager):
    res = manager.store("hi", metadata={"topic": "pricing", "nested": {"a": 1}})
    assert res["metadata"]["topic"] == "pricing"
    assert res["metadata"]["nested"] == "{'a': 1}"  # coerced to a primitive


# ── top-K relevance ordering ─────────────────────────────────────────────────
def test_top_k_returns_k_and_orders_by_score(manager):
    manager.store("python fastapi backend service", user_id="u1")
    manager.store("banana mango fruit smoothie", user_id="u1")
    manager.store("pinecone vector database embedding", user_id="u1")

    hits = manager.fetch("python fastapi backend", user_id="u1", top_k=2)
    assert len(hits) == 2
    assert hits[0]["score"] >= hits[1]["score"]
    assert "fastapi" in hits[0]["text"]


def test_fetch_top_k_limits_results(manager):
    for i in range(6):
        manager.store(f"memory number {i}", user_id="u1")
    assert len(manager.fetch("memory", user_id="u1", top_k=3)) == 3


def test_fetch_respects_default_top_k(manager):
    manager.default_top_k = 2
    for i in range(5):
        manager.store(f"item {i}", user_id="u1")
    assert len(manager.fetch("item", user_id="u1")) == 2


def test_min_score_filters_weak_matches(manager):
    manager.store("entirely unrelated topic", user_id="u1")
    assert manager.fetch("completely different words xyz", user_id="u1", min_score=0.99) == []


# ── metadata filtering ───────────────────────────────────────────────────────
def test_fetch_filters_by_user(manager):
    manager.store("alice likes graphs", user_id="alice", session_id="s1")
    manager.store("bob likes tables", user_id="bob", session_id="s1")

    hits = manager.fetch("likes", user_id="alice", top_k=10)
    assert hits
    assert all(h["metadata"]["user_id"] == "alice" for h in hits)


def test_fetch_filters_by_session(manager):
    manager.store("session one note", user_id="u1", session_id="s1")
    manager.store("session two note", user_id="u1", session_id="s2")

    hits = manager.fetch("note", user_id="u1", session_id="s2", top_k=10)
    assert hits
    assert all(h["metadata"]["session_id"] == "s2" for h in hits)


def test_fetch_without_filters_spans_all(manager):
    manager.store("alpha note", user_id="a")
    manager.store("beta note", user_id="b")
    users = {h["metadata"]["user_id"] for h in manager.fetch("note", top_k=10)}
    assert users == {"a", "b"}


# ── audit logging ───────────────────────────────────────────────────────────
def test_audit_logging_and_history(manager):
    row = manager.log(
        user_id="u1",
        session_id="s1",
        prompt="what is AQL-1?",
        response="an agent operating layer",
        model="gpt-4o-mini",
        provider="openai",
        latency_ms=180,
    )
    assert row["degraded"] is False
    assert row["log_id"] and row["created_at"]
    assert row["total_tokens"] == row["input_tokens"] + row["output_tokens"]
    assert row["input_tokens"] > 0 and row["output_tokens"] > 0
    assert row["cost_usd"] > 0  # derived from the router pricing table
    assert row["latency_ms"] == 180

    history = manager.history(user_id="u1")
    assert len(history) == 1
    assert history[0]["prompt"] == "what is AQL-1?"


def test_audit_explicit_tokens_are_kept(manager):
    row = manager.log(prompt="p", response="r", input_tokens=10, output_tokens=20)
    assert row["input_tokens"] == 10 and row["output_tokens"] == 20
    assert row["total_tokens"] == 30


def test_audit_history_is_newest_first_and_filtered(manager):
    manager.log(user_id="a", session_id="s1", prompt="one", response="1")
    manager.log(user_id="b", session_id="s1", prompt="two", response="2")
    manager.log(user_id="a", session_id="s2", prompt="three", response="3")

    assert manager.history(user_id="a")[0]["prompt"] == "three"
    assert len(manager.history(user_id="a", session_id="s1")) == 1
    assert len(manager.history()) == 3
    assert len(manager.history(limit=2)) == 2


def test_record_stores_both_turns_and_audits(manager):
    out = manager.record("hi", "hello", user_id="u1", session_id="s1", model="gpt-4o-mini")
    assert out["audit"]["prompt"] == "hi"
    assert out["prompt"]["metadata"]["role"] == "user"
    assert out["response"]["metadata"]["role"] == "assistant"
    assert len(manager.history(user_id="u1")) == 1


# ── no-keys fallback path ───────────────────────────────────────────────────
def test_no_keys_uses_local_fallback(manager):
    # No Pinecone / Supabase credentials \u2192 both layers run locally.
    assert manager.vector_store.is_local is True
    assert manager.state.is_local is True

    stored = manager.store("works without keys")
    assert stored["degraded"] is False
    assert manager.fetch("works without keys")[0]["text"] == "works without keys"

    row = manager.log(prompt="p", response="r")
    assert row["degraded"] is False
    assert len(manager.history()) == 1


# ── graceful degradation & strict mode ────────────────────────────────────────
def test_store_degrades_when_vector_store_raises(manager, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("pinecone down")

    monkeypatch.setattr(manager.vector_store, "upsert", boom)
    res = manager.store("still remembered")
    assert res["degraded"] is True  # no exception, buffered locally

    # ...and the buffered memory is still recallable.
    hits = manager.fetch("still remembered")
    assert any(h["text"] == "still remembered" for h in hits)


def test_store_strict_raises_typed_error(manager, monkeypatch):
    monkeypatch.setattr(
        manager.vector_store, "upsert", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    with pytest.raises(MemoryStoreError):
        manager.store("nope", strict=True)


def test_fetch_degrades_and_strict_raises(manager, monkeypatch):
    manager.store("kept in memory", user_id="u1")
    monkeypatch.setattr(
        manager.vector_store, "query", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    # default: degrades to an empty list, no crash
    assert manager.fetch("anything", strict=False) == []
    with pytest.raises(MemoryFetchError):
        manager.fetch("anything", strict=True)


def test_log_strict_raises_typed_error(manager, monkeypatch):
    monkeypatch.setattr(
        manager.state, "log_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert manager.log(prompt="p", response="r")["degraded"] is True
    with pytest.raises(MemoryAuditError):
        manager.log(prompt="p", response="r", strict=True)


def test_history_degrades_to_empty_list(manager, monkeypatch):
    monkeypatch.setattr(
        manager.state, "list_audit", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert manager.history() == []


# ── context builder ────────────────────────────────────────────────────────


def test_build_context_includes_memories(manager):
    manager.store("user is building AQL-1", user_id="u1", session_id="s1")
    ctx = manager.build_context("AQL-1", user_id="u1", session_id="s1", top_k=3)
    assert "AQL-1" in ctx
    assert ctx.startswith("-")


def test_build_context_empty_when_nothing_matches(manager):
    assert manager.build_context("nothing stored yet", user_id="ghost") == ""


# ── API wiring ────────────────────────────────────────────────────────────
def test_api_memory_logs_endpoints():
    r = client.post(
        "/memory/logs",
        json={
            "user_id": "api-user",
            "session_id": "api-session",
            "prompt": "hello",
            "response": "world",
            "model": "gpt-4o-mini",
            "provider": "openai",
            "latency_ms": 42,
        },
    )
    assert r.status_code == 200
    assert r.json()["total_tokens"] > 0

    r = client.get("/memory/logs", params={"user_id": "api-user"})
    assert r.status_code == 200
    assert any(row["prompt"] == "hello" for row in r.json()["logs"])


def test_api_memory_recall_endpoint():
    client.post(
        "/memory/recall",
        json={"query": "warmup", "top_k": 1},
    )
    r = client.post(
        "/memory/recall",
        json={"query": "warmup", "top_k": 3, "user_id": "someone"},
    )
    assert r.status_code == 200
    assert "results" in r.json()
