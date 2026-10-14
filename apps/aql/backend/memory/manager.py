"""Long-term memory manager for AQL-1.

``MemoryManager`` is the single fa\u00e7ade the agent runtime uses to remember
across sessions. It provides three capabilities:

1. **Store** \u2014 embed a user interaction / context snippet and upsert the
   vector into Pinecone together with rich metadata (``user_id``,
   ``session_id``, ``role``, ``timestamp``, the raw ``text``, ...).
2. **Fetch** \u2014 embed the current task and query Pinecone for the top-K most
   relevant past memories, optionally filtered by ``user_id`` / ``session_id``
   / ``role``, returning them with relevance scores.
3. **Log** \u2014 append a historical session/run record to Supabase PostgreSQL for
   auditing (prompt, response, model, token counts, cost, latency, timestamp).

Design notes
------------
* It **reuses** the existing ``memory/vector_store.py`` (Pinecone + in-process
  fallback) and ``memory/state.py`` (Supabase + in-memory fallback) instead of
  talking to those services directly, so it inherits their graceful
  degradation.
* With **no API keys present** every operation still succeeds against the local
  stores \u2014 nothing ever hard-fails.
* Lower-level failures surface as typed exceptions (:class:`MemoryStoreError`,
  :class:`MemoryFetchError`, :class:`MemoryAuditError`). By default the public
  methods *degrade* (log a warning and carry on); pass ``strict=True`` to raise.

Quickstart
----------
    from memory.manager import MemoryManager

    mgr = MemoryManager()
    mgr.store("User prefers concise Urdu answers", user_id="u1", session_id="s1")
    hits = mgr.fetch("how should I answer this user?", user_id="u1", top_k=3)
    mgr.log(user_id="u1", session_id="s1", prompt="hi", response="hello",
            model="gpt-4o-mini", latency_ms=180)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.config import get_settings
from core.router import estimate_cost, estimate_tokens

from .state import StateManager
from .vector_store import (
    MemoryRecord,
    VectorStore,
    cosine_similarity,
    metadata_matches,
)

logger = logging.getLogger(__name__)


# ── typed exceptions ─────────────────────────────────────────────────────────
class MemoryError(Exception):
    """Base class for every long-term memory failure."""


class MemoryStoreError(MemoryError):
    """A memory could not be written (raised in strict mode)."""


class MemoryFetchError(MemoryError):
    """Memory retrieval failed (raised in strict mode)."""


class MemoryAuditError(MemoryError):
    """The audit log write failed (raised in strict mode)."""


# ── helpers ──────────────────────────────────────────────────────────────
def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 string (the audit timestamp format)."""
    return datetime.now(timezone.utc).isoformat()


def _primitive(value: Any) -> Any:
    """Coerce a value into something Pinecone metadata can actually store."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


@dataclass
class ScoredMemory:
    """A memory returned by :meth:`MemoryManager.fetch`."""

    id: str
    text: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "score": self.score,
            "metadata": self.metadata,
        }


@dataclass
class AuditRecord:
    """One row of the Supabase ``memory_audit`` table."""

    user_id: str = "anonymous"
    session_id: str = "default"
    role: str = "assistant"
    prompt: str = ""
    response: str = ""
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    log_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_utcnow_iso)

    def to_row(self) -> dict[str, Any]:
        """Serialise to a flat, JSON-safe row for insert()."""
        row = asdict(self)
        row["total_tokens"] = self.total_tokens or (
            self.input_tokens + self.output_tokens
        )
        return row


class MemoryManager:
    """Store, fetch and audit long-term memory for the AQL-1 agent."""

    def __init__(
        self,
        vector_store: VectorStore | None = None,
        state_manager: StateManager | None = None,
        top_k: int | None = None,
    ) -> None:
        self.settings = get_settings()
        self.vector_store = vector_store or VectorStore()
        self.state = state_manager or StateManager()
        self.default_top_k = top_k or self.settings.memory_top_k
        # Last-resort buffer, used only if the vector store itself raises.
        self._degraded: list[MemoryRecord] = []

    # ── internal helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _build_filters(
        user_id: str | None,
        session_id: str | None,
        role: str | None,
    ) -> dict[str, Any]:
        """Keep only the filters the caller actually asked for."""
        return {
            key: value
            for key, value in {
                "user_id": user_id,
                "session_id": session_id,
                "role": role,
            }.items()
            if value is not None
        }

    def _build_metadata(
        self,
        text: str,
        user_id: str,
        session_id: str,
        role: str,
        run_id: str | None,
        model: str | None,
        extra: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Assemble the Pinecone metadata payload for a memory."""
        meta: dict[str, Any] = {
            "user_id": user_id,
            "session_id": session_id,
            "role": role,
            "timestamp": _utcnow_iso(),
            "text": text,
            "kind": "interaction",
        }
        if run_id:
            meta["run_id"] = run_id
        if model:
            meta["model"] = model
        for key, value in (extra or {}).items():
            if value is not None:
                meta[key] = _primitive(value)
        return meta

    # ── 1. STORE ───────────────────────────────────────────────────────────
    def store(
        self,
        text: str,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        role: str = "user",
        run_id: str | None = None,
        model: str | None = None,
        metadata: dict[str, Any] | None = None,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Embed ``text`` and upsert it into Pinecone with metadata.

        Steps: build the metadata payload \u2192 embed the text \u2192 upsert the
        vector (id, embedding, metadata including the raw text). On failure the
        item is buffered locally and ``degraded`` is set in the result \u2014
        unless ``strict=True``, which re-raises as :class:`MemoryStoreError`.
        """
        clean = (text or "").strip()
        meta = self._build_metadata(
            clean, user_id, session_id, role, run_id, model, metadata
        )
        try:
            record = self.vector_store.upsert(clean, meta)
        except Exception as exc:  # noqa: BLE001 — degrade, never crash
            logger.warning(
                "MemoryManager.store failed (%s) \u2014 buffering locally", exc
            )
            if strict:
                raise MemoryStoreError(str(exc)) from exc
            record = MemoryRecord(
                id=str(uuid.uuid4()),
                text=clean,
                embedding=self.vector_store.embed(clean),
                metadata=meta,
            )
            self._degraded.append(record)
            return {
                "id": record.id,
                "text": record.text,
                "metadata": record.metadata,
                "degraded": True,
            }
        return {
            "id": record.id,
            "text": record.text,
            "metadata": record.metadata,
            "degraded": False,
        }

    # ── 2. FETCH ───────────────────────────────────────────────────────────
    def fetch(
        self,
        query: str,
        *,
        top_k: int | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        role: str | None = None,
        min_score: float | None = None,
        strict: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the top-K relevant past memories for ``query``.

        Steps: embed the query \u2192 query Pinecone with ``top_k`` and any
        user/session/role filter \u2192 return scored memories (highest score
        first). On failure it degrades to an empty list \u2014 unless
        ``strict=True``, which re-raises as :class:`MemoryFetchError`.
        """
        k = top_k or self.default_top_k
        filters = self._build_filters(user_id, session_id, role)

        try:
            hits = self.vector_store.query(query, top_k=k, filters=filters or None)
        except Exception as exc:  # noqa: BLE001 — degrade, never crash
            logger.warning("MemoryManager.fetch failed (%s)", exc)
            if strict:
                raise MemoryFetchError(str(exc)) from exc
            hits = []

        # Merge in anything the vector store could not persist earlier, so
        # degraded writes are still recallable within the process.
        if self._degraded:
            q_vec = self.vector_store.embed(query)
            seen = {h.id for h in hits}
            extra = [
                MemoryRecord(
                    id=r.id,
                    text=r.text,
                    embedding=r.embedding,
                    metadata=r.metadata,
                    score=cosine_similarity(q_vec, r.embedding),
                )
                for r in self._degraded
                if r.id not in seen and metadata_matches(r.metadata, filters)
            ]
            hits = sorted([*hits, *extra], key=lambda r: r.score, reverse=True)

        results = [
            ScoredMemory(
                id=h.id,
                text=h.text,
                score=round(float(h.score), 6),
                metadata=h.metadata,
            ).to_dict()
            for h in hits[:k]
        ]
        if min_score is not None:
            results = [r for r in results if r["score"] >= min_score]
        return results

    # ── 3. LOG (Supabase audit) ───────────────────────────────────────────────
    def log(
        self,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        role: str = "assistant",
        prompt: str = "",
        response: str = "",
        model: str = "",
        provider: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
        latency_ms: int = 0,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Append a session/run row to the Supabase audit table.

        Token counts default to an estimate from the text, and cost defaults to
        the router's per-model pricing table \u2014 so an audit row is complete even
        when the caller only supplies the prompt/response/model. On failure the
        row is kept in memory and ``degraded`` is set \u2014 unless
        ``strict=True``, which re-raises as :class:`MemoryAuditError`.
        """
        if not input_tokens:
            input_tokens = estimate_tokens(prompt)
        if not output_tokens:
            output_tokens = estimate_tokens(response)
        if not cost_usd and model:
            cost_usd = estimate_cost(model, input_tokens, output_tokens)

        row = AuditRecord(
            user_id=user_id,
            session_id=session_id,
            role=role,
            prompt=prompt,
            response=response,
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=round(float(cost_usd), 8),
            latency_ms=latency_ms,
        ).to_row()

        try:
            stored = self.state.log_audit(row)
        except Exception as exc:  # noqa: BLE001 — degrade, never crash
            logger.warning("MemoryManager.log failed (%s)", exc)
            if strict:
                raise MemoryAuditError(str(exc)) from exc
            row["degraded"] = True
            return row
        return {**stored, "degraded": False}

    # ── read side of the audit log ──────────────────────────────────────────
    def history(
        self,
        *,
        user_id: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return past audit rows, newest first."""
        try:
            return self.state.list_audit(
                user_id=user_id, session_id=session_id, limit=limit
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("MemoryManager.history failed (%s)", exc)
            return []

    # ── conveniences ─────────────────────────────────────────────────────────
    def build_context(
        self,
        query: str,
        *,
        top_k: int | None = None,
        user_id: str | None = None,
        session_id: str | None = None,
        min_score: float | None = None,
        limit_chars: int = 2000,
    ) -> str:
        """Return a prompt-ready block of relevant memories (empty if none)."""
        memories = self.fetch(
            query,
            top_k=top_k,
            user_id=user_id,
            session_id=session_id,
            min_score=min_score,
        )
        lines = [
            f"- ({m['metadata'].get('role', '?')} \u00b7 {m['score']:.2f}) {m['text']}"
            for m in memories
            if m.get("text")
        ]
        return "\n".join(lines)[:limit_chars]

    def record(
        self,
        prompt: str,
        response: str,
        *,
        user_id: str = "anonymous",
        session_id: str = "default",
        model: str = "",
        provider: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cost_usd: float = 0.0,
        latency_ms: int = 0,
        run_id: str | None = None,
        strict: bool = False,
    ) -> dict[str, Any]:
        """Persist a full interaction: store both turns **and** audit the run."""
        stored_prompt = self.store(
            prompt,
            user_id=user_id,
            session_id=session_id,
            role="user",
            run_id=run_id,
            model=model or None,
            strict=strict,
        )
        stored_response = self.store(
            response,
            user_id=user_id,
            session_id=session_id,
            role="assistant",
            run_id=run_id,
            model=model or None,
            strict=strict,
        )
        audit = self.log(
            user_id=user_id,
            session_id=session_id,
            prompt=prompt,
            response=response,
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            strict=strict,
        )
        return {"prompt": stored_prompt, "response": stored_response, "audit": audit}
