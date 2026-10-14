"""Vector store abstraction backed by Pinecone.

Falls back to an in-process store when no Pinecone key is configured, so the
boilerplate runs out of the box.

Extended for the long-term memory manager (``memory/manager.py``):

* caller-supplied vector ids, so a memory keeps a stable identity
* metadata filtering (``user_id`` / ``session_id`` / ``role`` / ...)
* relevance **scores** on query results
* **Pinecone integrated embeddings** \u2014 with a Pinecone key the index
  (``llama-text-embed-v2-index``) embeds text server-side, so we call
  ``upsert_records`` / ``search`` with raw text and never embed manually. The
  local fallback uses a deterministic hash embedding.
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class MemoryRecord:
    """A single memory item."""

    id: str
    text: str
    embedding: list[float] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0  # relevance — populated on query results


def _hash_embed(text: str, dim: int = 64) -> list[float]:
    """Deterministic, dependency-free pseudo-embedding for local dev.

    Replace with a real embedding model (OpenAI text-embedding-3-small, etc.)
    in production.
    """
    vec = [0.0] * dim
    for i, ch in enumerate(text):
        vec[i % dim] += (ord(ch) % 31) / 31.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def embed_text(text: str) -> list[float]:
    """Local embedding used only by the in-process fallback store.

    Pinecone embeds text itself (integrated index), so no external embedding
    provider (and no OpenAI key) is needed.
    """
    return _hash_embed(text or "")


def _flat_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Keep only Pinecone-safe scalar metadata values (drop None/objects)."""
    out: dict[str, Any] = {}
    for k, v in metadata.items():
        if v is None or k in {"id", "_id", "text"}:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, list) and all(isinstance(i, str) for i in v):
            out[k] = v
        else:
            out[k] = str(v)
    return out


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors."""
    if not a or not b:
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def _matches(metadata: dict[str, Any], filters: dict[str, Any] | None) -> bool:
    """True when every non-null entry in ``filters`` equals the metadata value."""
    if not filters:
        return True
    return all(
        metadata.get(key) == value
        for key, value in filters.items()
        if value is not None
    )


# Public aliases so other modules never have to reach for private names.
cosine_similarity = _cosine
metadata_matches = _matches


class VectorStore:
    """Thin wrapper over Pinecone with a local fallback."""

    def __init__(self, embedder: Callable[[str], list[float]] | None = None) -> None:
        self.settings = get_settings()
        # Swappable embedder (tests inject a deterministic one).
        self._embed: Callable[[str], list[float]] = embedder or embed_text
        self._local: list[MemoryRecord] = []
        self._index = None
        self._namespace = self.settings.pinecone_namespace
        if self.settings.pinecone_api_key:
            self._index = self._connect_pinecone()

    # ── internals ─────────────────────────────────────────────────────────
    def _connect_pinecone(self):  # pragma: no cover — needs real creds
        try:
            from pinecone import Pinecone

            pc = Pinecone(api_key=self.settings.pinecone_api_key)
            return pc.Index(self.settings.pinecone_index_name)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully
            logger.warning("Pinecone unavailable (%s) — using the local store", exc)
            return None

    @property
    def is_local(self) -> bool:
        """True when reads/writes go to the in-process fallback store."""
        return self._index is None

    def embed(self, text: str) -> list[float]:
        """Embed ``text`` with the configured embedder."""
        return self._embed(text or "")

    # ── writes ────────────────────────────────────────────────────────────
    def upsert(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
        record_id: str | None = None,
        embedding: list[float] | None = None,
    ) -> MemoryRecord:
        """Store ``text`` (+ metadata) and return the stored record.

        ``record_id`` lets the caller keep a stable identity for the vector;
        when omitted a uuid4 is generated. On a Pinecone failure the record is
        written to the local store instead of raising.
        """
        metadata = dict(metadata or {})
        record = MemoryRecord(
            id=record_id or str(uuid.uuid4()),
            text=text,
            embedding=embedding or self._embed(text),
            metadata=metadata,
        )
        if self._index is not None:  # pragma: no cover — needs real creds
            try:
                self._index.upsert_records(
                    namespace=self._namespace,
                    records=[
                        {"_id": record.id, "text": text, **_flat_metadata(metadata)}
                    ],
                )
                return record
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Pinecone upsert failed (%s) — storing locally instead", exc
                )
        self._local.append(record)
        return record

    # ── reads ─────────────────────────────────────────────────────────────
    def query(
        self,
        text: str,
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[MemoryRecord]:
        """Return the ``top_k`` most relevant memories for ``text``.

        ``filters`` is an exact-match metadata filter (e.g.\n        ``{"user_id": "u1", "session_id": "s2"}``). Results carry a
        ``score`` (0..1 for the local cosine store, provider score for
        Pinecone). Pinecone failures fall back to the local search.
        """
        q = self._embed(text)
        if self._index is not None:  # pragma: no cover — needs real creds
            try:
                query: dict[str, Any] = {"top_k": top_k, "inputs": {"text": text}}
                clean = {k: v for k, v in (filters or {}).items() if v is not None}
                if clean:
                    query["filter"] = clean
                res = self._index.search(namespace=self._namespace, query=query)
                result = res["result"] if isinstance(res, dict) else res.result
                hits = result["hits"] if isinstance(result, dict) else result.hits
                out: list[MemoryRecord] = []
                for h in hits:
                    get = h.get if isinstance(h, dict) else (lambda k, d=None: getattr(h, k, d))
                    fields = dict(get("fields", {}) or {})
                    out.append(
                        MemoryRecord(
                            id=str(get("_id", "")),
                            text=str(fields.get("text", "")),
                            metadata=fields,
                            score=float(get("_score", 0.0) or 0.0),
                        )
                    )
                return out
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Pinecone search failed (%s) — searching locally instead", exc
                )
        scored = [
            MemoryRecord(
                id=r.id,
                text=r.text,
                embedding=r.embedding,
                metadata=r.metadata,
                score=_cosine(q, r.embedding),
            )
            for r in self._local
            if _matches(r.metadata, filters)
        ]
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]
