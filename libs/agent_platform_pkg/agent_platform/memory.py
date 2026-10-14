"""Memory: a bounded working set plus a searchable episodic store.

Two layers, on purpose:

* **working memory** -- the live message transcript the model sees.  It must be *bounded*, because an
  unbounded transcript is how an agent run turns an O(n^2) context cost into a budget blowout.  When
  it exceeds its cap the oldest non-system turns are summarised into a single synthetic note rather
  than dropped silently, so the model keeps continuity without keeping the tokens.
* **episodic memory** -- durable records (task, outcome, lesson) the agent can search on a later run.
  Retrieval is deliberately simple and explainable (token overlap + recency), not a black box: a
  wrong recall must be debuggable by reading the score.

Neither layer ever stores a credential: records pass through :func:`redact` on the way in, so a secret
that appears in a transcript cannot be re-read out of memory later.
"""
from __future__ import annotations

import math
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .ids import new_id
from .types import Message, Role
from .validation import redact, truncate

__all__ = ["MemoryRecord", "EpisodicMemory", "WorkingMemory", "tokenize"]

_WORD_RE = re.compile(r"[a-z0-9_]+")

#: Very common words carry no retrieval signal and would dominate every score.
_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "if", "then", "to", "of", "in", "on", "for", "with",
    "is", "are", "was", "were", "be", "been", "it", "its", "this", "that", "these", "those",
    "as", "at", "by", "from", "into", "than", "so", "do", "does", "did", "not", "no", "yes",
    "i", "you", "he", "she", "they", "we", "me", "my", "your", "our", "their", "can", "will",
})


def tokenize(text: str) -> List[str]:
    """Lowercase word tokens with stopwords removed -- the shared vocabulary for scoring."""
    return [w for w in _WORD_RE.findall((text or "").lower()) if w not in _STOPWORDS and len(w) > 1]


@dataclass
class MemoryRecord:
    """One durable episode.  ``key`` is what a future run searches by; ``value`` is what it reads."""

    key: str
    value: str
    kind: str = "episode"
    tags: List[str] = field(default_factory=list)
    score: float = 0.0
    record_id: str = field(default_factory=lambda: new_id("mem"))
    created_at: float = field(default_factory=time.time)
    last_used_at: Optional[float] = None
    uses: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"record_id": self.record_id, "kind": self.kind, "key": self.key,
                "value": self.value, "tags": list(self.tags), "score": round(self.score, 6),
                "created_at": self.created_at, "uses": self.uses,
                "metadata": redact(self.metadata)}

    @property
    def haystack(self) -> str:
        return f"{self.key} {self.value} {' '.join(self.tags)}"


class EpisodicMemory:
    """A bounded, thread-safe store with explainable keyword retrieval and optional TTL.

    The capacity is enforced by evicting the *lowest-value* records first: never-used and
    least-recently-used entries go before frequently-used ones, so a long-lived agent keeps the
    lessons that keep proving useful.
    """

    def __init__(self, *, capacity: int = 500, ttl_s: Optional[float] = None,
                 clock: Any = time.time) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = int(capacity)
        self.ttl_s = ttl_s
        self._clock = clock
        self._records: Dict[str, MemoryRecord] = {}
        self._lock = threading.Lock()
        self.evictions = 0

    # -- writes ------------------------------------------------------------------------------
    def remember(self, key: str, value: str, *, kind: str = "episode",
                 tags: Sequence[str] = (), metadata: Optional[Mapping[str, Any]] = None,
                 record_id: Optional[str] = None) -> MemoryRecord:
        """Store one episode.  Values are redacted and truncated before they are kept."""
        record = MemoryRecord(
            key=truncate(redact(str(key)), 512),
            value=truncate(redact(str(value)), 8192),
            kind=str(kind or "episode"),
            tags=[truncate(str(t), 64) for t in (tags or ())][:16],
            metadata=dict(redact(dict(metadata or {}))),
            created_at=self._clock(),
            **(dict(record_id=record_id) if record_id else {}))
        with self._lock:
            self._records[record.record_id] = record
            self._evict_locked()
        return record

    def forget(self, record_id: str) -> bool:
        with self._lock:
            return self._records.pop(record_id, None) is not None

    def expire(self) -> int:
        """Drop records past their TTL.  Returns how many were removed."""
        if self.ttl_s is None:
            return 0
        cutoff = self._clock() - float(self.ttl_s)
        with self._lock:
            stale = [rid for rid, rec in self._records.items() if rec.created_at < cutoff]
            for rid in stale:
                del self._records[rid]
            return len(stale)

    # -- reads -------------------------------------------------------------------------------
    def retrieve(self, query: str, *, top_k: int = 5, kind: Optional[str] = None) -> List[MemoryRecord]:
        """Rank records against ``query`` by token overlap, tie-broken by recency and reuse.

        The score is ``overlap / sqrt(len(query_tokens))`` plus a small recency-and-reuse bonus, which
        keeps it comparable across queries of different lengths and keeps a repeatedly useful lesson
        near the top even when a newer, weaker match appears.
        """
        self.expire()
        if top_k <= 0:
            return []
        query_tokens = set(tokenize(query))
        now = self._clock()
        with self._lock:
            candidates = [r for r in self._records.values() if kind is None or r.kind == kind]
        scored: List[MemoryRecord] = []
        for record in candidates:
            tokens = set(tokenize(record.haystack))
            overlap = len(query_tokens & tokens)
            if not overlap and query_tokens:
                continue
            base = overlap / math.sqrt(max(1, len(query_tokens)))
            age_hours = max(0.0, (now - record.created_at) / 3600.0)
            recency = 1.0 / (1.0 + age_hours)
            reuse = min(1.0, record.uses / 10.0)
            record.score = round(base + 0.15 * recency + 0.1 * reuse, 6)
            scored.append(record)
        scored.sort(key=lambda r: (r.score, r.created_at), reverse=True)
        chosen = scored[: int(top_k)]
        for record in chosen:
            record.uses += 1
            record.last_used_at = now
        return chosen

    def render(self, query: str, *, top_k: int = 5, max_chars: int = 4000) -> str:
        """Render the top matches as a block suitable for a system prompt (bounded)."""
        hits = self.retrieve(query, top_k=top_k)
        if not hits:
            return ""
        lines = ["Relevant prior context (from memory):"]
        for record in hits:
            lines.append(f"- [{record.kind}] {record.key}: {record.value}")
        return truncate("\n".join(lines), max_chars)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"records": len(self._records), "capacity": self.capacity,
                    "evictions": self.evictions, "ttl_s": self.ttl_s}

    # -- internals ---------------------------------------------------------------------------
    def _evict_locked(self) -> None:
        """Keep the store bounded, dropping the least valuable record first (caller holds the lock)."""
        while len(self._records) > self.capacity:
            victim = min(self._records.values(),
                         key=lambda r: (r.uses, r.last_used_at or 0.0, r.created_at))
            del self._records[victim.record_id]
            self.evictions += 1


class WorkingMemory:
    """The bounded live transcript, with summarising compaction instead of silent truncation.

    System messages are never compacted (they carry the agent's operating rules); user/assistant/tool
    turns are the ones summarised.  The most recent turns are always kept verbatim, because that is
    what the next model call reacts to.
    """

    def __init__(self, *, max_messages: int = 40, keep_recent: int = 12,
                 summariser: Optional[Any] = None) -> None:
        self.max_messages = max(4, int(max_messages))
        self.keep_recent = max(2, min(int(keep_recent), self.max_messages - 1))
        self._summariser = summariser
        self._messages: List[Message] = []
        self.compactions = 0

    # -- access ------------------------------------------------------------------------------
    def add(self, message: Message) -> Message:
        self._messages.append(message)
        self.compact_if_needed()
        return message

    def extend(self, messages: Sequence[Message]) -> None:
        self._messages.extend(messages)
        self.compact_if_needed()

    def messages(self) -> List[Message]:
        return list(self._messages)

    def __len__(self) -> int:
        return len(self._messages)

    # -- compaction --------------------------------------------------------------------------
    def compact_if_needed(self) -> bool:
        """Compact when over the cap.  Returns True when a compaction happened.

        Prior compaction notes are folded into the NEW note rather than kept alongside it.  Keeping
        them would grow the system block by one message per compaction -- the same unbounded growth
        the compaction exists to prevent.
        """
        if len(self._messages) <= self.max_messages:
            return False
        is_note = lambda m: m.role == Role.SYSTEM.value and "compacted" in (m.metadata or {})  # noqa: E731
        system = [m for m in self._messages if m.role == Role.SYSTEM.value and not is_note(m)]
        prior_notes = [m for m in self._messages if is_note(m)]
        body = [m for m in self._messages if m.role != Role.SYSTEM.value]
        keep = self.keep_recent
        drop, recent = body[:-keep], body[-keep:]
        if not drop and not prior_notes:
            return False
        note = self._summarise(list(prior_notes) + list(drop))
        merged = system + ([note] if note is not None else []) + recent
        # A pathological cap (or a flood of system messages) must still terminate.
        if len(merged) > self.max_messages:
            merged = merged[: max(1, self.max_messages - 1)] + [merged[-1]]
        self._messages = merged
        self.compactions += 1
        return True

    def _summarise(self, dropped: Sequence[Message]) -> Optional[Message]:
        if self._summariser is not None:
            try:
                text = self._summariser(list(dropped))
                if text:
                    return Message.system(f"Earlier turns (summarised): {truncate(text, 2000)}",
                                          metadata={"compacted": len(dropped)})
            except Exception:  # noqa: BLE001 - a failing summariser falls back to the local one
                pass
        return self._local_summary(dropped)

    @staticmethod
    def _local_summary(dropped: Sequence[Message]) -> Optional[Message]:
        """Deterministic, dependency-free summary: roles, counts, tool names, first line of each."""
        if not dropped:
            return None
        tools: List[str] = []
        snippets: List[str] = []
        counts: Dict[str, int] = {}
        for message in dropped:
            counts[message.role] = counts.get(message.role, 0) + 1
            for call in message.tool_calls or ():
                if call.name not in tools:
                    tools.append(call.name)
            first_line = (message.content or "").strip().splitlines()
            if first_line and len(snippets) < 8:
                snippets.append(f"{message.role}: {truncate(first_line[0], 160)}")
        parts = [f"{counts.get(role, 0)} {role} message(s)" for role in
                 (Role.USER.value, Role.ASSISTANT.value, Role.TOOL.value)]
        text = "Earlier turns compacted (" + ", ".join(parts) + ")."
        if tools:
            text += " Tools used: " + ", ".join(tools[:12]) + "."
        if snippets:
            text += " Excerpts: " + " | ".join(snippets)
        return Message.system(truncate(text, 2000), metadata={"compacted": len(dropped)})

    def stats(self) -> Dict[str, Any]:
        return {"messages": len(self._messages), "max_messages": self.max_messages,
                "keep_recent": self.keep_recent, "compactions": self.compactions}
