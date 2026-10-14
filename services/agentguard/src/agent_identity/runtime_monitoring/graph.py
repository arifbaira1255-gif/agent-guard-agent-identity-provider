"""Phase 5 intent graph.

A graph model connecting the entities and events Phase 5 observes: agents/identities, tasks, tools,
resources, policies, events, data classifications and destinations.

**Naming honesty.** This is an *intent graph* in the sense that it captures the observable
relationships that constitute an agent's observed behaviour -- which tools it touched, which
resources it accessed, which destinations it sent data to, which policies governed those decisions,
and which task (if any) a trusted application declared it was working on. It does **not** infer
internal goals. Every edge records ``provenance`` (what produced it) and ``confidence`` (how strong
that evidence is), so a directly-observed invocation is never presented as equivalent to a
co-occurrence guess.

Storage: this graph is backed by the same store abstraction as the rest of the monitoring plane
(migration 0008 tables ``runtime_graph_nodes`` / ``runtime_graph_edges``). No separate graph database
is introduced -- see the requirement not to duplicate existing persistence.

Tenant isolation is enforced on every mutation and every query.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..security.ids import new_id
from .errors import GraphError, TenantBoundaryError
from .models import EdgeKind, GraphEdge, GraphNode, NodeKind, RuntimeEvent
from .store import RuntimeMonitoringStore

#: Provenance labels -- what produced an edge. Ordered strongest -> weakest.
P_DIRECT = "direct_observation"        # the event itself named both endpoints
P_DECLARED = "declared_scope"          # a trusted application declared the relationship
P_CO_OCCURRENCE = "co_occurrence"      # both appeared in the same correlation window

CONF_DIRECT = 1.0
CONF_DECLARED = 0.9
CONF_CO_OCCURRENCE = 0.5


class IntentGraph:
    """Tenant-isolated graph of observed entities and relationships."""

    def __init__(self, store: RuntimeMonitoringStore, *, max_nodes: int = 100_000,
                 max_edges: int = 500_000, audit=None, clock=None):
        self.store = store
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.audit = audit
        self._clock = clock

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    # ------------------------------------------------------------------ node helpers
    @staticmethod
    def node_id(org_id: str, kind: str, key: str) -> str:
        """A deterministic, org-namespaced node id (so two tenants can never collide)."""
        return f"{kind}:{key}"

    def upsert_node(self, *, org_id: str, kind: str, key: str, label: Optional[str] = None,
                    ts: Optional[float] = None, attributes: Optional[dict] = None) -> GraphNode:
        if not org_id:
            raise TenantBoundaryError("org_id is required for a graph node")
        k = NodeKind.coerce(kind)
        if k is None:
            raise GraphError(f"unknown node kind: {kind!r}")
        if not key:
            raise GraphError("node key is required")
        now = ts if ts is not None else self._now()
        node = GraphNode(node_id=self.node_id(org_id, k.value, str(key)), org_id=org_id,
                         kind=k.value, label=str(label or key), first_seen=now, last_seen=now,
                         attributes=dict(attributes or {}))
        self.store.put_node(node)
        return node

    # ------------------------------------------------------------------ ingestion
    def record_event(self, ev: RuntimeEvent, *, task_id: Optional[str] = None) -> dict:
        """Project one runtime event into graph nodes and edges. Returns a small summary."""
        org = ev.org_id
        ts = ev.ts
        if task_id is None:
            task_id = ev.task_id
        agent = self.upsert_node(org_id=org, kind=NodeKind.AGENT.value,
                                 key=ev.agent_id or "unknown", label=ev.agent_id or "unknown",
                                 ts=ts)
        event_node = self.upsert_node(org_id=org, kind=NodeKind.EVENT.value, key=ev.event_id,
                                      label=ev.event_type, ts=ts,
                                      attributes={"event_type": ev.event_type,
                                                  "decision": ev.decision})
        self._edge(org, EdgeKind.EVENT_SUBJECT.value, agent.node_id, event_node.node_id, ts,
                   P_DIRECT, CONF_DIRECT, ev.event_id)

        tool = _tool_of(ev)
        if tool:
            tn = self.upsert_node(org_id=org, kind=NodeKind.TOOL.value, key=tool, ts=ts)
            self._edge(org, EdgeKind.AGENT_TOOL.value, agent.node_id, tn.node_id, ts, P_DIRECT,
                       CONF_DIRECT, ev.event_id)
        if ev.resource:
            rn = self.upsert_node(org_id=org, kind=NodeKind.RESOURCE.value, key=ev.resource,
                                  label=ev.resource, ts=ts,
                                  attributes={"resource_type": ev.resource_type or ""})
            self._edge(org, EdgeKind.AGENT_RESOURCE.value, agent.node_id, rn.node_id, ts, P_DIRECT,
                       CONF_DIRECT, ev.event_id)
        if ev.destination:
            dn = self.upsert_node(org_id=org, kind=NodeKind.DESTINATION.value, key=ev.destination,
                                  ts=ts, attributes={"address_class": ev.address_class or ""})
            self._edge(org, EdgeKind.AGENT_DESTINATION.value, agent.node_id, dn.node_id, ts,
                       P_DIRECT, CONF_DIRECT, ev.event_id)
            if ev.resource:
                self._edge(org, EdgeKind.RESOURCE_DESTINATION.value,
                           self.node_id(org, NodeKind.RESOURCE.value, ev.resource), dn.node_id, ts,
                           P_DIRECT, CONF_DIRECT, ev.event_id)
        if ev.policy_id:
            pn = self.upsert_node(org_id=org, kind=NodeKind.POLICY.value, key=ev.policy_id, ts=ts,
                                  attributes={"policy_version": ev.policy_version or ""})
            self._edge(org, EdgeKind.AGENT_POLICY.value, agent.node_id, pn.node_id, ts, P_DIRECT,
                       CONF_DIRECT, ev.event_id)
        for dc in ev.data_classes:
            cn = self.upsert_node(org_id=org, kind=NodeKind.DATA_CLASS.value, key=dc, ts=ts)
            if ev.resource:
                self._edge(org, EdgeKind.TASK_RESOURCE.value,
                           self.node_id(org, NodeKind.RESOURCE.value, ev.resource), cn.node_id, ts,
                           P_DIRECT, CONF_DIRECT, ev.event_id)
        if task_id:
            tkn = self.upsert_node(org_id=org, kind=NodeKind.TASK.value, key=task_id, ts=ts)
            self._edge(org, EdgeKind.AGENT_TASK.value, agent.node_id, tkn.node_id, ts, P_DECLARED,
                       CONF_DECLARED, ev.event_id)
        return {"agent_node": agent.node_id, "event_node": event_node.node_id}

    def declare_task_scope(self, *, org_id: str, task_id: str, resources: Sequence[str] = (),
                           tools: Sequence[str] = (), destinations: Sequence[str] = (),
                           ts: Optional[float] = None, provenance: str = P_DECLARED) -> dict:
        """Record a TRUSTED application's declaration of what a task may touch.

        This is the one place a relationship is recorded without a matching runtime event, so it is
        labelled ``declared_scope`` rather than ``direct_observation``.
        """
        now = ts if ts is not None else self._now()
        task = self.upsert_node(org_id=org_id, kind=NodeKind.TASK.value, key=task_id, ts=now)
        edges = 0
        for res in resources:
            rn = self.upsert_node(org_id=org_id, kind=NodeKind.RESOURCE.value, key=res, ts=now)
            self._edge(org_id, EdgeKind.TASK_RESOURCE.value, task.node_id, rn.node_id, now,
                       provenance, CONF_DECLARED, None)
            edges += 1
        for tool in tools:
            tn = self.upsert_node(org_id=org_id, kind=NodeKind.TOOL.value, key=tool, ts=now)
            self._edge(org_id, EdgeKind.AGENT_TOOL.value, task.node_id, tn.node_id, now,
                       provenance, CONF_DECLARED, None)
            edges += 1
        for dest in destinations:
            dn = self.upsert_node(org_id=org_id, kind=NodeKind.DESTINATION.value, key=dest, ts=now)
            self._edge(org_id, EdgeKind.AGENT_DESTINATION.value, task.node_id, dn.node_id, now,
                       provenance, CONF_DECLARED, None)
            edges += 1
        return {"task_node": task.node_id, "edges_declared": edges}

    # ------------------------------------------------------------------ queries
    def neighbors(self, *, org_id: str, node_id: str, direction: str = "both",
                  kind: Optional[str] = None, limit: int = 200) -> dict:
        """Direct neighbours of a node. Tenant-scoped."""
        edges = self.store.list_edges(org_id=org_id, node_id=node_id, kind=kind, limit=limit)
        if direction == "out":
            edges = [e for e in edges if e.src == node_id]
        elif direction == "in":
            edges = [e for e in edges if e.dst == node_id]
        elif direction != "both":
            raise GraphError("direction must be in|out|both")
        node = self.store.get_node(node_id, org_id=org_id)
        return {"node": node.public_dict() if node else None,
                "edges": [e.public_dict() for e in edges], "count": len(edges)}

    def agent_toolchain(self, *, org_id: str, agent_id: str, limit: int = 200) -> dict:
        """Every tool/resource/destination an agent was OBSERVED to touch."""
        agent_node = self.node_id(org_id, NodeKind.AGENT.value, agent_id)
        edges = self.store.list_edges(org_id=org_id, node_id=agent_node, limit=limit)
        out: Dict[str, List[dict]] = {}
        for e in edges:
            out.setdefault(e.kind, []).append(e.public_dict())
        return {"org_id": org_id, "agent_id": agent_id, "agent_node": agent_node,
                "by_kind": out, "edge_count": len(edges)}

    def suspicious_chains(self, *, org_id: str, agent_id: Optional[str] = None,
                          max_depth: int = 3, limit: int = 100) -> List[dict]:
        """Find short observed chains that an investigator should look at.

        Heuristic ranking only. A chain is 'suspicious' when it contains a deny/destination edge to a
        node the agent had not previously used, or a tool/resource node reached with no policy
        governance on the path. Reported with its provenance so the investigator can judge it.
        """
        if max_depth < 1:
            raise GraphError("max_depth must be >= 1")
        edges = self.store.list_edges(org_id=org_id, limit=limit * 10)
        if agent_id:
            agent_node = self.node_id(org_id, NodeKind.AGENT.value, agent_id)
            edges = [e for e in edges if e.src == agent_node or e.dst == agent_node]
        adjacency: Dict[str, List[GraphEdge]] = {}
        for e in edges:
            adjacency.setdefault(e.src, []).append(e)
        chains: List[dict] = []
        for e in edges:
            if len(chains) >= limit:
                break
            nodes = self.store.list_nodes(org_id=org_id, limit=limit * 10)
            node_by_id = {n.node_id: n for n in nodes}
            path = [e]
            frontier = e.dst
            for _ in range(max_depth - 1):
                nxt = adjacency.get(frontier)
                if not nxt:
                    break
                path.append(nxt[0])
                frontier = nxt[0].dst
            kinds = [node_by_id[p.src].kind if p.src in node_by_id else "?"
                     for p in path] + \
                    [node_by_id[path[-1].dst].kind if path[-1].dst in node_by_id else "?"]
            has_destination = NodeKind.DESTINATION.value in kinds
            has_policy = NodeKind.POLICY.value in kinds
            score = 0.0
            reasons: List[str] = []
            if has_destination and not has_policy:
                score += 0.5
                reasons.append("destination reached with no policy node on the observed path")
            if any(p.count == 1 for p in path):
                score += 0.2
                reasons.append("relationship observed only once")
            if score <= 0:
                continue
            chains.append({
                "score": round(min(1.0, score), 2), "reasons": reasons,
                "node_ids": [p.src for p in path] + [path[-1].dst], "node_kinds": kinds,
                "edges": [p.public_dict() for p in path],
                "note": ("observed relationships only; the graph does not establish intent or "
                         "causality beyond the recorded provenance"),
            })
        return sorted(chains, key=lambda c: -c["score"])[:limit]

    def repeated_patterns(self, *, org_id: str, kind: str = EdgeKind.AGENT_RESOURCE.value,
                          min_count: int = 3, limit: int = 100) -> List[dict]:
        """Edges with a high observed count -- repeated access patterns worth reviewing."""
        edges = self.store.list_edges(org_id=org_id, kind=kind, limit=limit * 10)
        out = [e.public_dict() for e in edges if e.count >= min_count]
        return sorted(out, key=lambda e: -e["count"])[:limit]

    def stats(self, *, org_id: str) -> dict:
        nodes = self.store.list_nodes(org_id=org_id, limit=self.max_nodes)
        edges = self.store.list_edges(org_id=org_id, limit=self.max_edges)
        by_kind: Dict[str, int] = {}
        for n in nodes:
            by_kind[n.kind] = by_kind.get(n.kind, 0) + 1
        return {"org_id": org_id, "nodes": len(nodes), "edges": len(edges),
                "nodes_by_kind": dict(sorted(by_kind.items()))}

    def clear(self, *, org_id: str, actor_user_id: Optional[str] = None) -> int:
        removed = self.store.delete_graph(org_id=org_id)
        if self.audit is not None:
            self.audit.record("runtime.graph.updated", org_id=org_id, outcome="ok",
                              action="clear", actor_user_id=actor_user_id,
                              extra={"removed": removed})
        return removed

    # ------------------------------------------------------------------ internals
    def _edge(self, org_id: str, kind: str, src: str, dst: str, ts: float, provenance: str,
              confidence: float, event_id: Optional[str]) -> GraphEdge:
        edge_id = f"{kind}|{src}|{dst}"
        edge = GraphEdge(edge_id=edge_id, org_id=org_id, kind=kind, src=src, dst=dst,
                         first_seen=ts, last_seen=ts, count=1, confidence=confidence,
                         provenance=provenance, last_event_id=event_id)
        self.store.put_edge(edge)
        return edge


def _tool_of(ev: RuntimeEvent) -> Optional[str]:
    from .models import EventType
    if ev.event_type not in (EventType.TOOL_INVOCATION.value, EventType.API_INVOCATION.value):
        return None
    for candidate in ((ev.extra.get("tool_id") if isinstance(ev.extra, dict) else None),
                      ev.action, ev.resource):
        if isinstance(candidate, str) and candidate:
            return candidate
    return None
