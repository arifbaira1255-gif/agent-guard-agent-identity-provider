# Step 11 — Security Limitations & Unprotected Execution Paths

This is the honest boundary of what Step 11 enforces. Read it before claiming coverage.

## 1. Enforcement is NOT universal — the bypass paths

The governance guard is a **chokepoint**, not a syscall interceptor. It authorizes operations that are
**routed through it**. The following code paths are **outside** enforcement and are NOT governed in
this step. If an agent process can reach them directly, it bypasses Step 11 entirely:

| Unprotected path | Why | Mitigation required (future step) |
|---|---|---|
| Direct cloud-provider SDK calls (`boto3`, `google-cloud-*`, `azure-*`) made by agent code | They never pass through a `ResourceConnector` | Run agent code in a mediated sandbox / egress proxy (Step 12) |
| Raw outbound HTTP from agent code (sockets, `requests`, `urllib`) | Not routed through `HttpApiConnector` | Egress gateway + DLP (Step 12) |
| Direct database connections with embedded credentials | The connector is a reference shell; no proxy | DB proxy / credential brokering |
| Direct filesystem writes / reads | No filesystem connector is wired to real I/O | Host-level sandbox or FUSE mediation |
| Process/shell execution outside the connector | `ShellConnector.perform` only returns a plan; it spawns nothing | Sandboxed executor with seccomp/cgroups |
| Calls to *tool implementations* that never consult `GovernanceService` | A tool that is not wrapped is simply not governed | Wrap all adapters; enforce by convention + review |

**No claim of universal enforcement is made.** Integration partners MUST route protected operations
through `GovernanceService.execute` (or a `GuardedConnector`); anything else is an unmediated path.

## 2. External systems keep their own permissions (integration boundary)

The guard proves that **an AgentGuard-governed agent is authorized to request** an operation. It does
NOT confer the target system's own authority. The database credential, cloud IAM role, HTTP API key
and SaaS tenant ACLs are still enforced by that external system — and must be granted separately,
with least privilege. Governance is the control plane for *who may ask*, not a replacement for the
target's access control.

## 3. In-process decision seal

The `avoid-forgery` seal is a **single-use, short-lived token held in an in-process ledger**
(`_SealLedger`), not a signed bearer token. It proves a decision was minted by *this* process and has
not been consumed. Therefore:

* A **remote client or SDK cannot forge or replay** a decision — this is the property that matters and
  it is tested (`test_enforce_requires_sealed_allow`, `test_concurrent_seal_consumption_is_single_use`).
* A caller that already has **code execution inside the trusted process** is out of scope for any
  in-process control; at that point policy enforcement, key protection and audit integrity all
  require process isolation, not a token.
* Seals do **not** survive a process restart or move across replicas (by design: a seal is consumed by
  the same process that minted it).

## 4. Risk signals are a stub

`NeutralRiskProvider` (Step 10) remains the risk source; governance escalation is **rule-based**
(destructive operation × sensitivity), not driven by a live behavioural risk score. Wiring a real risk
engine is Steps 14+ work. `request_context` carries `tool_risk` so a policy *can* act on risk now.

## 5. Approvals are minimal

Only `request / decide / check` exist — enough to gate a `REQUIRE_APPROVAL` decision. There is no
approval workflow engine, no multi-approver quorum, no escalation path, no expiry policy beyond what
the Step 10 store provides. **Step 17 owns the full approval system**; this step deliberately stops at
the integration interface.

## 6. Rego validation is a guard, not a sandbox

Policy source is validated (namespace, complete-rule shape, denylist of `http.send` /
`net.lookup_ip_addr` / `opa.runtime` / `trace` / `print`, size/bound limits). **OPA is the isolation
boundary.** Validation reduces the blast radius of a malicious policy author; it does not make it safe
to evaluate untrusted Rego. Policy authorship is an RBAC-controlled, audited privilege.

## 7. Registry reads are uncached (correct, but a per-decision DB read)

There is intentionally **no cross-request cache** of registry records: this is what guarantees no
stale ALLOW survives a registry change. The cost is one indexed primary-key read per decision. If this
becomes a bottleneck, add a bounded, generation-invalidated cache — **do not** relax the invalidation.

## 8. Reference connectors do not perform real I/O

`HttpApiConnector`, `DatabaseConnector` and `ShellConnector` return an *authorized plan*; they do not
issue network calls, execute SQL, or spawn processes. They exist to prove the enforcement shape. Real
transports (with DLP, egress control, sandboxing) are Step 12+.

## 9. SDK scope

Only the **Python** SDK is extended (registry-aware `ToolGuard`, governance client). The
TypeScript/Go/Rust SDKs remain at their Step 1–9 conformance level; server-side enforcement is
language-agnostic, but a governance *client* for those SDKs is future work.

## 10. Other deliberate properties

* **Platform administrators** may administer any tenant's registry (RBAC by design, audited). Tenant
  administrators are confined to their own tenant by both an explicit check and PostgreSQL RLS.
* **Registry writes are last-writer-wins** (a row-revision `version` is bumped, but there is no
  optimistic-concurrency precondition on update). Concurrent admin edits to one record can clobber;
  this is an availability concern, not an authorization one.
* **No signed bundles.** Policies and tool records are not distributed as signed artifacts; there is
  no signature verification of tool manifests (only a checksum is recorded).
* **No secrets are stored or logged** by the governance plane: resource/tool records hold logical ids
  and metadata only, and audit records carry ids, decisions and reason codes — never payloads.
