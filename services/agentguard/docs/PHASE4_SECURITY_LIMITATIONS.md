# AgentGuard Phase 4 — Security Limitations, Bypass Paths & Deployment Requirements

This document is the **honest** companion to `PHASE4_ARCHITECTURE.md`. It states exactly what Phase 4
enforces, what it does **not** enforce, the bypass paths that remain, and the external infrastructure
required to close them. Nothing here is a claim of universal network enforcement.

---

## 1. What Phase 4 enforces (verified by tests)

| Control | Enforced at | Verified by |
|---|---|---|
| Destination allowlist / deny rules (host, protocol, port) | `SecureEgressGateway.decide` | `test_egress_unit.DestinationPolicyTests`, `GatewayDecisionTests` |
| SSRF floor: private / loopback / link-local / cloud-metadata / CGNAT / multicast / reserved / unspecified | `egress/addresses.py` | `AddressClassificationTests`, `AddressPolicyTests` |
| DNS resolution validation + DNS-rebinding protection (mixed answer = hostile) | `egress/addresses.py` | `AddressPolicyTests.test_dns_rebinding_mixed_answer_is_hostile` |
| Redirect re-validation (each hop) | `SecureEgressGateway._execute` | `RedirectBypassTests` |
| Request/response size + timeout limits | `egress/config.py`, `gateway.py` | `GatewayDecisionTests.test_oversized_request_denied` |
| Connection/request rate limiting (tenant+agent) | `egress/ratelimit.py` | `RateLimiterTests`, `GatewayDecisionTests.test_rate_limited` |
| DLP detection (API keys, credentials, PII, financial, enterprise, org-specific) | `egress/dlp.py` | `DlpTests` |
| DLP redaction / block / approval | `egress/dlp.py`, `gateway.py` | `DlpTests`, `GatewayDecisionTests` |
| Fail-closed on policy/DLP/gateway failure | `gateway.py` | `GatewayDecisionTests`, `AddressPolicyTests.test_resolution_failure_fails_closed` |
| Two-leg enforcement (governance AND egress) | `governance/guard.py` | `test_egress_guard_integration` |
| Cross-tenant isolation (RLS) | migration 0007 | `test_egress_pg_integration.test_rls_blocks_cross_tenant_reads_for_non_superuser` |
| Append-only audit | migration 0007 trigger | `test_egress_pg_integration.test_audit_append_only` |
| No stale allow after a policy change | authoritative per-decision read | `test_egress_pg_integration.test_gateway_allow_then_deny_after_policy_change` |

---

## 2. What Phase 4 does NOT enforce (application-level boundary)

Phase 4 governs outbound traffic **that is routed through it**. It is an application-level control.
It does **not** transparently intercept all machine traffic. Specifically:

1. **A process that opens a raw socket directly bypasses the gateway.** If an agent runtime, a
   dependency, or a subprocess calls `socket.connect()` / `requests.get()` / `curl` without going
   through `SecureEgressGateway` or `GuardedEgressConnector`, Phase 4 does not see it. Closing this
   requires OS/container/network enforcement (see §4).
2. **DNS is validated at decision time, not at connect time by the kernel.** The gateway pins the
   connection to the validated address set, which defeats rebinding *for requests it carries*. A
   process that resolves and connects itself is not covered.
3. **DLP is pattern + context based, not semantic.** It cannot understand meaning. It will have
   false positives (a test card number, a documentation example) and false negatives (a secret in an
   unexpected format, a novel credential type).
4. **Encoded payloads are decoded once.** Base64 / percent / hex are decoded a single round and
   re-scanned. Multiply-encoded or custom-encoded content may evade detection. This is stated, not
   claimed away.
5. **Oversized payloads are not silently passed** — they are reported `INDETERMINATE` and the
   configured failure action (block by default) applies. But a payload just under the ceiling that
   contains a secret beyond the inspected region is not detected.
6. **The decision seal is in-process, not a signed token.** It proves a decision was produced by the
   server process and is single-use. It is not cryptographically signed; forging one would require
   code execution inside the trusted process, at which point no in-process control is meaningful.
   The property that matters — an SDK, tool adapter, or remote caller cannot fabricate or replay one
   — holds and is tested.
7. **The in-process rate limiter is single-node.** For a multi-replica deployment the shared limiter
   must be the existing Redis-backed state layer; the in-process limiter is the single-node
   implementation and the fallback.

---

## 3. Unsupported bypass paths (explicitly listed)

| Bypass path | Covered? | Mitigation |
|---|---|---|
| Direct raw socket / `requests` / `curl` from agent code | ❌ | network namespace / egress proxy / firewall (§4) |
| Subprocess spawning its own network client | ❌ | seccomp / network policy / no-network sandbox |
| DNS rebinding on a request the gateway carries | ✅ | resolve-once + pin + mixed-answer-is-hostile |
| Redirect to a private/metadata address | ✅ | per-hop re-validation |
| Redirect to a non-allowlisted host | ✅ | per-hop destination policy |
| Cloud metadata via hostname (`metadata.google.internal`) | ✅ | explicit metadata-host deny |
| Cloud metadata via literal IP (`169.254.169.254`) | ✅ | address-class deny |
| Cross-tenant policy read/write | ✅ | explicit org filter + RLS |
| Forged / replayed decision seal | ✅ | single-use, short-TTL, in-process ledger |
| Stale allow after a policy change | ✅ | authoritative per-decision read (no cache) |
| Multiply-encoded secret | ⚠️ partial | one decode round only |
| Secret in an unexpected format | ⚠️ partial | pattern-based; add an org-specific rule |
| Payload just under the DLP ceiling with a secret beyond the inspected region | ⚠️ partial | raise `AGENTGUARD_DLP_MAX_INSPECT_BYTES` or lower the request ceiling |

---

## 4. Deployment requirements for transparent interception

To move from *application-level* to *transparent* enforcement, the following external infrastructure
is required. **Phase 4 does not configure these; it documents them.**

### 4.1 Network namespace / egress proxy (recommended)

Run the agent runtime in a network namespace whose only route out is the egress proxy, and have the
proxy enforce the same policy set:

```bash
# illustrative — adapt to your orchestrator
ip netns add agentguard
ip netns exec agentguard ip link set lo up
# route all egress through the proxy; deny direct routes
ip netns exec agentguard ip route add default via <proxy-ip>
```

The proxy should call the same `SecureEgressGateway.decide` contract (or a sidecar that does) so the
policy set is single-sourced.

### 4.2 Kubernetes NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: agentguard-egress }
spec:
  podSelector: { matchLabels: { app: agent-runtime } }
  policyTypes: [Egress]
  egress:
    - to: [{ podSelector: { matchLabels: { app: agentguard-egress-proxy } } }]
      ports: [{ protocol: TCP, port: 8443 }]
```

### 4.3 Firewall / security group

Deny all egress from the agent subnet except to the egress proxy, and deny the cloud metadata
endpoint (`169.254.169.254`) at the network layer as defence in depth.

### 4.4 TLS

The egress proxy should terminate or pass through TLS with a pinned CA. Phase 4's
`EgressHttpConnector` uses the system trust store by default; a deployment may inject an mTLS-aware
transport as long as it honours the `send(...)` contract (bounded timeout, response-size cap, no
automatic redirects).

---

## 5. Manual setup checklist

- [ ] Apply migration 0007 (`python -m agent_identity.storage.postgres.migrate`).
- [ ] Connect the application as a **least-privilege, non-superuser** role (RLS does not apply to
      superusers or the table owner — the RLS test provisions exactly such a role to prove it).
- [ ] Set `AGENTGUARD_ENV=production` and review every `AGENTGUARD_EGRESS_*` / `AGENTGUARD_DLP_*`
      value for your environment.
- [ ] Register the tenant egress policies (allowlist the destinations agents legitimately need).
- [ ] Bind the egress service into `GovernanceService(..., egress=...)` and route outbound calls
      through `ResourceGuard.authorize_egress_with_run` / `GuardedEgressConnector`.
- [ ] Deploy the network-layer controls in §4 if transparent interception is required.
- [ ] Wire `EgressService.metrics()` into your observability stack.
- [ ] Add org-specific DLP rules for your credential formats.

---

## 6. Prioritized remaining work

1. **Transparent interception** — deploy the network namespace / proxy / NetworkPolicy controls in
   §4 and single-source the policy set between the proxy and the gateway.
2. **Shared rate limiter** — back `RateLimiter` with the existing Redis state layer for multi-replica
   deployments.
3. **Multi-round decoding** — extend DLP to decode nested encodings (bounded) to close the
   multiply-encoded gap.
4. **Semantic DLP** — add an optional classifier leg for high-value payloads (clearly labelled as
   best-effort, not a guarantee).
5. **Signed decision tokens** — replace the in-process seal with a signed, verifiable token if
   decisions must cross a process boundary.
6. **Go / Rust / TypeScript SDK parity** — mirror `governed_request` / `require_egress` in the other
   SDKs (the Python SDK is done; the others are optional polish).
7. **Phase 5** — Runtime Monitoring, Agent Behavior Analytics, Intent Graph and Agentic Drift
   Detection (see the boundary section in `PHASE4_ARCHITECTURE.md`).
