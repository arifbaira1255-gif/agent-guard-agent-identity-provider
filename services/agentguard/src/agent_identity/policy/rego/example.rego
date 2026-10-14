# AgentGuard Step 10 — example policy (Rego).
#
# This is a complete, working example of the policy contract the engine expects. It is loaded by
# `opa eval` / `opa run` after the engine rewrites the package line to a per-version namespace
# (`agentguard.policies.<id>_v<version>`), so many policies coexist in one OPA instance.
#
# CONTRACT
#   * package MUST be `agentguard.authz` (the engine namespaces it).
#   * a `decision` rule MUST return an object:
#         {"decision": "ALLOW" | "DENY" | "REQUIRE_APPROVAL", "reason": "...", "obligations": [...]}
#   * `INDETERMINATE` is produced by the ENGINE (timeout/outage/malformed result), never by a policy.
#   * forbidden builtins (http.send, net.lookup_ip_addr, opa.runtime, trace, print) are rejected at
#     validation time.
#   * `decision` is a COMPLETE rule: use a single `else` chain (as below) so exactly one output is
#     produced. Multiple independent `decision := {...}` bodies would raise eval_conflict_error.
#
# INPUT (assembled server-side from verified state; a client can never supply these directly):
#   input.agent_id, input.instance_id, input.tenant, input.action, input.resource,
#   input.capabilities[], input.credential_status, input.environment, input.request_context,
#   input.risk{level,score,reasons}, input.jit_grants[], input.approval{valid,...},
#   input.policy_version, input.resource_tenant, input.denied_actions[],
#   input.approval_required_actions[], input.is_sub_agent, input.parent_agent_id

package agentguard.authz

# Priority order (first match wins): explicit deny > tenant boundary > invalid credential >
# critical risk > high risk (approval) > action-requires-approval > live JIT grant > capability
# match > read-only tool > default deny.
decision := {"decision": "DENY", "reason": "explicitly_denied"} {
    some i
    input.denied_actions[i] == input.action
} else := {"decision": "DENY", "reason": "tenant_boundary_violation"} {
    input.resource_tenant != ""
    input.resource_tenant != input.tenant
} else := {"decision": "DENY", "reason": "credential_not_valid"} {
    input.credential_status != "valid"
} else := {"decision": "DENY", "reason": "critical_risk"} {
    input.risk.level == "critical"
} else := {"decision": "REQUIRE_APPROVAL", "reason": "high_risk"} {
    input.risk.level == "high"
    not input.approval.valid
} else := {"decision": "REQUIRE_APPROVAL", "reason": "action_requires_approval"} {
    some i
    input.approval_required_actions[i] == input.action
    not input.approval.valid
} else := {"decision": "ALLOW", "reason": "jit_grant"} {
    some i
    g := input.jit_grants[i]
    g.action == input.action
    g.resource == input.resource
} else := {"decision": "ALLOW", "reason": "capability_match"} {
    some i
    input.capabilities[i] == input.action
} else := {"decision": "ALLOW", "reason": "read_only_tool"} {
    startswith(input.action, "tool:read")
} else := {"decision": "DENY", "reason": "default_deny"}
