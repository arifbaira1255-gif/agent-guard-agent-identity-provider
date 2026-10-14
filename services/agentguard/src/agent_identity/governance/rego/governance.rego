# AgentGuard Step 11 — example GOVERNANCE policy (Rego).
#
# This is a complete, working example of the governance policy contract. The registry context is
# merged into `input.request_context` by `ResourceGuard`, so a policy can make decisions on the
# resource TYPE, its SENSITIVITY and the OPERATION being requested — not just the raw action string.
#
# CONTRACT (identical to Step 10; the engine namespaces the package per version):
#   * package MUST be `agentguard.authz`.
#   * a `decision` rule MUST return an object:
#         {"decision": "ALLOW"|"DENY"|"REQUIRE_APPROVAL", "reason": "...", "obligations": [...]}
#   * `INDETERMINATE` is produced by the ENGINE (timeout/outage/malformed), never by a policy.
#   * `decision` is a COMPLETE rule: use ONE `else` chain so exactly one output is produced.
#
# GOVERNANCE INPUT (in addition to the Step 10 fields), under `input.request_context`:
#   request_context.resource_id, .operation, .resource_type, .sensitivity, .registry_status,
#   .permitted_operations[], .tool_id, .tool_risk, .approved_capabilities[], .claimed_capabilities[]
#
# Priority order (first match wins):
#   explicit deny > tenant boundary > invalid credential > restricted+destructive approval >
#   high risk approval > sensitive writes approval > shell/cloud execute approval > capability match >
#   read-only operation allow > default deny.

package agentguard.authz

decision := {"decision": "DENY", "reason": "explicitly_denied"} {
    some i
    input.denied_actions[i] == input.action
} else := {"decision": "DENY", "reason": "tenant_boundary_violation"} {
    input.resource_tenant != ""
    input.resource_tenant != input.tenant
} else := {"decision": "DENY", "reason": "credential_not_valid"} {
    input.credential_status != "valid"
} else := {"decision": "DENY", "reason": "unclassified_resource"} {
    input.request_context.registry_status != "registered"
} else := {"decision": "REQUIRE_APPROVAL", "reason": "restricted_destructive_operation"} {
    input.request_context.sensitivity == "restricted"
    is_destructive(input.request_context.operation)
    not input.approval.valid
} else := {"decision": "REQUIRE_APPROVAL", "reason": "confidential_write_requires_approval"} {
    input.request_context.sensitivity == "confidential"
    is_write(input.request_context.operation)
    not input.approval.valid
} else := {"decision": "REQUIRE_APPROVAL", "reason": "cloud_or_shell_execution"} {
    in_execution_surface(input.request_context.resource_type)
    not input.approval.valid
} else := {"decision": "REQUIRE_APPROVAL", "reason": "high_risk"} {
    input.risk.level == "high"
    not input.approval.valid
} else := {"decision": "DENY", "reason": "operation_not_permitted"} {
    not permitted(input.request_context.operation, input.request_context.permitted_operations)
} else := {"decision": "ALLOW", "reason": "governed_grant"} {
    is_read_only(input.request_context.operation)
} else := {"decision": "ALLOW", "reason": "capability_match"} {
    some i
    input.capabilities[i] == input.action
} else := {"decision": "DENY", "reason": "default_deny"}

# ---- helpers ---------------------------------------------------------------------------------
is_destructive(op) {
    destructive := {"delete", "admin", "deploy", "execute"}
    destructive[op]
}

is_write(op) {
    writes := {"write", "create", "update", "delete", "admin", "deploy", "execute", "send"}
    writes[op]
}

is_read_only(op) {
    reads := {"read", "list", "connect"}
    reads[op]
}

in_execution_surface(t) {
    surfaces := {"shell", "cloud"}
    surfaces[t]
}

permitted(op, ops) {
    some i
    ops[i] == op
}
