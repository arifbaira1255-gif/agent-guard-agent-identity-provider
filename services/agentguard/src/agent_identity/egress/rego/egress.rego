# AgentGuard Phase 4 — example EGRESS policy (Rego).
#
# This is a complete, working example of the egress policy contract. The egress gateway merges the
# destination + DLP context into `input.request_context` before consulting the Step 10 policy engine,
# so a policy can make decisions on the DESTINATION, the PROTOCOL, the ADDRESS CLASS and the DLP
# outcome — not just the raw action string.
#
# CONTRACT (identical to Steps 10/11; the engine namespaces the package per version):
#   * package MUST be `agentguard.authz`.
#   * a `decision` rule MUST return an object:
#         {"decision": "ALLOW"|"DENY"|"REQUIRE_APPROVAL", "reason": "...", "obligations": [...]}
#   * `INDETERMINATE` is produced by the ENGINE (timeout/outage/malformed), never by a policy.
#   * `decision` is a COMPLETE rule: use ONE `else` chain so exactly one output is produced.
#
# EGRESS INPUT (in addition to the Step 10/11 fields), under `input.request_context`:
#   request_context.destination, .host, .port, .protocol, .method,
#   request_context.resource_id, .operation,
#   request_context.dlp_outcome ("clean"|"redacted"|"block"|"require_approval"|"indeterminate"),
#   request_context.dlp_rule_ids[], .address_class
#
# IMPORTANT: this policy is a TIGHTENING-ONLY leg. The egress gateway already applies the SSRF
# address floor, the destination allowlist and the DLP pipeline BEFORE consulting this policy, and
# combines the results with DENY > INDETERMINATE > REQUIRE_APPROVAL > ALLOW. A policy ALLOW here can
# never loosen an egress DENY; a policy DENY here always tightens.
#
# Priority order (first match wins):
#   explicit deny > non-https > DLP block/indeterminate > DLP approval > sensitive destination
#   approval > default deny.

package agentguard.authz

decision := {"decision": "DENY", "reason": "explicitly_denied"} {
    some i
    input.denied_actions[i] == input.action
} else := {"decision": "DENY", "reason": "egress_plaintext_denied"} {
    input.request_context.protocol == "http"
} else := {"decision": "DENY", "reason": "egress_dlp_block"} {
    input.request_context.dlp_outcome == "block"
} else := {"decision": "DENY", "reason": "egress_dlp_indeterminate"} {
    input.request_context.dlp_outcome == "indeterminate"
} else := {"decision": "REQUIRE_APPROVAL", "reason": "egress_dlp_requires_approval"} {
    input.request_context.dlp_outcome == "require_approval"
    not input.approval.valid
} else := {"decision": "REQUIRE_APPROVAL", "reason": "egress_sensitive_destination"} {
    is_sensitive_destination(input.request_context.host)
    not input.approval.valid
} else := {"decision": "ALLOW", "reason": "egress_governed_grant"} {
    input.request_context.protocol == "https"
} else := {"decision": "DENY", "reason": "default_deny"}

# ---- helpers ---------------------------------------------------------------------------------
is_sensitive_destination(host) {
    sensitive := {"admin.internal", "billing.internal", "secrets.internal"}
    sensitive[host]
}
