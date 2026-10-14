"""Step 7 metric names. Used with the existing thread-safe ``spiffe.metrics.Metrics`` registry.

No metric ever carries an identity, token, key or IP: only fixed names and a closed set of labels
(operation names, dependency names, job names).
"""

# --- idempotency
IDEM_NEW = "agentguard_idempotency_new_total"
IDEM_REPLAY = "agentguard_idempotency_replay_total"
IDEM_IN_PROGRESS = "agentguard_idempotency_in_progress_total"
IDEM_CONFLICT = "agentguard_idempotency_conflict_total"
IDEM_TAKEOVER = "agentguard_idempotency_takeover_total"

# --- request handling (per instance)
REQUEST_TOTAL = "agentguard_requests_total"
REQUEST_ERRORS = "agentguard_request_errors_total"
REQUEST_LATENCY = "agentguard_request_latency_seconds"

# --- credential operations
CREDENTIAL_OPS = "agentguard_credential_operations_total"

# --- dependency health / latency (PG + Redis already emit their own; these are the aggregate view)
DEPENDENCY_UP = "agentguard_dependency_up"
DEPENDENCY_LATENCY = "agentguard_dependency_latency_seconds"
DEPENDENCY_FAILURES = "agentguard_dependency_failures_total"

# --- reconciliation / coordination
RECONCILE_RUNS = "agentguard_reconciliation_runs_total"
RECONCILE_DRIFT = "agentguard_reconciliation_drift_total"
