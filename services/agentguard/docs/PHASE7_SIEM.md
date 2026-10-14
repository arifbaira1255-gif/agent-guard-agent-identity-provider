# Phase 7 — SIEM Configuration & Integration

## 1. Supported transports

| Kind | Transport | TLS |
|---|---|---|
| `syslog_tls` | RFC 5424 over TLS (preferred) | required, verified |
| `syslog_tcp` | RFC 5424 over plain TCP | refused while `siem_require_tls` is set |
| `http` | generic JSON over HTTPS | required, verified |
| `splunk_hec` | Splunk HTTP Event Collector | required, verified |
| `elastic_bulk` | Elasticsearch `_bulk` NDJSON | required, verified |
| `webhook` | generic signed JSON webhook | required, verified |

## 2. Guarantees

* **TLS verification** is enforced (`siem_require_tls`, `siem_verify_tls`); a plaintext transport is
  refused in production.
* **Credentials never appear in logs**: a closed set of field names is redacted, and any value that
  looks like a secret (a bearer token, a PEM header, a long opaque string) is redacted too. The
  destination's secret material is never logged.
* **Tenant + classification controls before export**: an event whose classification is not in
  `siem_allowed_classifications` is suppressed and **recorded** (never silently dropped).
* **Bounded retries** with exponential backoff + jitter; exhaustion dead-letters the event.
* **Rate limiting** per destination; a rate-limited pass re-queues rather than dropping.
* **Batching** up to `siem_batch_max` events per request.
* **Backpressure**: `reject` (fail closed, surfaced) or `drop_oldest` (explicit, recorded).
* **Delivery status** per (destination, event) — a failure is visible, never silent.
* A SIEM outage does **not** stop the security plane; the failure is recorded and surfaced.

## 3. Event schema

```json
{
  "event_id": "sev_...",
  "ts": "2026-10-12T08:10:04Z",
  "severity": "high",
  "category": "policy",
  "action": "deny",
  "outcome": "denied",
  "source": "policy",
  "dedup_key": "…",
  "classification": "internal",
  "provenance": "observed_fact",
  "org_id": "acme",
  "correlation_id": "cor_...",
  "agent_id": "a1",
  "incident_id": "inc_...",
  "policy_id": "pol_...",
  "policy_version": "3",
  "fields": { "…": "redacted projection" }
}
```

Severity is normalized into the closed set `info|low|medium|high|critical` (unknown → `medium`).
`provenance` distinguishes an **original** evidence event (`observed_fact`) from a **derived**
analytics event (`derived`), so a consumer never mistakes a correlation output for primary evidence.

## 4. Configuration

| Env var | Default | Effect |
|---|---|---|
| `AGENTGUARD_ASSURANCE_SIEM_REQUIRE_TLS` | true | refuse plaintext transports |
| `AGENTGUARD_ASSURANCE_SIEM_VERIFY_TLS` | true | verify the server certificate |
| `AGENTGUARD_ASSURANCE_SIEM_QUEUE_MAX` | 10000 | bounded queue (backpressure boundary) |
| `AGENTGUARD_ASSURANCE_SIEM_BACKPRESSURE` | reject | `reject` or `drop_oldest` |
| `AGENTGUARD_ASSURANCE_SIEM_MAX_RETRIES` | 5 | bounded retry attempts |
| `AGENTGUARD_ASSURANCE_SIEM_RETRY_BACKOFF_S` | 0.5 | initial backoff (exponential + jitter) |
| `AGENTGUARD_ASSURANCE_SIEM_RETRY_BACKOFF_MAX_S` | 30 | backoff ceiling |
| `AGENTGUARD_ASSURANCE_SIEM_TIMEOUT_S` | 10 | per-request timeout |
| `AGENTGUARD_ASSURANCE_SIEM_BATCH_MAX` | 500 | max events per batch |
| `AGENTGUARD_ASSURANCE_SIEM_RATE_LIMIT_PER_S` | 200 | per-destination rate limit (0 = unlimited) |
| `AGENTGUARD_ASSURANCE_SIEM_FAIL_CLOSED` | false | raise on backpressure instead of recording |
| `AGENTGUARD_ASSURANCE_SIEM_ALLOWED_CLASSIFICATIONS` | public,internal,confidential | exportable classifications |

## 5. Registering a destination (code)

```python
from agent_identity.assurance import AssuranceService, MemoryAssuranceStore, AssuranceConfig, build_transport

cfg = AssuranceConfig(environment="production")
svc = AssuranceService(MemoryAssuranceStore(), config=cfg)

# Splunk HEC
t = build_transport("splunk_hec", config=cfg,
                    url="https://splunk.example:8088/services/collector/event",
                    token="<HEC token>")
svc.siem.register_destination("splunk-prod", t, org_id="acme", min_severity="medium")

# Elastic
t2 = build_transport("elastic_bulk", config=cfg,
                     url="https://elastic.example:9200", index="agentguard", token="<api key>")
svc.siem.register_destination("elastic-prod", t2, org_id="acme")

# Syslog over TLS
t3 = build_transport("syslog_tls", config=cfg, host="syslog.example", port=6514,
                     ca_cert="/etc/ssl/certs/ca.pem")
svc.siem.register_destination("syslog-prod", t3, org_id="acme")
```

## 6. Operations

```bash
# ingest an event (normalize -> dedup -> enqueue)
curl -X POST /v1/admin/assurance/siem/events -d '{"event":{"category":"policy","action":"deny",
  "outcome":"denied","source":"policy","severity":"high","agent_id":"a1"}}'

# flush the queue (batch + retry)
curl -X POST /v1/admin/assurance/siem/flush

# inspect destinations and delivery status
curl -s /v1/assurance/siem/destinations | jq
curl -s '/v1/assurance/siem/deliveries?status=dead_letter' | jq

# health (queue depth, per-destination health, metrics)
curl -s /v1/assurance/health | jq
```

## 7. Verification status — read this before claiming a vendor integration works

The transports are **code-complete and unit-tested against a fake transport** (retry, backoff,
dead-letter, backpressure, redaction, classification gate, dedup). The **live vendor endpoints are
NOT verified in this environment** — there is no Splunk/Elastic/syslog server here. A vendor
integration is only "production-ready" once it has been tested against the actual supported
interface or a clearly identified test environment. See `PHASE7_SECURITY_LIMITATIONS.md`.
