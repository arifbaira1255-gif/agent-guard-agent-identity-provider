# Phase 7 — Compliance Control Mappings & Evidence Limitations

## 1. What this framework is

A configurable mapping from **implemented controls + collected evidence** to framework requirements.
Mappings are **data** (a built-in seed catalogue plus operator-supplied mappings), not hard-coded
claims. Reports are built from **actual system records**.

## 2. What this framework is NOT

> Generating a report is **NOT** a claim of certification or legal compliance. Framework mappings
> must be reviewed for the organization's actual scope and applicable obligations. The report itself
> states this in its `disclaimer` field.

## 3. Verification statuses (honest labelling)

| Status | Meaning |
|---|---|
| `implemented` | a technical control exists and is evidenced |
| `evidence_collected` | evidence gathered, control not fully verified |
| `organizational` | requires a human/process control, not code |
| `unverified` | claimed but not verified |
| `incomplete` | partially implemented / known gap |

## 4. Seed catalogue

| Framework | Control | Title | Status |
|---|---|---|---|
| SOC 2 | CC6.1 | Logical access controls | implemented |
| SOC 2 | CC6.6 | Boundary protection | implemented |
| SOC 2 | CC7.2 | Monitoring for anomalies | implemented |
| SOC 2 | CC7.3 | Incident response | implemented |
| SOC 2 | CC7.4 | Audit logging integrity | implemented (gap: truncation needs external anchoring) |
| SOC 2 | CC8.1 | Change management | implemented |
| ISO 27001 | A.5.15 | Access control | implemented |
| ISO 27001 | A.8.15 | Logging | implemented |
| ISO 27001 | A.8.16 | Monitoring activities | implemented |
| ISO 27001 | A.5.24 | Incident management | **organizational** (needs a process + owners) |
| GDPR | Art.5(1)(f) | Integrity and confidentiality | implemented |
| GDPR | Art.30 | Records of processing | **organizational** (needs a RoPA register) |
| GDPR | Art.32 | Security of processing | implemented |
| EU AI Act | Art.12 | Record-keeping | implemented |
| EU AI Act | Art.14 | Human oversight | implemented |
| EU AI Act | Art.15 | Accuracy, robustness, cybersecurity | **incomplete** (needs system-specific evaluation) |

Every `organizational` / `incomplete` control carries a non-empty `known_gaps` list.

## 5. Per-mapping record

`control_id`, `control_title`, `description`, `scope`, `evidence_source`, `evidence_ts`,
`provenance`, `owner_component`, `verification_status`, `known_gaps`, `last_review`, `next_review`,
`evidence_refs`.

## 6. Evidence provenance

Evidence is referenced, never copied: an evidence row stores a `ref` and a SHA-256 `digest` of the
referenced content, so an investigator can later prove the referenced material has not changed. The
report's `evidence_summary` counts real evidence by kind for the tenant.

## 7. Usage

```bash
# install the seed catalogue (idempotent)
curl -X POST /v1/admin/assurance/compliance/seed

# list controls (optionally by framework)
curl -s '/v1/assurance/compliance/controls?framework=soc2' | jq

# generate an evidence report
curl -s '/v1/assurance/compliance/report?framework=iso27001' | jq
```

## 8. Limitations

* The catalogue is a **starting point**; it must be reviewed and extended for the organization's
  actual scope, systems and obligations.
* `evidence_stale` flags evidence older than `compliance_evidence_stale_days` (default 90) — a stale
  flag is a prompt to re-collect, not a failure.
* The framework does not perform a conformity assessment, a legal review or a certification audit.
* EU AI Act applicability depends on the system's risk classification, which is an organizational
  determination.
