# Phase 7 — Security Limitations & Unverified Features

This document is deliberately blunt. It lists what Phase 7 does **not** guarantee, what is mocked or
stubbed, and what has **not** been verified in this environment.

## 1. Audit integrity is tamper-EVIDENT, not tamper-PROOF

* Hash chaining alone does **not** prevent every form of deletion or truncation, especially if an
  attacker controls all relevant storage and checkpoints.
* **Tail truncation is only detectable via a checkpoint.** A checkpoint stored in the same database as
  the chain provides no protection against an attacker who controls that database. Checkpoints must be
  exported/anchored **externally** to be meaningful.
* An attacker with the signing key can forge records. Key custody is the critical control.
* An attacker with DDL rights can disable the append-only trigger. The hash chain still detects the
  tamper (proven by `test_audit_chain_detects_tampering`), but the trigger itself is not a defence
  against a DDL-capable attacker.
* Do **not** describe this system as absolutely immutable or tamper-proof.

## 2. Row-Level Security requires a non-superuser role

PostgreSQL exempts `SUPERUSER` and `BYPASSRLS` roles from RLS. The application **must** connect as a
non-superuser role for tenant isolation to be enforced by the database. The application-level
`org_id=` filter is always applied as well, but RLS is the second line of defence and is only
effective for a non-superuser. The PG integration suite verifies RLS enforcement live as a
non-superuser role (`RlsEnforcementTests`).

## 3. Policy intelligence is heuristic, not omniscient

* The engine does **not** reliably infer every attack and does **not** discover perfect policies.
* Confidence is a documented heuristic over signal counts and severity, capped at 0.95.
* A repeated authorization denial is ambiguous (missing grant vs. probing) and is emitted as `review`
  unless corroborated by administrative feedback.
* The static security checks are **heuristic text checks** (regex over the Rego source). They catch
  common ways a change broadens privilege or disables a control; they are a guardrail, not a proof of
  safety. A change that passes them is not thereby proven safe.

## 4. Compliance is not certification

* Generating a report is **not** a claim of certification or legal compliance.
* The seed catalogue is a starting point and must be reviewed for the organization's actual scope.
* `organizational` and `incomplete` controls are labelled as such and carry known gaps.
* No conformity assessment, legal review or certification audit is performed.

## 5. SIEM vendor integrations are NOT verified against live endpoints

* The transports (`syslog_tls`, `syslog_tcp`, `http`, `splunk_hec`, `elastic_bulk`, `webhook`) are
  code-complete and unit-tested against a **fake transport**.
* There is **no** Splunk, Elastic or syslog server in this environment, so the live vendor interfaces
  are **unverified**. A vendor integration is only "production-ready" once tested against the actual
  supported interface or a clearly identified test environment.
* `syslog_tcp` is refused while `siem_require_tls` is set (the default).

## 6. Mocked / stubbed / unverified inventory

| Item | Status |
|---|---|
| `FakeTransport` | **test double** — used only in tests |
| `LocalEd25519Signer` | **development/test only** — refuses staging/production |
| `NullSigner` | **unsigned mode** — only when `audit_require_signature=False` (refused in production) |
| `MemoryAssuranceStore` | **dev/test only** — no durability, no cross-process sharing |
| Live Splunk HEC endpoint | **unverified** |
| Live Elastic `_bulk` endpoint | **unverified** |
| Live syslog (TLS/TCP) endpoint | **unverified** |
| Live generic webhook endpoint | **unverified** |
| KMS/HSM-backed audit signing | **interface-complete**; exercised in tests via the local signer, not against a real HSM |
| External checkpoint anchoring | **not implemented** — checkpoints are stored locally; external export is an operator responsibility |
| Retention enforcement (deletion) | **not implemented** — `audit_retention_days` is recorded but no purge job ships |
| Scheduled/background SIEM flush | **not implemented** — flush is invoked explicitly (API or caller) |
| Correlation is key-based | agent+category grouping over a bounded in-memory window; not a streaming engine |

## 7. Operational notes

* A SIEM outage does not stop the security plane (`siem_fail_closed=False`), but the failure is
  recorded and surfaced in `/v1/assurance/health` and the delivery table.
* The audit store **is** fail-closed (`audit_fail_closed=True`): a protected operation is refused when
  the audit store cannot be written.
* The SIEM queue and the correlation window are **in-process**; a multi-process deployment needs a
  shared queue (not shipped in this phase).

## 8. Not implemented in this phase (by design)

The next consolidated phase — Enterprise Dashboard, API, CLI, Observability and Developer Platform —
is **not** implemented here. This phase only prepares the repository for it.
