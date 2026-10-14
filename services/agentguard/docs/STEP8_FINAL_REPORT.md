# AgentGuard — Step 8 Final Report
## Enterprise Authentication, RBAC & Multi-Tenancy

*Repository:* `agentguard_v2` (continuation of the Step 7 archive; Step 8 only, Steps 1–7 untouched in
behaviour)
*Schema version:* **v4** (`0004_step8_enterprise_auth.sql`)
*Test result:* **567 tests, 0 failures, 0 errors, 12 skipped** (Docker-gated Step 7 SPIRE tests)

---

## (1) Existing components reused

| Reused | How |
|---|---|
| `storage/postgres/db.py` `Database` | Added a `tenant_scope()` context manager that sets RLS session vars; same pooling/retry/readiness |
| `storage/postgres/migrate.py` | Step 8 migration is one more checksummed, forward-only file; no new mechanism |
| `storage/postgres/repos.py` `Repository` base | Step 8 repos follow the same constant-SQL + bound-param pattern |
| `state/backend.py`, `state/redis_backend.py` | Permission cache, OIDC transaction/nonce store, rate limiter |
| `state/ratelimit.py` | Login throttling token bucket |
| `observability/logging.py` `SecurityLogger` | Same redaction allow-list + correlation ids; extended with non-secret Step 8 fields only |
| `core/errors.py`, `core/clock.py`, `core/validation.py`, `core/models.iso` | Error taxonomy, injectable clock, email/identifier validation |
| `spiffe/`, `mtls/` (Steps 1–7) | **Untouched** — machine identity plane remains separate |
| `tests/helpers.py`, `tests/state_contract.py`, `tests/test_security_pg.py` conventions | Same PG/Redis test environment and contract tests |

## (2) Files created and modified

**Created — security package** (`src/agent_identity/security/`):
`__init__.py`, `models.py`, `config.py`, `passwords.py`, `tokens.py`, `rbac.py`, `session_manager.py`,
`oidc.py`, `auth_service.py`, `admin_ops.py`, `audit.py`, `store.py`, `memory_store.py`,
`permission_cache.py`, `redis_keys.py`, `ids.py`.

**Created — storage / api:**
`storage/postgres/enterprise.py` (PostgreSQL `EnterpriseStore`),
`storage/postgres/migrations/0004_step8_enterprise_auth.sql`,
`api/enterprise_http.py` (RBAC-gated routes, secure cookies, CSRF).

**Created — tests & docs:**
`tests/test_security_unit.py` (58 unit tests), `tests/test_security_pg.py` (24 real PG+Redis tests),
`docs/STEP8_AUTHENTICATION.md`, `docs/STEP8_RBAC.md`, `docs/STEP8_TENANT_ISOLATION.md`,
`docs/STEP8_ADMINISTRATION.md`, `docs/STEP8_SECURITY_LIMITATIONS.md`, this report.

**Modified:**
`core/errors.py` (+`AuthenticationError`, `ForbiddenError`, `CsrfError`),
`observability/logging.py` (allow-list += Step 8 non-secret fields),
`storage/postgres/db.py` (tenant/RLS scope), `tests/test_pg_integration.py`,
`tests/test_pg_unit.py` (bug fixes — see §7).

## (3) Authentication mechanisms actually implemented

* **Local**: scrypt password hashing, constant-time verify, account locking, Redis rate limiting,
  generic failure (no enumeration).
* **OIDC SSO**: authorization-code + PKCE (S256); `state` (single-use) + `nonce` + `azp` checks; issuer and
  audience exact match; signature via cached JWKS with refetch-on-miss; `exp`/`iat`/`nbf` against the
  injected clock; just-in-time provisioning keyed by `sub`.
* **Sessions/tokens**: HMAC-SHA256 short-lived access tokens; rotating refresh tokens with replay
  detection + family revocation; idle & absolute expiry; logout/revocation; secure cookies; CSRF.

## (4) RBAC roles and permissions

Six roles — Platform Administrator, Tenant Administrator, Security Analyst, Security Operator, Developer,
Read-Only Auditor — over a 25-permission catalogue, with **explicit deny** subtractive overrides and
**least privilege** sets. Full matrix in `docs/STEP8_RBAC.md`. Enforcement is server-side in
`EnterpriseAuthService.authorize`, called by every protected route and admin operation.

## (5) Tenant isolation enforcement

* Tenant identity derived **only** from the verified session, never from request input.
* Application-scoped queries + explicit `org_id` filters on every tenant query.
* **PostgreSQL RLS** on tenant tables; **proven** in-suite by a non-owner `NOSUPERUSER` login that sees
  only its own tenant and nothing when the scope is unset (fail-closed).
* Constraints/FKs prevent orphaned cross-tenant rows; UUID ids + not-found semantics defeat id guessing.
* Redis keys namespaced per tenant; PostgreSQL authoritative; cache invalidated on role changes.

## (6) API endpoints protected

| Method & path | AuthN | AuthZ (permission) |
|---|---|---|
| `POST /v1/auth/login` | none (rate-limited, CSRF-exempt) | — |
| `GET /v1/auth/oidc/{org}/start` | none | valid tenant + IdP config |
| `GET /v1/auth/oidc/callback` | IdP id_token | `state`/`nonce`/`azp`/iss/aud |
| `POST /v1/auth/logout` | session | CSRF |
| `POST /v1/auth/refresh` | refresh token | rotation + replay detection |
| `GET /v1/auth/me` | session | — |
| `GET /v1/tenants` | session | `tenant:read` (platform: all) |
| `POST /v1/tenants` | session | `tenant:create` (platform) |
| `GET /v1/users`, `POST /v1/users`, `PATCH /v1/users/{id}` | session | `user:read` / `user:write` (+scope) |
| `POST /v1/users/{id}/suspend`, `/activate` | session | `user:write` + guards |
| `POST /v1/memberships`, `DELETE /v1/memberships` | session | `membership:write` + `role:assign` |
| `POST /v1/roles/assign` | session | `role:assign` + no-escalation guard |
| `POST /v1/sessions/revoke` | session | `session:revoke` |
| `GET /v1/audit` | session | `audit:read` (tenant-scoped) |
| `GET/POST /v1/idp-configs` | session | `idp:read` / `idp:write` |

All protected routes verify authn → authz → tenant scope → input validation, and return **safe generic
errors**. Internal admin endpoints are not exposed; each route requires the specific permission.

## (7) Security and regression test results

```
Ran 567 tests in 61.967s
OK (skipped=12)
```

* **58** Step 8 unit tests (passwords, tokens, RBAC matrix + explicit deny, session idle/absolute expiry,
  refresh rotation + replay, OIDC validation incl. bad signature/issuer/audience/`azp`/expired/`none` alg/
  nonce mismatch/state replay, admin escalation guards, CSRF).
* **24** real **PostgreSQL + Redis** security tests, including the **negative** cases: cross-tenant reads,
  RLS at the DB level (non-owner login), privilege-escalation attempts, suspended-account login, token
  replay, refresh-token reuse, and CSRF. All adversarial assertions expect **failure**.
* **3 pre-existing failures fixed** (§7a) — suite is now **0 failing**.
* **12 skipped**: Step 7 SPIRE/mTLS integration tests (require a Docker host; Docker unavailable here).

### (7a) Bugs found and fixed during Step 8

1. **`tests/test_pg_integration.Migrations` hardcoded “exactly 1 migration”** — stale test expectation
   (broken since migrations 2–3 were added), not an infra issue. Made generic over `load_migrations()`.
2. **`test_service_refuses_unmigrated_database` cross-test contamination** — it asserted against a shared
   class database that a sibling test migrates. Switched to a dedicated, never-migrated database.
3. **OIDC temporal checks ran against wall-clock**, not the injected clock (`PyJWT`). Moved `exp/nbf/iat`
   validation into the module and disabled PyJWT's clock-dependent checks, so expiry is clock-injectable.
4. **Schema-hygiene guard flagged legitimate columns** — the Step 7 substring check rejected
   `password_hash`/`client_secret_encrypted`. Made the guard identifier-exact (still rejects literal
   `password`/`secret`/`private_key` columns).
5. Two small **syntax** defects in the new store (`count_platform_admins`, `revoke_session_refresh`)
   caught by the import smoke test.

## (8) External identity-provider setup still required

OIDC issuer URL, `client_id`, `client_secret` (stored encrypted via KMS), registered redirect URI
`/v1/auth/oidc/callback`, scopes (`openid email profile`), reachable `jwks_uri`, and production TLS trust.
SAML/SCIM are **not** implemented. Details in `docs/STEP8_SECURITY_LIMITATIONS.md` §2.

## (9) Known limitations

No password self-service/reset flow; no mandatory MFA/step-up; SAML & SCIM not implemented; in-memory
store is dev/test only; per-account lockout (not WAF-grade); 12 SPIRE/mTLS tests skipped (Docker host
required). Full list in `docs/STEP8_SECURITY_LIMITATIONS.md` §4.

## (10) Integration boundary for Step 9 — Universal Agent SDK Productionization

Step 9 should consume these **stable seams** (no Step 8 rewrite needed):

* **AuthN**: `EnterpriseAuthService.login/local + oidc`, `SessionManager.create/resolve/refresh/revoke`,
  `TokenSigner` — the SDK authenticates as a user principal by presenting an access token.
* **AuthZ**: `EnterpriseAuthService.authorize(principal, org_id, required={...})` and
  `rbac.effective_access()` — the SDK must call this before each privileged agent operation.
* **Tenant context**: `Database.tenant_scope(org_id, platform_admin, user_id)` — wrap every SDK DB unit of
  work; the SDK must never accept `org_id` from an untrusted field.
* **Audit**: `security.audit.AuditLog` — SDK operations emit audit events with the same correlation id.
* **Config**: `security/config.EnterpriseAuthConfig` — the SDK inherits the same fail-closed validation.
* The SDK’s agent-to-agent calls continue to ride the **Step 1–7 mTLS/SPIFFE** plane; its *human* callers
  ride Step 8. Keep the two planes separate.
