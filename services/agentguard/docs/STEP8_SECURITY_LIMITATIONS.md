# Step 8 — Security Limitations & Production Deployment Requirements

> This section states plainly what is **implemented and tested**, what is **implemented but requires
> external setup**, and what is **not implemented**. Nothing here is claimed as production-ready unless it
> is on this list with its dependency named.

## 1. Implemented and verified (tested against real PostgreSQL + Redis)

* Local password authentication (scrypt), lockout, timing-equalised unknown-user path.
* OIDC authorization-code + PKCE flow with issuer/audience/`azp`/signature/`exp`/`nonce`/`state`
  validation, single-use state, JWKS caching with one refetch on key miss.
* Session lifecycle: short-lived access tokens, refresh-token rotation, replay detection with family
  revocation, idle + absolute expiry, logout/revocation.
* RBAC: 6 roles, explicit deny, least privilege, server-side enforcement on every protected route.
* Tenant isolation: verified tenant context, app-scoped queries, PostgreSQL RLS (proven with a non-owner
  login), constraints/FKs, Redis key namespacing.
* Administrative operations incl. the two escalation guards, with audit events.
* Durable, append-only audit log; redaction of secrets via the existing `SecurityLogger` allow-list.

## 2. External identity-provider setup still required

| Item | Required for | Notes |
|---|---|---|
| OIDC **issuer URL** per tenant | SSO login | e.g. `https://idp.example.com/realms/acme` |
| **client_id** + **client_secret** | SSO login | secret stored via `client_secret_encrypted`; supplied by a KMS/secret manager |
| **Redirect URI** registered at the IdP | SSO callback | `https://<host>/v1/auth/oidc/callback` |
| **Scopes/claims** (`openid email profile`) | identity mapping | `sub` is the stable key |
| **JWKS reachability** | token verification | the RP caches keys; the IdP must publish `jwks_uri` |
| **TLS trust** for IdP + RP | anything in production | no dev certs in prod |

SAML 2.0 and SCIM are **not implemented** (see §4).

## 3. Production deployment requirements

1. **TLS everywhere.** Terminate HTTPS at the ingress; set `cookie_secure=True` (the config **refuses** to
   start in `production` with `cookie_secure=False` or with a default/absent `session_secret`).
2. **Non-owner DB role.** The application must connect as a role that does **not** own the Step 8 tables
   and has neither `SUPERUSER` nor `BYPASSRLS`, otherwise PostgreSQL exempts it from RLS. Grant only
   `SELECT/INSERT/UPDATE/DELETE` on the tenant tables (plus sequence usage).
3. **Separate Redis.** Redis holds the permission cache, login transactions, nonce replay guard and rate
   limiter. Use a dedicated logical DB/instance, authentication on, and TLS if remote. Redis is **never**
   authoritative for permissions.
4. **Secret material.** `session_secret` (HS256 signing key) and IdP client secrets must come from a
   secret manager / KMS, rotated on schedule. The config fails closed if they are missing in production.
5. **Clock discipline.** Access/refresh/session expiries and OIDC `exp` are enforced against an injectable
   clock; production must run NTP-synchronised hosts (a skewed host weakens expiry checks by the skew).
6. **Backups & restore.** `users`, `tenant_memberships`, `sessions`, `refresh_tokens`, `idp_configs` and
   `audit_events` are in PostgreSQL and covered by the standard backup/restore runbook. After a restore,
   **revoke all sessions** (they may be older than the point of compromise) and rotate `session_secret`.

## 4. Known limitations (explicit)

* **No password self-service / reset email flow** in Step 8. Password changes are administrative (or via
  the IdP for SSO users). A reset-token flow is a candidate for a later step.
* **No mandatory MFA / step-up authentication** yet. The IdP can enforce MFA for SSO users; local logins
  have no second factor. This is a deliberate, documented gap.
* **SAML 2.0 and SCIM 2.0 provisioning are not implemented** and are not represented as working.
* **The permission cache is process-local in the in-memory store** (the PostgreSQL + Redis path is the
  production path). The in-memory store is for unit tests/dev only.
* **Account lockout is per-account** (not per-IP reputation); IP-based abuse is mitigated by the Redis
  rate limiter, not a full WAF.
* **12 SPIRE/mTLS integration tests remain skipped** in this environment. They require a **Docker host**
  running `integration/spire/run.sh` (docker compose up spire-server + spire-agent). Docker is **not
  available** in the build sandbox, so these Step 7 tests could not be executed here and are unchanged by
  Step 8. They are the *only* skipped tests; all Step 8 security tests run for real against PostgreSQL and
  Redis.

## 5. Threat-model notes

* Tokens are **signed** (HMAC-SHA256), not encrypted — do not place secrets inside claims.
* Access tokens are short-lived and revocable via the session row; a stolen access token is bounded by
  `access_ttl_s` and dies on logout/revocation.
* The generic `authentication_failed` error and constant-shape lookup prevent user enumeration.
* CSRF is enforced for cookie-authenticated mutations; bearer-token clients are unaffected.
