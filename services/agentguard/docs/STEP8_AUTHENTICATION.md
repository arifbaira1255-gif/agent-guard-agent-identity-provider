# Step 8 — Enterprise Authentication Architecture

> Scope: Step 8 adds the **human/enterprise identity plane** (users, sessions, SSO, RBAC,
> multi-tenancy) on top of the machine-identity plane delivered in Steps 1–7. It reuses the
> existing PostgreSQL storage, Redis state backend, audit/correlation architecture and mTLS/spiffe
> identity boundary; it does not rebuild them.

## 1. Two identity planes (do not conflate)

| Plane | Who | Mechanism | Where |
|---|---|---|---|
| **Machine / workload** | Agents, sub-agents, services | SPIFFE SVIDs + mTLS (Steps 1–7) | `src/agent_identity/spiffe/`, `mtls/` |
| **Enterprise / human** | Operators, admins, auditors | Local credentials **+ OIDC SSO**, sessions | `src/agent_identity/security/` (Step 8) |

The two planes share the audit store and correlation IDs, but have **separate** credential stores and
verification paths. A human session never grants a workload SVID and vice-versa.

## 2. Module map

| File | Responsibility |
|---|---|
| `security/passwords.py` | `hashlib.scrypt` PHC-style hashing + constant-time verify; password policy |
| `security/tokens.py` | Opaque session ids; HMAC-SHA256 access/refresh tokens (signed, not encrypted) |
| `security/session_manager.py` | Session + refresh-token lifecycle: issue, resolve, refresh-rotation, revoke, replay detection |
| `security/oidc.py` | OIDC relying-party boundary: discovery, JWKS, id_token verification, code exchange, state/nonce store |
| `security/auth_service.py` | `EnterpriseAuthService`: login (local + OIDC), logout, authorization guard, tenant scope, audit |
| `security/rbac.py` | Roles, permission catalogue, role→permission matrix, `effective_access()` |
| `security/permission_cache.py` | Tenant-scoped Redis cache of effective access (PostgreSQL authoritative) |
| `security/admin_ops.py` | Administrative operations with escalation / last-admin guards |
| `security/audit.py` | Durable audit writer + correlation ids (reuses `SecurityLogger` redaction) |
| `security/store.py`, `memory_store.py`, `storage/postgres/enterprise.py` | Storage interface + in-memory + PostgreSQL implementations |
| `security/config.py` | `EnterpriseAuthConfig` (fail-closed production validation) |
| `api/enterprise_http.py` | HTTP routes: login, SSO, session, admin; secure cookies + CSRF |

## 3. Local (password) authentication

1. `POST /v1/auth/login {email, password}`.
2. Email is normalised (lower-cased, trimmed); lookup is constant-shape. Unknown user → **generic**
   `authentication_failed` (no user-enumeration), and a dummy scrypt verify is performed to equalise timing.
3. On success: `failed_count` resets; on failure it increments; at `login_max_failures` the account is
   **locked** for `login_lock_window_s`. A locked/suspended/disabled account is rejected even with the
   correct password.
4. Redis token-bucket rate limiting per `(email, ip)` (reuses `state/ratelimit`). Over-limit → `rate_limited`.
5. The plaintext password is **never** persisted or logged; only `password_hash` (scrypt) and `password_algo`.

## 4. OIDC SSO (authorization-code + PKCE)

Boundary: `security/oidc.py` is the **only** place that talks to an IdP. The rest of the system sees
normalised `OidcIdentity` claims.

```
GET /v1/auth/oidc/{org}/start
  → discovery(issuer) → authorize_url(scope, state, nonce, code_challenge)
  → store LoginTransaction{state, nonce, code_verifier, return_to, org} in Redis (TTL, single-use)
  → 302 to IdP

GET /v1/auth/oidc/callback?code&state
  → consume transaction by state  (SINGLE-USE: replay ⇒ invalid_state)
  → POST token_endpoint (code + code_verifier)   [PKCE]
  → verify id_token:
        alg allow-list (RS256/384/512, ES256/384)   → reject 'none'/HS*
        signature via cached JWKS (kid; refetch once on miss)
        iss  == issuer            (exact)
        aud  contains client_id   (audience)
        azp  == client_id         (token substitution guard, when multiple audiences)
        exp/iat/nbf vs INJECTED clock  (+ leeway)
        nonce == transaction nonce
  → just-in-time user provisioning by OIDC 'subject' (stable id, not email)
  → find tenant membership for the requesting org  (no auto-join)
  → create session
```

**Login-CSRF & token-substitution protections**
- `state`: 256-bit random, bound to the login transaction, **single-use** (consumed atomically).
- `nonce`: 256-bit random, echoed inside the id_token and compared exactly.
- `PKCE S256`: `code_verifier` never leaves the RP; prevents code interception.
- `azp` check: blocks an id_token minted for a *different* client being replayed to us.
- The IdP issuer and `client_id` are fixed per tenant in `idp_configs`; a callback cannot redirect to
  arbitrary issuers.

## 5. Session & token lifecycle

| Artifact | Form | Storage | Notes |
|---|---|---|---|
| **Access token** | HMAC-SHA256, short-lived (`access_ttl_s`, default 900s) | not stored | verified by signature + `sid` lookup |
| **Refresh token** | HMAC-SHA256, longer (`refresh_ttl_s`, default 14d) | hash stored in `refresh_tokens` | **rotated on every use** |
| **Session** | row (`sessions`) | PostgreSQL | `access_token_hash` stores the **current** access token's hash → logout/revocation is instant |
| **CSRF token** | HMAC-SHA256 bound to session + clock bucket | not stored | required on every state-changing cookie-auth request |

**Refresh-token rotation with replay detection.** Each refresh consumes the presented token and issues a
new one. If an **already-rotated** token is presented again (theft signal), the **entire refresh family**
for that session is revoked and a `refresh_replay_detected` audit event is written. Idle timeout
(`session_idle_ttl_s`) and absolute timeout (`session_absolute_ttl_s`) are enforced on resolve.

**Logout / revocation.** `logout` sets the session `revoked` and revokes its refresh tokens; access tokens
stop working immediately because `resolve()` rejects revoked sessions. `session:revoke` lets an authorised
admin revoke another user's sessions (e.g. on incident response).

**Secure cookie settings** (`api/enterprise_http.py`): `HttpOnly`, `Secure` (unless `cookie_secure=False`
for tests), `SameSite=Strict`, path-scoped. CSRF via double-submit HMAC token, checked **before** the
handler runs for every `POST/PUT/PATCH/DELETE`.

## 6. Enterprise SSO / provisioning readiness

* **OIDC**: fully implemented and tested (see §4). Production requires real IdP metadata (`issuer`,
  `client_id`, `client_secret_encrypted`, `allowed_algs`).
* **SAML 2.0**: **not implemented** in Step 8 and **not labelled production-ready**. It is architecturally
  anticipated behind the IdP-config boundary; adding it means a new verifier beside `oidc.py`.
* **SCIM 2.0 (user/group provisioning)**: **not implemented**. Users are provisioned just-in-time on first
  OIDC login, or created by administrators. A SCIM endpoint is a future extension, not a hidden claim.

## 7. Secret hygiene

* No plaintext passwords, tokens or client secrets are ever stored or logged.
* The `SecurityLogger` field allow-list still redacts anything not explicitly whitelisted; Step 8 added only
  non-secret fields (`event`, `org_id`, `actor_id`, `target_id`, `outcome`, `reason`, `session_id`, `correlation_id`).
* `idp_configs.client_secret_encrypted` is a ciphered blob; the application supplies the KMS material.
