# Step 8 — Tenant Isolation Model

> Tenant identity comes **only** from verified context (the session's active `org_id`), never from a
> client-supplied header/body/query field. Isolation is enforced in **three** independent layers.

## Layer 1 — Verified tenant context

The active tenant is resolved at login time from the user's `tenant_memberships` (and, for SSO, the
`org` in the login transaction). It is carried in the signed access token's `sid` → session row and can
be switched only via an explicit, membership-checked `switch_tenant` that re-issues a session. There is
no code path where `org_id` is read from an untrusted request field.

## Layer 2 — Application-scoped queries (`tenant_scope`)

Every store call that touches tenant data runs inside a tenant scope. The scope is a context manager on
`storage/postgres/db.py`:

```python
db.tenant_scope(org_id, platform_admin=False, user_id=None)
```

It sets SQL session variables for the duration of the block:

* `app.current_org` — the tenant being acted on,
* `app.user_id` — the acting principal,
* `app.platform_admin` — `'on'` only when the caller holds `platform:admin`.

Queries are **always** additionally filtered by `org_id = %s` in their own `WHERE` clause (defence in
depth — RLS is the backstop, not the only control). Ownership checks (`owner_id`, membership rows) are
applied on top for per-resource actions.

## Layer 3 — PostgreSQL RLS (defence in depth)

Migration `0004_step8_enterprise_auth.sql` enables `ROW LEVEL SECURITY` on tenant tables and installs
policies of the form:

```sql
USING (
  org_id = current_setting('app.current_org', true)
  OR current_setting('app.platform_admin', true) = 'on'
  OR (org_id = current_setting('app.current_org', true)          -- a user may read their OWN memberships
      AND user_id = current_setting('app.user_id', true))
)
```

Key properties:

* **Fail-closed**: if no scope is set, `current_setting(..., true)` returns `NULL` → no rows match.
* **Platform-admin bypass is explicit and audited**: only a session with `platform:admin` sets the bypass.
* **Non-owner enforcement**: production must connect as a **non-owner, non-superuser** role (see
  *Limitations*). PostgreSQL exempts table owners and `BYPASSRLS` roles from RLS, so the deployment uses a
  dedicated application role. The integration suite proves the policy by connecting as a freshly created
  `NOSUPERUSER` login.

## Constraints & foreign keys (integrity, not just visibility)

| Constraint | Purpose |
|---|---|
| `users.email` `UNIQUE (lower(email))` (citext) | one account per address; no duplicate identities |
| `tenant_memberships` `UNIQUE (org_id, user_id)` | a user has at most one role edge per tenant |
| `sessions.session_id` `UNIQUE`; `refresh_tokens.token_hash` `UNIQUE` | no token collision / aliasing |
| `refresh_tokens` `ON DELETE CASCADE` from `sessions` | revoking a session removes its refresh family |
| `tenant_memberships` FK → `organizations(org_id)`, `users(user_id)` | **no orphaned cross-tenant rows possible** |
| `sessions.org_id` FK → `organizations(org_id)` | a session cannot name a non-existent tenant |
| audit append-only `CHECK` | `audit_events` cannot be updated/deleted |

## Cross-tenant ID-guessing protection

* **UUID random ids** everywhere (no sequential/guessable ids).
* Even with a valid id, a cross-tenant read returns **not-found** because Layer 2 + Layer 3 filter it out;
  the API never reveals whether another tenant's object exists.
* Administrative operations require the caller to hold the relevant permission **in the target tenant**
  (or be a platform admin), so guessing an id is not sufficient.
* A tenant administrator managing a user in another tenant is rejected with a generic `forbidden`.

## Redis isolation

All Step 8 Redis keys are namespaced by tenant (see `security/redis_keys.py`):

```
ag:v1:s8:<env>:perm:<org_id>:<user_id>:<version>   # effective-access cache (tenant-scoped)
ag:v1:s8:<env>:oidc:tx:<state>                     # login transaction (single-use)
ag:v1:s8:<env>:oidc:nonce:<nonce>                  # replay guard for consumed nonces
ag:v1:s8:<env>:login:rl:<org|->:<hash>             # login rate limiting
```

* A permission lookup for tenant A **cannot** read a key written for tenant B (different key prefix *and*
  the cache stores the `org_id`, which is re-verified on read).
* **PostgreSQL stays authoritative**: the cache is a read-through accelerator only; it is loaded from the
  database and is invalidated on any role/permission/membership change (`perm_version:<org>:<user>` bump).
* Cache entries carry a `version`; a stale version is ignored, so a revoked role takes effect immediately.
