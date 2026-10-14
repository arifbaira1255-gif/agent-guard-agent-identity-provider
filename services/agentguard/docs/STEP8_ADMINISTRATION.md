# Step 8 — Administration, Provisioning & Audit

## 1. Secure initial admin provisioning (no default password)

`POST`-bootstrapping is a **one-time** operation:

```python
bootstrap_platform_admin(store, audit, email=..., password=...)
```

* Refuses if **any** platform administrator already exists (`ConflictError`) — it cannot be replayed.
* The password is policy-checked (see below) and scrypt-hashed. **There is no default, hard-coded,
  seeded, or documented password anywhere** — the operator supplies it out-of-band (env var read once at
  bootstrap, or an interactive prompt in a real deployment).
* The event is audited as `bootstrap_platform_admin`.

**Password policy** (`security/passwords.py`): minimum length (`password_min_len`, default 12) and a
rejection list of well-known weak passwords. Passwords are never stored, echoed, or logged.

**Operational sequence for a new deployment**

1. Provision PostgreSQL + Redis; run migrations (`migrate.migrate`) → schema v4.
2. Create the application login as a **non-owner** role with `SELECT/INSERT/UPDATE/DELETE` on the tenant
   tables (no `SUPERUSER`, no `BYPASSRLS`) so RLS applies.
3. Call `bootstrap_platform_admin` once, with a password supplied via a secret manager.
4. Rotate that password through the normal admin flow after first login.

## 2. Administrative operations (`security/admin_ops.py`)

Every operation resolves required permissions, calls `authorize(...)` first, applies guards, writes an audit
row, and invalidates the permission cache on change.

| Operation | Guard beyond RBAC |
|---|---|
| `create_user` | platform-admin (or tenant-admin grant) |
| `suspend_user` / `activate_user` | cannot suspend yourself; revocation of all sessions |
| `assign_membership` / `remove_membership` | target within caller's tenant; `role:assign` |
| `assign_platform_admin` / `remove_platform_admin` | platform admin only; **cannot remove the last platform admin**; **cannot self-escalate** |
| `grant_permission` / `deny_permission` | platform admin; adds to/removes from effective set |
| `revoke_session` / `revoke_all_user_sessions` | `session:revoke` in scope |
| `create_tenant` / `update_tenant` / `suspend_tenant` | platform plane (`tenant:create`) |
| `create_idp_config` / `update_idp_config` | `idp:write`; secret stored **encrypted** |
| `bootstrap_platform_admin` | one-time only |

**Two escalation guards that are explicitly tested:**

1. **No tenant-admin → platform escalation.** A `tenant_admin` attempting `assign_platform_admin` (for
   themselves or anyone) is rejected with `forbidden`, even for a user in their own tenant. The platform
   plane can only be granted by an existing platform administrator.
2. **No last-platform-admin removal.** Demoting the final platform administrator is rejected
   (`last_platform_admin`), preventing a permanent administrative lock-out.

## 3. Audit events

Audit events are stored durably in PostgreSQL (`audit_events`, append-only) **and** emitted through the
project's existing `SecurityLogger` (same redaction/correlation architecture as Steps 1–7).

**Common fields:** timestamp, `event`, `outcome`, `actor_id`, `org_id` (tenant context), `target_id`,
`reason`, `session_id`, `correlation_id`, client `ip`, `user_agent`. **No secret is ever recorded.**

| Event | When |
|---|---|
| `login_succeeded` / `login_failed` | local login outcome |
| `login_locked` / `login_rate_limited` | lockout / throttling |
| `sso_login_succeeded` / `sso_login_failed` | OIDC callback outcome |
| `oidc_state_replay` | reused/unknown `state` during callback (login-CSRF signal) |
| `oidc_nonce_mismatch`, `oidc_token_invalid` | id_token validation failures |
| `session_created` / `session_refreshed` / `session_revoked` / `session_expired` | session lifecycle |
| `refresh_replay_detected` | reused refresh token → family revoked |
| `logout` | explicit logout |
| `authorization_denied` | RBAC/tenant check failed |
| `csrf_rejected` | CSRF token missing/invalid |
| `user_created`, `user_suspended`, `user_activated` | account administration |
| `membership_granted`, `membership_revoked` | tenant membership changes |
| `role_assigned`, `permission_granted`, `permission_denied` | RBAC changes |
| `platform_admin_assigned`, `platform_admin_removed` | platform plane |
| `tenant_created`, `tenant_updated`, `tenant_suspended` | tenant lifecycle |
| `idp_config_created`, `idp_config_updated` | SSO configuration changes |
| `bootstrap_platform_admin` | initial provisioning |

Each row carries a `correlation_id` so a single request's login → authorization → action→ audit trail can
be reconstructed end to end.

## 4. Preventing tenant-admin self-escalation (summary)

* Role assignment validates that the role is **allowable for the caller** in that scope.
* `platform_admin` is never assignable by a tenant-scoped principal.
* `tenant:create` and `platform:admin` are not present in any tenant role's permission set.
* Direct permission grants cannot introduce `platform:admin` outside the platform plane.
