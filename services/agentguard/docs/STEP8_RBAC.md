# Step 8 — RBAC Roles & Permission Matrix

> Enforcement is **server-side on every protected operation** (`EnterpriseAuthService.authorize`). The
> HTTP layer never trusts a client-supplied role; it resolves the principal from the verified session.

## Roles

| Role | Intent |
|---|---|
| **Platform Administrator** (`platform_admin`) | Full authority across all tenants + the platform plane |
| **Tenant Administrator** (`tenant_admin`) | Runs one tenant end-to-end; **cannot** touch the platform plane or other tenants |
| **Security Analyst** (`security_analyst`) | Investigates; can cut off compromised material but does not provision |
| **Security Operator** (`security_operator`) | Day-to-day agent credential issuance/rotation/lifecycle |
| **Developer** (`developer`) | Self-service on the agents they own |
| **Read-Only Auditor** (`readonly_auditor`) | Sees what it is entitled to see, mutates nothing |

Platform scope grants exactly one extra role — `platform_admin`. `tenant_admin` and the operator roles are
**tenant-scoped** and cannot be escalated to platform privileges.

## Permission catalogue

`agent:read`, `agent:write`, `agent:revoke`, `agent:spawn`, `instance:read`, `instance:revoke`,
`credential:read`, `credential:issue`, `credential:rotate`, `credential:revoke`, `audit:read`,
`tenant:read`, `tenant:write`, `tenant:create`, `user:read`, `user:write`, `user:delete`,
`membership:write`, `role:assign`, `session:read`, `session:revoke`, `rbac:read`, `idp:read`,
`idp:write`, `platform:admin`.

## Matrix (`security/rbac.py` → `ROLE_PERMISSIONS`)

| Permission | Platform Admin | Tenant Admin | Security Analyst | Security Operator | Developer | Read-Only Auditor |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| `agent:read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `agent:write` | ✔ | ✔ | | ✔ | ✔ | |
| `agent:revoke` | ✔ | ✔ | ✔ | ✔ | | |
| `agent:spawn` | ✔ | ✔ | | ✔ | ✔ | |
| `instance:read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `instance:revoke` | ✔ | ✔ | ✔ | ✔ | | |
| `credential:read` | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| `credential:issue` | ✔ | ✔ | | ✔ | ✔ | |
| `credential:rotate` | ✔ | ✔ | | ✔ | ✔ | |
| `credential:revoke` | ✔ | ✔ | ✔ | ✔ | | |
| `audit:read` | ✔ | ✔ | ✔ | | | ✔ |
| `tenant:read` | ✔ | ✔ | | | | ✔ |
| `tenant:write` | ✔ | ✔ | | | | |
| `tenant:create` | ✔ | | | | | |
| `user:read` | ✔ | ✔ | | | | ✔ |
| `user:write` | ✔ | ✔ | | | | |
| `user:delete` | ✔ | | | | | |
| `membership:write` | ✔ | ✔ | | | | |
| `role:assign` | ✔ | ✔ | | | | |
| `session:read` | ✔ | ✔ | ✔ | | | ✔ |
| `session:revoke` | ✔ | ✔ | ✔ | | | |
| `rbac:read` | ✔ | ✔ | ✔ | | | ✔ |
| `idp:read` | ✔ | ✔ | | | | ✔ |
| `idp:write` | ✔ | ✔ | | | | |
| `platform:admin` | ✔ | | | | | |

## Resolution algorithm (`effective_access`)

```
effective = tenant_role_perms(role_for(principal, org))          # base grant
          ∪ platform_role_perms(platform_roles(principal))       # platform plane
effective |= direct_permission_grants(principal, org)            # additive grants
effective -= deny_overrides(principal, org)                      # explicit deny WINS
```

* **Least privilege**: each role is an explicit small set, not a wildcard.
* **Explicit deny**: `access_denials` rows are subtracted last and always win.
* **Only real permissions count**: unknown strings are dropped (cannot be used to smuggle a grant).
* **Platform plane is separate**: `platform_admin` only comes from a `platform_admin` membership with
  `org_id = NULL`; a tenant-scoped principal can never reach `platform:admin` or `tenant:create`.

## Authorization contract

```python
guard = svc.authorize(principal, org_id=tenant, required={P_CREDENTIAL_ROTATE})
# raises ForbiddenError('forbidden') when the permission or the tenant scope is missing
```

Every protected route and every administrative operation calls `authorize(...)` **before** doing work.
Authorization failures are audited as `authorization_denied` with actor, tenant, required permission and
correlation id. The endpoint returns a **safe generic error** — no permission names or internal detail leak.
