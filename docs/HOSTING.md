# Hosting guide

## 1. Minimum viable deployment (safe defaults)
```bash
cp .env.example .env     # set ADMIN_TOKEN (long random), SUPABASE_*, LLM keys, CORS_ORIGINS
docker compose up -d --build
```
Defaults: `TOOL_GATE_MODE=local`, `PYTHON_EXEC_MODE=disabled`. Agents can call echo / now /
web_search / file_generator; code execution is off. Put **TLS in front** (Caddy, nginx or your
cloud load balancer) — neither container terminates TLS.

Apply the database schema: `apps/aql/supabase/migrations/0001_aql1_schema.sql`.

## 2. Turning on code execution (`PYTHON_EXEC_MODE=isolated`)
Needs a working jail backend on the host that runs the backend:
* Docker/Podman/bubblewrap on the host, or unprivileged user namespaces with `unshare`.
* Docker's default seccomp profile blocks nested namespaces, so it will say
  `isolation_unavailable` and **refuse** (that is the intended fail-closed behaviour).
* Recommended for real customers: run the backend (or a small execution worker) on a dedicated VM
  with no secrets and no access to your database, or under gVisor/Firecracker. Do not use
  `--privileged` on the machine that holds your keys.
* Verify with `GET /v1/security/posture` → `isolation.available: true`, then add `python_exec` and
  `happy_run` to `TOOL_ALLOWLIST`.

## 3. AgentGuard mode (`TOOL_GATE_MODE=agentguard`)
1. Run the AgentGuard server (`docker compose --profile agentguard up -d` for dev; the production
   topology is `services/agentguard/deploy/compose/docker-compose.production.yml`: Postgres, Redis,
   TLS, real KMS).
2. Register the AQL agent in AgentGuard with capabilities `tool:web_search`, `tool:file_generator`, …
3. Write a factory returning an AgentGuard SDK `AuthorizationClient` for that agent and set
   `AGENTGUARD_CLIENT_FACTORY=your_pkg.module:make_client`. The SDK handles credentials and
   proof-of-possession.
4. This path is covered by unit tests using fake clients; **it has not been exercised against a
   live AgentGuard server in this build.** Test it in staging.

## 4. Pre-launch checklist
- [ ] `ADMIN_TOKEN` is long and random; admin endpoints are reachable only over HTTPS
- [ ] `AUTH_ENABLED=true`; API keys created via `/v1/keys`
- [ ] `/v1/security/posture` reviewed (it requires an API key)
- [ ] Payoneer flow tested end-to-end with a real small payment
- [ ] Backups for Supabase; secrets in a secret manager, not in the repo
