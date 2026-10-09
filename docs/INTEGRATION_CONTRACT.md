# Integration Contract

Stable surface: `agent_identity.IdentityService`, `VerificationResult.to_dict()`, `Reason` codes,
passport claims, storage ABCs. Everything else is internal.

## Passport claims (token `agp1.<b64url JSON>.<b64url sig>`)
`v, credential_id, agent_id, instance_id, org_id, owner, issuer, issuer_key_id, iat, nbf, exp,
agent_name, agent_type, environment, capabilities[], parent_agent_id, is_sub_agent, lineage[],
public_key, key_fingerprint, spiffe_id`. Never authorise from an unverified token: always call `verify_credential`.

## Consumers
**SDK (agent side):** generate `AgentSideKey`; obtain credential via control plane (`issue_credential` with CSR);
for every call create `make_proof(credential_id, audience=<target service>)` (fresh nonce, request_id);
refresh via `rotate_credential` before `expires_at`; on restart create a new instance.

**Runtime security / gateway:** call `verify_credential(token, proof=…, audience=<self>)`; allow only if
`valid`; propagate `correlation_id`; log `reason` on deny. Use `expected_agent_id`/`expected_instance_id`
when a session is pinned to one runtime.

**Policy engine:** use verified `agent_id`, `instance_id`, `org_id`, `capabilities`, `is_sub_agent`,
`parent_agent_id` (and `lineage` via `get_agent_identity`) as subject attributes. Same agent ≠ same instance.

**Control plane:** owns authN/authZ for admin operations and passes `actor`. Calls `register_organization`,
`register_agent`, `create_agent_instance`, `issue_credential`, `rotate_*`, `revoke_*`.
Terminate an agent ⇒ `revoke_agent` (all instances, credentials, descendants fail immediately).

## Failure handling
`valid=false` is a verdict, not an exception. Treat unknown reasons as deny. Reasons are stable strings.

## Extension points
Implement `KeyStore` (KMS/HSM sign-only), `AgentRegistry`/`CredentialRegistry`/`RevocationRegistry`/`TrustStore`
(PostgreSQL), `ReplayCache` (Redis, atomic), `Attestor`/`IdentityProvider` (SPIFFE/SPIRE) and pass them to
`IdentityService(...)`.

## Audit events (logger `agentguard.identity.security`, JSON)
`organization.register, agent.register, instance.create, credential.issue|verify|rotate, revocation.add,
agent.spawn, agent.key_rotate, issuer.rotate` with fields: agent_id, instance_id, credential_id, result,
reason, actor, correlation_id (never tokens or keys).
