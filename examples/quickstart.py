"""End-to-end walkthrough.  Run:  PYTHONPATH=src python3 examples/quickstart.py"""
import json

from agent_identity import (AgentSideKey, IdentityConfig, IdentityService, SPAWN_AUDIENCE)

svc = IdentityService(IdentityConfig(log_to_python_logging=False))
svc.register_organization("acme", "Acme Corp")

# 1. Register agent (identity) -> 2. start an instance (runtime) -> 3. short-lived credential
agent = svc.register_agent("acme", "customer-support-agent", "support", "ops@acme.com",
                           "Handles tickets", ["agent:spawn", "tickets:read"], "production")
inst = svc.create_agent_instance(agent["agent_id"])

# Recommended mode: the agent holds its own private key; the service only sees the public key.
key = AgentSideKey()
cred = svc.issue_credential(agent["agent_id"], inst["instance_id"],
                            **key.csr(agent["agent_id"], inst["instance_id"]))
print("issued:", cred)                                  # token is redacted in repr

# 4. Present credential + fresh proof to a verifier (e.g. an API gateway)
proof = key.make_proof(cred.credential_id, audience="tickets-api")
print(json.dumps(svc.verify_credential(cred.token, proof=proof, audience="tickets-api").to_dict(), indent=2))
print("replay ->", svc.verify_credential(cred.token, proof=proof, audience="tickets-api").reason)

# 5. Spawn a sub-agent (parent authenticates; capabilities can only shrink)
res = svc.spawn_sub_agent(cred.token, key.make_proof(cred.credential_id, SPAWN_AUDIENCE),
                          agent_name="research-agent", agent_type="research",
                          capabilities=["tickets:read"])
print("child lineage:", res.agent["lineage"])

# 6. Rotate, then revoke
new = svc.rotate_credential(cred.credential_id, grace_seconds=30)
svc.revoke_credential(new.credential_id, "administrative_action", "secops@acme.com", "demo")
print("status:", svc.get_credential_status(new.credential_id)["status"])
