from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.clock import FixedClock
from agent_identity.observability.logging import SecurityLogger


def make_service(**cfg):
    clock = FixedClock()
    svc = IdentityService(IdentityConfig(log_to_python_logging=False, **cfg), clock=clock,
                          logger=SecurityLogger(use_python_logging=False))
    svc.register_organization("acme", "Acme Corp")
    return svc, clock


def make_agent(svc, name="customer-support-agent", caps=("agent:spawn", "tickets:read")):
    a = svc.register_agent("acme", name, "support", "ops@acme.com", "test agent",
                           list(caps), "production", {"team": "cx"})
    i = svc.create_agent_instance(a["agent_id"])
    c = svc.issue_credential(a["agent_id"], i["instance_id"])
    return a, i, c
