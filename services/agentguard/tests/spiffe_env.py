"""Shared fixtures: identity service + dev SPIRE (real wire protocol, real X.509/JWT crypto)."""
from agent_identity import IdentityConfig, IdentityService
from agent_identity.core.clock import FixedClock
from agent_identity.observability.logging import SecurityLogger
from agent_identity.spiffe.config import Environment, SpireConfig
from agent_identity.spiffe.dev import DevSpireCA, DevWorkloadTransport
from agent_identity.spiffe.errors import R
from agent_identity.spiffe.ids import agent_spiffe_id
from agent_identity.spiffe.provider import SpiffeIdentityProvider

TD = "prod.agentguard.example.net"      # non-placeholder trust domain


def cfg(**kw):
    d = dict(environment=Environment.DEVELOPMENT, provider="dev", trust_domain=TD,
             retry_initial_backoff_seconds=0.0, retry_max_attempts=3)
    d.update(kw)
    return SpireConfig(**d).validate()


class Env:
    """service(agent a1 + instance i1) <-> provider <-> dev SPIRE entitled to a1/i1."""

    def __init__(self, caps=("agent:spawn", "tickets:read"), federated=None, clock_start=None, **cfg_kw):
        self.clock = FixedClock(clock_start) if clock_start is not None else FixedClock()
        self.svc = IdentityService(IdentityConfig(trust_domain=TD, log_to_python_logging=False),
                                   clock=self.clock, logger=SecurityLogger(use_python_logging=False))
        self.svc.register_organization("acme", "Acme")
        self.agent = self.svc.register_agent("acme", "support-bot", "support", "ops@acme.com", "t",
                                             list(caps), "production", {})
        self.inst = self.svc.create_agent_instance(self.agent["agent_id"])
        self.cfg = cfg(**cfg_kw)
        self.ca = DevSpireCA(TD, self.clock)
        self.a_id = self.agent["agent_id"]
        self.i_id = self.inst["instance_id"]
        self.sid_agent = agent_spiffe_id(TD, "acme", self.a_id)
        self.sid_inst = agent_spiffe_id(TD, "acme", self.a_id, self.i_id)
        self.api = DevWorkloadTransport(self.cfg, self.ca, entitled=[self.sid_inst, self.sid_agent],
                                       federated_cas=federated)
        self.p = SpiffeIdentityProvider(self.svc, self.cfg, self.api, clock=self.clock,
                                        sleep=lambda s: None)
        self.p.bind_agent(self.a_id)
        self.p.bind_instance(self.a_id, self.i_id)
        self.p.refresh_bundles()

    def jwt(self, sid=None, aud="gateway", **kw):
        return self.ca.issue_jwt(sid or self.sid_inst, aud, **kw)
