"""Phase 4 integration tests: the guard <-> egress two-leg enforcement boundary.

These prove that an outbound HTTP/tool call runs ONLY when BOTH the Step 11 governance decision AND
the Phase 4 egress decision (destination policy + SSRF + DLP) are sealed ALLOWs -- i.e. the egress
control is enforced at the REAL execution boundary, not merely SDK-side.

They run against a REAL OPA binary (``opa eval``) plus the in-memory governance/policy/egress stores.

Run:  PYTHONPATH=src:. python -m unittest -v tests.test_egress_guard_integration
"""
from __future__ import annotations

import shutil
import unittest

from agent_identity.core.errors import ForbiddenError
from agent_identity.egress import (EgressConfig, EgressRequest, EgressService, MemoryEgressStore)
from agent_identity.egress.addresses import AddressPolicy, StaticDnsResolver
from agent_identity.governance import (GovernanceConfig, GovernanceService, MemoryGovernanceStore,
                                       ResourceDescriptor)
from agent_identity.governance.connectors import GuardedEgressConnector, HttpApiConnector
from agent_identity.policy import (MemoryPolicyStore, PolicyConfig, PolicyDecisionService,
                                   StoreApprovalProvider, build_engine)
from agent_identity.security.rbac import ROLE_TENANT_ADMIN, effective_access

OPA = shutil.which("opa")

GOV_ALLOW_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "default_deny"}

decision := {"decision": "ALLOW", "reason": "gov_allow"} {
    input.request_context.registry_status == "registered"
}
"""

GOV_DENY_REGO = """
package agentguard.authz

default decision := {"decision": "DENY", "reason": "gov_deny"}
"""


def _actor(org="acme"):
    return effective_access("usr_admin", org, tenant_roles=(ROLE_TENANT_ADMIN,))


def _policy_service(rego):
    pstore = MemoryPolicyStore()
    pcfg = PolicyConfig(environment="development", engine="opa", opa_mode="cli",
                        eval_timeout_ms=3000, cache_enabled=True, cache_ttl_ms=5000)
    svc = PolicyDecisionService(pstore, build_engine(pcfg), pcfg,
                                approvals=StoreApprovalProvider(pstore, pcfg))
    a = _actor()
    rec = svc.create_policy(a, name="gov", org_id="acme", rego_source=rego)
    svc.activate(a, rec.policy_id, 1)
    return svc


def _egress_service():
    resolver = StaticDnsResolver({"api.example.com": ["93.184.216.34"]})
    return EgressService(MemoryEgressStore(), config=EgressConfig(environment="development"),
                         address_policy=AddressPolicy(resolver=resolver))


@unittest.skipUnless(OPA, "the opa binary is required")
class GuardEgressBoundaryTests(unittest.TestCase):
    def _gov(self, rego=GOV_ALLOW_REGO, egress=None):
        svc = _policy_service(rego)
        gov = GovernanceService(MemoryGovernanceStore(), svc,
                                config=GovernanceConfig(environment="development"), egress=egress)
        gov.resources.register_resource(
            _actor(), resource_id="api:billing", org_id="acme", resource_type="http_api",
            name="billing_api", owner="platform-team", sensitivity="internal",
            permitted_operations=["read", "write"])
        return gov

    def test_both_legs_allow_runs(self):
        eg = _egress_service()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        gov = self._gov(egress=eg)
        ran = {"v": False}

        def ex():
            ran["v"] = True
            return "done"
        out = gov.guard.authorize_egress_and_run(
            agent_id="agt1", tenant="acme",
            descriptor=ResourceDescriptor(resource_id="api:billing", operation="read"),
            egress_request=EgressRequest(url="https://api.example.com/x"), executor=ex)
        self.assertEqual(out, "done")
        self.assertTrue(ran["v"])

    def test_governance_deny_blocks_before_egress(self):
        eg = _egress_service()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        gov = self._gov(rego=GOV_DENY_REGO, egress=eg)
        ran = {"v": False}
        with self.assertRaises(ForbiddenError):
            gov.guard.authorize_egress_and_run(
                agent_id="agt1", tenant="acme",
                descriptor=ResourceDescriptor(resource_id="api:billing", operation="read"),
                egress_request=EgressRequest(url="https://api.example.com/x"),
                executor=lambda: ran.__setitem__("v", True))
        self.assertFalse(ran["v"])

    def test_egress_deny_blocks_even_when_governance_allows(self):
        eg = _egress_service()   # NO egress policy -> default deny
        gov = self._gov(egress=eg)
        ran = {"v": False}
        with self.assertRaises(ForbiddenError):
            gov.guard.authorize_egress_and_run(
                agent_id="agt1", tenant="acme",
                descriptor=ResourceDescriptor(resource_id="api:billing", operation="read"),
                egress_request=EgressRequest(url="https://api.example.com/x"),
                executor=lambda: ran.__setitem__("v", True))
        self.assertFalse(ran["v"])

    def test_egress_ssrf_blocks_even_when_governance_allows(self):
        eg = _egress_service()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        gov = self._gov(egress=eg)
        ran = {"v": False}
        with self.assertRaises(ForbiddenError):
            gov.guard.authorize_egress_and_run(
                agent_id="agt1", tenant="acme",
                descriptor=ResourceDescriptor(resource_id="api:billing", operation="read"),
                egress_request=EgressRequest(url="http://169.254.169.254/latest/meta-data"),
                executor=lambda: ran.__setitem__("v", True))
        self.assertFalse(ran["v"])

    def test_egress_dlp_block_blocks_even_when_governance_allows(self):
        eg = _egress_service()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        gov = self._gov(egress=eg)
        ran = {"v": False}
        with self.assertRaises(ForbiddenError):
            gov.guard.authorize_egress_and_run(
                agent_id="agt1", tenant="acme",
                descriptor=ResourceDescriptor(resource_id="api:billing", operation="write"),
                egress_request=EgressRequest(
                    url="https://api.example.com/x", method="POST",
                    body={"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}),
                executor=lambda: ran.__setitem__("v", True))
        self.assertFalse(ran["v"])

    def test_guarded_egress_connector_runs_on_both_allow(self):
        eg = _egress_service()
        eg.register_policy(org_id="acme", name="allow api", host_patterns=["api.example.com"])
        gov = self._gov(egress=eg)
        conn = GuardedEgressConnector(gov.guard, HttpApiConnector())
        out = conn(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read",
                   egress_request=EgressRequest(url="https://api.example.com/x"),
                   method="GET", path="/x")
        self.assertTrue(out["authorized"])

    def test_guarded_egress_connector_blocks_on_egress_deny(self):
        eg = _egress_service()   # no policy -> deny
        gov = self._gov(egress=eg)
        conn = GuardedEgressConnector(gov.guard, HttpApiConnector())
        with self.assertRaises(ForbiddenError):
            conn(agent_id="agt1", tenant="acme", resource_id="api:billing", operation="read",
                 egress_request=EgressRequest(url="https://api.example.com/x"))

    def test_guard_without_egress_raises(self):
        gov = self._gov(egress=None)
        with self.assertRaises(ForbiddenError):
            gov.guard.authorize_egress_and_run(
                agent_id="agt1", tenant="acme",
                descriptor=ResourceDescriptor(resource_id="api:billing", operation="read"),
                egress_request=EgressRequest(url="https://api.example.com/x"),
                executor=lambda: "x")


if __name__ == "__main__":
    unittest.main()
