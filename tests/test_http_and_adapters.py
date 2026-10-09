import json
import unittest

from agent_identity.adapters.spiffe import (LocalIdentityProvider,
                                            SpireWorkloadApiProvider, parse_spiffe_id)
from agent_identity.api.http_transport import handle
from tests.helpers import make_agent, make_service

TOK = "admin-secret-token"
H = {"Authorization": "Bearer " + TOK}


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.svc, self.clock = make_service()

    def call(self, m, p, b=None, h=H):
        return handle(self.svc, TOK, m, p, b or {}, h)

    def test_auth_required(self):
        self.assertEqual(self.call("GET", "/v1/agents/x", h={})[0], 401)
        self.assertEqual(self.call("GET", "/v1/agents/x", h={"Authorization": "Bearer nope"})[0], 401)
        self.assertEqual(handle(self.svc, "", "GET", "/v1/agents/x", {}, {"Authorization": "Bearer "})[0], 401)

    def test_full_flow(self):
        s, a = self.call("POST", "/v1/agents", dict(org_id="acme", agent_name="bot",
                         agent_type="t", owner="o@x.com", capabilities=["x:read"]))
        self.assertEqual(s, 201)
        s, i = self.call("POST", "/v1/instances", {"agent_id": a["agent_id"]})
        s, c = self.call("POST", "/v1/credentials/issue", dict(agent_id=a["agent_id"],
                         instance_id=i["instance_id"]))
        self.assertEqual(s, 201)
        proof = self.svc.create_proof(c["token"], "gw")
        s, v = self.call("POST", "/v1/credentials/verify", dict(token=c["token"], proof=proof,
                         audience="gw"))
        self.assertTrue(v["valid"])
        s, r = self.call("POST", "/v1/credentials/revoke", dict(credential_id=c["credential_id"],
                         reason="compromise"))
        self.assertEqual(r["revoked_by"], "http:admin")
        s, st = self.call("GET", f"/v1/credentials/{c['credential_id']}/status")
        self.assertEqual(st["status"], "revoked")
        self.assertNotIn("private", json.dumps([a, i, st]).lower())

    def test_errors_are_safe(self):
        self.assertEqual(self.call("POST", "/v1/agents", {"org_id": "acme"})[0], 400)
        s, e = self.call("POST", "/v1/agents", dict(org_id="acme", agent_name="../x",
                         agent_type="t", owner="o@x.com"))
        self.assertEqual((s, e["error"]), (400, "validation_error"))
        self.assertEqual(self.call("GET", "/v1/agents/agt_nope")[0], 404)
        s, v = self.call("POST", "/v1/credentials/verify", {"token": "garbage"})
        self.assertEqual((s, v["valid"], v["reason"]), (200, False, "malformed_token"))


class AdapterTests(unittest.TestCase):
    def test_spiffe_id_roundtrip(self):
        svc, _ = make_service()
        a, i, c = make_agent(svc)
        p = parse_spiffe_id(c.passport["spiffe_id"])
        self.assertEqual((p["org"], p["agent"], p["instance"]),
                         ("acme", a["agent_id"], i["instance_id"]))
        self.assertIsNone(parse_spiffe_id("spiffe://x/../y"))

    def test_local_provider_and_spire_adapter_is_real(self):
        from agent_identity.spiffe.provider import SpiffeIdentityProvider
        svc, _ = make_service()
        a, i, _ = make_agent(svc)
        lp = LocalIdentityProvider(svc)
        c = lp.issue(a["agent_id"], i["instance_id"])
        self.assertTrue(lp.verify(c.token, require_proof=False).valid)
        self.assertIs(SpireWorkloadApiProvider, SpiffeIdentityProvider)   # stub removed


if __name__ == "__main__":
    unittest.main()
