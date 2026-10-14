"""Bootstrap helpers for the live AgentGuard HTTP tests.

Builds a REAL AgentGuard ``IdentityService`` with its REAL in-process HTTP transport (the same
``make_server``/``handle`` pair AgentGuard's own SDK tests use), then registers an organization, an
agent carrying explicit capabilities, an instance, and issues a REAL credential.

That is what makes the end-to-end test real rather than mocked: the Happy LANG integration performs
an actual authenticated ``POST /v1/authorize`` against AgentGuard's actual authorization path, and
the decision comes from AgentGuard's actual deny-by-default capability hook.

Nothing in AgentGuard is modified: only its public entry points are used.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional, Sequence

ORG_ID = "acme"
ADMIN_TOKEN = "test-admin-token"


def dev_env() -> None:
    """Set the environment AgentGuard's development mode requires (idempotent)."""
    os.environ.setdefault("AGENTGUARD_ENV", "development")
    if not os.environ.get("AGENT_IDENTITY_MASTER_KEY"):
        from cryptography.fernet import Fernet

        os.environ["AGENT_IDENTITY_MASTER_KEY"] = Fernet.generate_key().decode()


@dataclass
class LiveAgentGuard:
    """A running AgentGuard HTTP server plus an issued credential for a registered agent."""

    service: object
    httpd: object
    port: int
    agent_id: str
    instance_id: str
    token: str
    org_id: str
    capabilities: tuple

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def post(self, path: str, payload: dict, *, admin: bool = True) -> tuple:
        """POST ``payload`` and return ``(status, body)`` -- never raises on an HTTP error status."""
        data = json.dumps(payload).encode()
        request = urllib.request.Request(self.base_url + path, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        if admin:
            request.add_header("X-Admin-Token", ADMIN_TOKEN)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                return int(getattr(response, "status", 200)), json.loads(
                    response.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return int(exc.code), json.loads(raw or "{}")
            except ValueError:
                return int(exc.code), {"raw": raw[:400]}

    def authorize(self, payload: dict) -> tuple:
        return self.post("/v1/authorize", payload)

    def make_proof(self, audience: str = "agentguard:tool") -> dict:
        """Build a real possession proof for the issued credential (development key mode).

        AgentGuard's ``/v1/authorize`` requires proof of possession as well as a valid credential;
        this uses AgentGuard's own ``create_proof`` helper so the integration is exercised against
        the genuine authentication path rather than a bypass.
        """
        return self.service.create_proof(self.token, audience)

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def start_live_agentguard(*, agent_name: str = "happy_lang_runner",
                          capabilities: Optional[Sequence[str]] = None) -> LiveAgentGuard:
    """Start a real AgentGuard server and issue a real credential carrying ``capabilities``."""
    dev_env()
    from agent_identity.api import http_transport
    from agent_identity.api.service import IdentityService

    service = IdentityService()
    service.register_organization(ORG_ID, "Acme Corp")
    agent = service.register_agent(org_id=ORG_ID, agent_name=agent_name, agent_type="service",
                                   owner="aunika", description="Happy LANG integrated runner",
                                   capabilities=list(capabilities or ()))
    agent_id = agent["agent_id"]
    instance = service.create_agent_instance(agent_id)
    instance_id = instance["instance_id"]
    credential = service.issue_credential(agent_id, instance_id, ttl_seconds=3600)
    token = getattr(credential, "token", None) or credential["token"]

    httpd = http_transport.make_server(service, ADMIN_TOKEN, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return LiveAgentGuard(service=service, httpd=httpd, port=port, agent_id=agent_id,
                          instance_id=instance_id, token=token, org_id=ORG_ID,
                          capabilities=tuple(capabilities or ()))


def install_policy_hook(service) -> None:
    """Install AgentGuard's real Step-10 policy hook (requires the OPA binary)."""
    from agent_identity.policy.service import make_policy_hook

    from agent_identity.api import http_transport

    http_transport.set_policy_hook(make_policy_hook(service))


def restore_default_hook() -> None:
    """Restore AgentGuard's built-in deny-by-default capability hook."""
    from agent_identity.api import http_transport

    http_transport.set_policy_hook(None)
