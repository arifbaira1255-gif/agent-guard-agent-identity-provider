"""Optional HTTP transport (stdlib only). Pure `handle()` function + thin server wrapper,
so the core engine stays transport-agnostic. All routes require a bearer token.
Use TLS/mTLS (reverse proxy) in production; this server speaks plain HTTP."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple

from ..core.errors import (ConflictError, IdentityError, NotFoundError,
                           UnauthorizedError, ValidationError)
from .service import IdentityService

MAX_BODY = 64 * 1024
_STATUS = {ValidationError: 400, UnauthorizedError: 403, NotFoundError: 404, ConflictError: 409}


def _err(exc: Exception) -> Tuple[int, dict]:
    for t, s in _STATUS.items():
        if isinstance(exc, t):
            return s, {"error": exc.code, "message": str(exc)}
    if isinstance(exc, IdentityError):
        return 400, {"error": exc.code, "message": str(exc)}
    return 500, {"error": "internal_error"}          # never leak internals


def handle(svc: IdentityService, admin_token: str, method: str, path: str,
           body: dict, headers: dict) -> Tuple[int, dict]:
    auth = headers.get("Authorization", "")
    supplied = auth[7:] if auth.startswith("Bearer ") else ""
    if not admin_token or not hmac.compare_digest(supplied.encode(), admin_token.encode()):
        return 401, {"error": "unauthenticated"}
    actor = "http:admin"
    try:
        parts = [p for p in path.split("?")[0].split("/") if p]
        if method == "GET" and parts[:2] == ["v1", "agents"] and len(parts) == 3:
            return 200, svc.get_agent_identity(parts[2])
        if method == "GET" and parts[:2] == ["v1", "credentials"] and len(parts) == 4 \
                and parts[3] == "status":
            return 200, svc.get_credential_status(parts[2])
        if method != "POST" or not isinstance(body, dict):
            return 404, {"error": "not_found"}
        route = "/".join(parts)
        if route == "v1/organizations":
            return 201, svc.register_organization(body["org_id"], body["name"],
                                                   allowed_capabilities=body.get("allowed_capabilities"),
                                                   actor=actor)
        if route == "v1/agents":
            return 201, svc.register_agent(
                body["org_id"], body["agent_name"], body["agent_type"], body["owner"],
                body.get("description", ""), body.get("capabilities"),
                body.get("environment", "development"), body.get("metadata"),
                body.get("parent_agent_id"), actor=actor)
        if route == "v1/instances":
            return 201, svc.create_agent_instance(body["agent_id"], session_id=body.get("session_id"),
                                                  actor=actor)
        if route == "v1/credentials/issue":
            c = svc.issue_credential(body["agent_id"], body["instance_id"],
                                     ttl_seconds=body.get("ttl_seconds"),
                                     public_key=body.get("public_key"),
                                     pop_signature=body.get("pop_signature"), actor=actor)
            return 201, c.to_dict()
        if route == "v1/credentials/rotate":
            c = svc.rotate_credential(body["credential_id"], grace_seconds=body.get("grace_seconds"),
                                      public_key=body.get("public_key"),
                                      pop_signature=body.get("pop_signature"), actor=actor)
            return 200, c.to_dict()
        if route == "v1/credentials/verify":
            r = svc.verify_credential(body.get("token"), proof=body.get("proof"),
                                      audience=body.get("audience"),
                                      expected_agent_id=body.get("expected_agent_id"),
                                      expected_instance_id=body.get("expected_instance_id"),
                                      correlation_id=body.get("correlation_id"))
            return 200, r.to_dict()                  # invalid != HTTP error: it is a verdict
        if route == "v1/credentials/revoke":
            return 200, svc.revoke_credential(body["credential_id"], body["reason"], actor,
                                              body.get("detail"))
        if route == "v1/agents/spawn":
            r = svc.spawn_sub_agent(
                body["parent_token"], body.get("parent_proof"), agent_name=body["agent_name"],
                agent_type=body["agent_type"], description=body.get("description", ""),
                capabilities=body.get("capabilities"), metadata=body.get("metadata"),
                ttl_seconds=body.get("ttl_seconds"), public_key=body.get("public_key"),
                pop_signature=body.get("pop_signature"))
            return 201, {"agent": r.agent, "instance": r.instance, "spawn": r.spawn,
                         "credential": r.credential.to_dict() if r.credential else None}
        return 404, {"error": "not_found"}
    except KeyError:
        return 400, {"error": "validation_error", "message": "missing field"}
    except Exception as e:  # noqa: BLE001
        return _err(e)


def make_server(svc: IdentityService, admin_token: str, host="127.0.0.1", port=8443):
    class H(BaseHTTPRequestHandler):
        def _do(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "payload_too_large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}") if method == "POST" else {}
            except ValueError:
                return self._send(400, {"error": "invalid_json"})
            self._send(*handle(svc, admin_token, method, self.path, body, dict(self.headers)))

        def do_GET(self): self._do("GET")
        def do_POST(self): self._do("POST")

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):   # no default access log (could contain paths/ids)
            pass

    return ThreadingHTTPServer((host, port), H)
