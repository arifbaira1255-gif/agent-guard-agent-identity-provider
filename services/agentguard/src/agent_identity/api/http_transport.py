"""Optional HTTP transport (stdlib only). Pure `handle()` function + thin server wrapper,
so the core engine stays transport-agnostic. All routes require a bearer token.

Step 6: pass `mtls=MtlsEndpoint` to `make_server` for mutually authenticated TLS. Plaintext is
only possible in development (AGENTGUARD_ENV=development) or, when AGENTGUARD_ENV is unset, on a
loopback address. In staging/production a plaintext listener is refused at construction time.
The bearer token is a SEPARATE credential and still required: mTLS authenticates the calling
service, the token authorises the admin call. Both must pass."""
import hmac
import ipaddress
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Tuple

from ..core.errors import (ConflictError, IdentityError, NotFoundError,
                           UnauthorizedError, ValidationError)
from .service import IdentityService

MAX_BODY = 64 * 1024
_STATUS = {ValidationError: 400, UnauthorizedError: 403, NotFoundError: 404, ConflictError: 409}
IDEMPOTENCY_HEADER = "Idempotency-Key"


def _err(exc: Exception) -> Tuple[int, dict]:
    for t, s in _STATUS.items():
        if isinstance(exc, t):
            return s, {"error": exc.code, "message": str(exc)}
    if isinstance(exc, IdentityError):
        return 400, {"error": exc.code, "message": str(exc)}
    return 500, {"error": "internal_error"}          # never leak internals


# --------------------------------------------------------------------------------- Step 9 SDK boundary
#: A policy hook receives (svc, request) and returns a decision dict:
#:   {"allowed": bool, "reason": str, "policy": str|None, "obligations": [..], "decision_id": str|None}
#: It is the single extension point the Step 10 policy engine implements, and the Step 11 governance
#: hook also plugs into it (see ``agent_identity.governance.hooks``). The default hook is a
#: deny-by-default capability check (see ``default_policy_hook``).
#:
#: Step 11 resource descriptor (OPTIONAL, honoured only when a governance hook is installed): a
#: request MAY additionally carry a governed target as ``resource_id`` + ``operation`` (plus optional
#: ``resource_type``, ``tool``, ``requested_capabilities``). Those fields are UNTRUSTED inputs to the
#: decision — the credential is verified first, and the governance layer resolves the authoritative
#: type/sensitivity/owner from the server-side registry. They never grant anything on their own.
_POLICY_HOOK = None


def set_policy_hook(hook) -> None:
    """Install the authorization decision function used by ``POST /v1/authorize``.

    Passing ``None`` restores the built-in deny-by-default capability check. This is the documented
    integration boundary for Step 10 (Policy Engine and Just-in-Time Authorization).
    """
    global _POLICY_HOOK
    _POLICY_HOOK = hook


def default_policy_hook(svc, request: dict) -> dict:
    """Least-privilege, deny-by-default capability check.

    An action of the form ``tool:<name>`` (or ``<resource>:<verb>``) is allowed only when the
    verified credential carries a capability that matches it EXACTLY. Everything else is denied.
    This is intentionally minimal: it exists so the SDK has a real, testable decision point, NOT to
    replace the Step 10 policy engine (which will add policy languages, conditions and JIT grants).
    """
    action = request.get("action") or ""
    caps = tuple(request.get("_capabilities") or ())
    if not action:
        return {"allowed": False, "reason": "missing_action", "policy": "capability-default"}
    if action in caps:
        return {"allowed": True, "reason": "capability_match", "policy": "capability-default"}
    return {"allowed": False, "reason": "no_matching_capability", "policy": "capability-default"}


def _authorize(svc: IdentityService, body: dict) -> dict:
    """Verify the caller's credential + possession proof, then ask the policy hook for a decision.

    Fails CLOSED: an invalid credential, a missing proof, or a hook error all yield ``allowed=false``.
    """
    token = body.get("token") or body.get("credential")
    proof = body.get("proof")
    audience = body.get("audience")
    correlation_id = body.get("correlation_id")
    if not isinstance(token, str) or not token:
        return {"allowed": False, "reason": "missing_credential", "correlation_id": correlation_id}
    try:
        res = svc.verify_credential(token, proof=proof, audience=audience, require_proof=True,
                                    correlation_id=correlation_id)
    except Exception:                                     # noqa: BLE001 - never leak internals
        return {"allowed": False, "reason": "verification_error", "correlation_id": correlation_id}
    if not res.valid:
        return {"allowed": False, "reason": res.reason or "invalid_credential",
                "correlation_id": res.correlation_id or correlation_id}
    request = dict(body)
    request["_capabilities"] = list(res.capabilities or ())
    request["_agent_id"] = res.agent_id
    request["_instance_id"] = res.instance_id
    request["_org_id"] = res.org_id
    hook = _POLICY_HOOK or default_policy_hook
    try:
        decision = hook(svc, request)
    except Exception:                                     # noqa: BLE001 - fail closed
        decision = {"allowed": False, "reason": "policy_error"}
    if not isinstance(decision, dict):
        decision = {"allowed": False, "reason": "policy_error"}
    out = {"allowed": bool(decision.get("allowed")), "reason": decision.get("reason") or "",
           "policy": decision.get("policy"), "obligations": decision.get("obligations") or [],
           "decision_id": decision.get("decision_id"),
           "correlation_id": res.correlation_id or correlation_id}
    return out


def _record_events(svc: IdentityService, body: dict, actor: str) -> dict:
    """Accept a batch of SDK security events and route them through the EXISTING security logger.

    Only allow-listed, non-secret fields survive (the logger drops unknown keys and redacts anything
    that looks like bearer material), so an SDK can never smuggle a token into the audit stream.
    """
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list):
        return {"accepted": 0}
    accepted = 0
    for ev in events[:200]:                               # bounded batch
        if not isinstance(ev, dict):
            continue
        event_type = ev.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            continue
        fields = {k: v for k, v in ev.items() if k != "event_type"}
        fields.setdefault("actor", actor)
        svc.log.emit(f"sdk.{event_type}", **fields)
        accepted += 1
    return {"accepted": accepted}


def handle(svc: IdentityService, admin_token: str, method: str, path: str,
           body: dict, headers: dict, *, health=None, metrics=None) -> Tuple[int, object]:
    # Step 7 health/metrics are attached to the service by make_server so the call signature stays
    # stable (existing callers/tests pass exactly six positional args).
    if health is None:
        health = getattr(svc, "_ha_health", None)
    if metrics is None:
        metrics = getattr(svc, "_ha_metrics", None)
    # --- Step 7 probes: liveness/readiness are UNAUTHENTICATED but sanitized (coarse ok/fail only,
    # no identities, versions, hostnames or error text). They must be reachable by the orchestrator.
    clean = path.split("?")[0]
    if method == "GET" and clean == "/livez":
        return 200, (health.liveness() if health is not None else {"status": "alive"})
    if method == "GET" and clean == "/readyz":
        if health is None:
            return 200, {"status": "ready"}
        r = health.readiness()
        return (200 if r["status"] == "ready" else 503), r
    # --- Step 9 SDK integration boundary ---------------------------------------------------------
    # These two routes are the surface the Universal Agent SDK talks to. They authenticate the AGENT
    # (credential + possession proof verified by the EXISTING verifier), NOT the admin bearer token,
    # so they are handled BEFORE the admin-token gate. The authorization decision is delegated to a
    # pluggable policy hook (``set_policy_hook``); the default hook is a least-privilege,
    # deny-by-default capability check and is a PLACEHOLDER for the Step 10 policy engine -- it is
    # not a policy language and must not be described as one.
    if method == "POST" and isinstance(body, dict):
        _sdk_route = "/".join(p for p in clean.split("/") if p)
        if _sdk_route == "v1/authorize":
            return 200, _authorize(svc, body)
        if _sdk_route == "v1/security/events":
            return 202, _record_events(svc, body, "sdk:agent")
    auth = headers.get("Authorization", "")
    supplied = auth[7:] if auth.startswith("Bearer ") else ""
    if not admin_token or not hmac.compare_digest(supplied.encode(), admin_token.encode()):
        return 401, {"error": "unauthenticated"}
    actor = "http:admin"
    # --- Step 7 metrics: authenticated (may reveal operational detail, never secrets).
    if method == "GET" and clean == "/metrics":
        if metrics is None:
            return 404, {"error": "not_found"}
        return 200, metrics.render_prometheus()
    try:
        parts = [p for p in clean.split("/") if p]
        if method == "GET" and parts[:2] == ["v1", "agents"] and len(parts) == 3:
            return 200, svc.get_agent_identity(parts[2])
        if method == "GET" and parts[:2] == ["v1", "credentials"] and len(parts) == 4 \
                and parts[3] == "status":
            return 200, svc.get_credential_status(parts[2])
        if method != "POST" or not isinstance(body, dict):
            return 404, {"error": "not_found"}
        idem = headers.get(IDEMPOTENCY_HEADER) or None
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
                body.get("parent_agent_id"), actor=actor, idempotency_key=idem)
        if route == "v1/instances":
            return 201, svc.create_agent_instance(body["agent_id"], session_id=body.get("session_id"),
                                                  actor=actor)
        if route == "v1/credentials/issue":
            c = svc.issue_credential(body["agent_id"], body["instance_id"],
                                     ttl_seconds=body.get("ttl_seconds"),
                                     public_key=body.get("public_key"),
                                     pop_signature=body.get("pop_signature"), actor=actor,
                                     idempotency_key=idem)
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


PEER_HEADER = "X-Peer-Spiffe-Id"          # set ONLY by the server after mTLS; client copies are dropped


def _plaintext_permitted(host: str) -> bool:
    env = os.environ.get("AGENTGUARD_ENV", "").strip().lower()
    if env == "development":
        return True
    if env in ("staging", "production"):
        return False
    try:
        loop = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loop = False
    return loop


def make_server(svc: IdentityService, admin_token: str, host="127.0.0.1", port=8443, *,
                mtls=None, health=None, metrics=None):
    if mtls is None and not _plaintext_permitted(host):
        from ..mtls.errors import PlaintextForbidden
        raise PlaintextForbidden("plaintext HTTP listener refused: configure mTLS "
                                 "(plaintext is development/loopback only)")
    # Attach Step 7 health/metrics to the service so `handle` can reach them without changing its
    # call signature (keeps existing callers and tests working).
    svc._ha_health = health
    svc._ha_metrics = metrics

    class H(BaseHTTPRequestHandler):
        def _do(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, {"error": "payload_too_large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}") if method == "POST" else {}
            except ValueError:
                return self._send(400, {"error": "invalid_json"})
            headers = {k: v for k, v in dict(self.headers).items() if k.lower() != PEER_HEADER.lower()}
            peer = getattr(self.request, "agentguard_peer", None)
            if peer is not None:
                headers[PEER_HEADER] = peer.spiffe_id
            self._send(*handle(svc, admin_token, method, self.path, body, headers))

        def do_GET(self): self._do("GET")
        def do_POST(self): self._do("POST")

        def _send(self, code, obj):
            if isinstance(obj, str):                       # /metrics: Prometheus text exposition
                data, ctype = obj.encode(), "text/plain; version=0.0.4"
            else:
                data, ctype = json.dumps(obj).encode(), "application/json"
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):   # no default access log (could contain paths/ids)
            pass

    if mtls is None:
        return ThreadingHTTPServer((host, port), H)

    from ..mtls.errors import MtlsError

    class MtlsHTTPServer(ThreadingHTTPServer):
        """TLS handshake + peer authentication happen in the per-request worker thread (not the
        accept thread), so a stalled client cannot block other connections."""
        daemon_threads = True

        def finish_request(self, request, client_address):
            try:
                tls, peer = mtls.accept(request)
            except MtlsError:
                return                                    # endpoint already closed + counted it
            tls.agentguard_peer = peer
            try:
                self.RequestHandlerClass(tls, client_address, self)
            finally:
                try:
                    tls.close()
                except Exception:  # noqa: BLE001
                    pass

        def shutdown_request(self, request):
            pass                                          # closed in finish_request

    return MtlsHTTPServer((host, port), H)


def serve_forever(server, *, on_shutdown=None, install_signal_handlers: bool = True):
    """Run ``server`` until SIGTERM/SIGINT, then shut down gracefully.

    Graceful shutdown (Step 7): stop accepting new connections, let in-flight requests finish
    (``daemon_threads`` + ``block_on_close``), then run ``on_shutdown`` (close the DB pool, Redis
    client, coordination scheduler). This is what makes a rolling update safe: a replica that is
    being replaced drains instead of dropping in-flight security decisions.
    """
    stop = threading.Event()

    def _handle(signum, _frame):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    if install_signal_handlers:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _handle)
            except (ValueError, OSError):     # not the main thread / unsupported platform
                pass
    try:
        server.serve_forever()
    finally:
        try:
            server.server_close()
        except Exception:  # noqa: BLE001
            pass
        if on_shutdown is not None:
            try:
                on_shutdown()
            except Exception:  # noqa: BLE001
                pass