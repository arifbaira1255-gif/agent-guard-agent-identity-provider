#!/usr/bin/env python3
"""Phase 8 development server: serves the management API (``/v2``), the legacy enterprise API
(``/v1``) and the static Enterprise Console over plain HTTP.

This is a **development / verification harness**, not a production server. It exists so the console,
the CLI and the SDKs can be exercised end to end against the real services (real auth service, real
RBAC, real audit log) without a full deployment. Production runs behind the existing mTLS/ingress
stack; see docs/PHASE8_IMPLEMENTATION.md.

Run::

    PYTHONPATH=src python3 scripts/phase8_dev_server.py --port 8443 --bootstrap-admin

Then::

    curl -s localhost:8443/v2/livez
    curl -s localhost:8443/            # the console
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_identity.api.enterprise_http import EnterpriseRouter, handle_enterprise
from agent_identity.api.management import ManagementApi
from agent_identity.core.clock import Clock
from agent_identity.observability.logging import SecurityLogger
from agent_identity.observability.phase8 import Observability
from agent_identity.security import (AdminOps, EnterpriseAuthConfig, EnterpriseAuthService,
                                     MemoryEnterpriseStore)
from agent_identity.security.admin_ops import bootstrap_platform_admin
from agent_identity.state.backend import MemoryBackend

CONSOLE_DIR = os.path.join(os.path.dirname(__file__), "..", "console")


def build_stack(*, bootstrap_admin: bool = False, admin_email: str = "admin@agentguard.local",
                admin_password: str = "ChangeMe-Dev-Only-1!"):
    """Wire the real services + the Phase 8 management API. Returns (management, auth_service)."""
    store = MemoryEnterpriseStore()
    logger = SecurityLogger(use_python_logging=False)
    clock = Clock()
    config = EnterpriseAuthConfig(environment="development", session_secret=b"d" * 32,
                                  cookie_secure=False)
    svc = EnterpriseAuthService(store, config, backend=MemoryBackend(), logger=logger, clock=clock)
    ops = AdminOps(store, svc.audit, config, permission_cache=svc.permission_cache,
                   sessions=svc.sessions, clock=clock)
    obs = Observability(logger=logger)
    obs.set_dependency("auth_store", up=True, detail="memory")
    obs.set_dependency("audit_log", up=True, detail="memory")
    api = ManagementApi(auth_service=svc, admin_ops=ops, config=config, clock=clock,
                        observability=obs)
    if bootstrap_admin:
        bootstrap_platform_admin(store, svc.audit, email=admin_email, password=admin_password,
                                 display_name="Dev Admin")
    return api, svc, config


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardDev/0.1"
    management = None
    router = None
    auth_service = None
    config = None

    def log_message(self, fmt, *args):                               # noqa: A003
        sys.stderr.write("[dev-server] " + (fmt % args) + "\n")

    # ------------------------------------------------------------------ helpers
    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return {}

    def _cookies(self) -> dict:
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _headers(self) -> dict:
        return {k: v for k, v in self.headers.items()}

    def _send(self, status: int, payload, extra: list):
        if isinstance(payload, (dict, list)):
            body = json.dumps(payload, default=str).encode("utf-8")
            ctype = "application/json"
        else:
            body = str(payload).encode("utf-8")
            ctype = "text/plain; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for hdr in (extra or []):
            # The router emits either a pre-formatted "Name=value; attrs" Set-Cookie string, or a
            # (name, value) / (name, value, attrs) tuple.
            if isinstance(hdr, str):
                self.send_header("Set-Cookie", hdr)
            elif len(hdr) == 3:
                k, v, attrs = hdr
                self.send_header(k, f"{v}; {attrs}" if attrs else v)
            else:
                k, v = hdr
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _serve_console(self, path: str) -> bool:
        if path in ("/", "/index.html", "/console", "/console/"):
            fp = os.path.join(CONSOLE_DIR, "index.html")
            if os.path.exists(fp):
                with open(fp, "rb") as fh:
                    body = fh.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
                return True
        return False

    # ------------------------------------------------------------------ verbs
    def _handle(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path
        if method == "GET" and self._serve_console(path):
            return
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else {}
        try:
            status, payload, extra = handle_enterprise(
                self.router, self.auth_service, method, self.path, body, self._headers(),
                self._cookies(), fallback=None, management=self.management)
        except Exception as e:                                       # noqa: BLE001
            status, payload, extra = 500, {"error": {"code": "internal_error",
                                                     "message": str(e)}}, []
        self._send(status, payload, extra)

    def do_GET(self):                                                # noqa: N802
        self._handle("GET")

    def do_POST(self):                                               # noqa: N802
        self._handle("POST")

    def do_PUT(self):                                                # noqa: N802
        self._handle("PUT")

    def do_DELETE(self):                                             # noqa: N802
        self._handle("DELETE")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AgentGuard Phase 8 dev server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--bootstrap-admin", action="store_true",
                   help="create a platform admin (dev only)")
    p.add_argument("--admin-email", default="admin@agentguard.local")
    p.add_argument("--admin-password", default="ChangeMe-Dev-Only-1!")
    args = p.parse_args(argv)

    api, svc, config = build_stack(bootstrap_admin=args.bootstrap_admin,
                                   admin_email=args.admin_email,
                                   admin_password=args.admin_password)
    ops = AdminOps(svc.store, svc.audit, config, permission_cache=svc.permission_cache,
                   sessions=svc.sessions, clock=Clock())
    Handler.management = api
    Handler.auth_service = svc
    Handler.config = config
    Handler.router = EnterpriseRouter(svc, ops, config)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AgentGuard dev server on http://{args.host}:{args.port}")
    print(f"  console:  http://{args.host}:{args.port}/")
    print(f"  livez:    http://{args.host}:{args.port}/v2/livez")
    if args.bootstrap_admin:
        print(f"  admin:    {args.admin_email} / {args.admin_password}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":                                           # pragma: no cover
    sys.exit(main())
