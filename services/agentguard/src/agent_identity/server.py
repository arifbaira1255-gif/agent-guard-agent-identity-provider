#!/usr/bin/env python3
"""AgentGuard production server entrypoint (Phase 9).

This is the ``serve`` command the Kubernetes manifest (``deploy/kubernetes/identity-service.yaml``)
references. It composes the **real** stack -- PostgreSQL-backed enterprise store, the existing
:class:`EnterpriseAuthService` (auth + RBAC + audit), :class:`AdminOps`, the Phase 8 ``/v2``
management API and the legacy ``/v1`` enterprise router -- behind one HTTP server, and exposes the
Step 7 health aggregator as ``/livez`` / ``/readyz``.

Design rules (Phase 9 §2, §8):

* **Fail closed on configuration.** In ``staging``/``production`` the server refuses to start with a
  missing session secret, a non-durable store, or a development-only KMS provider. It never silently
  downgrades a security control.
* **Liveness != readiness.** ``/livez`` is process-only (a dependency outage must not restart a
  healthy process). ``/readyz`` reflects every capability required to make a correct security
  decision and returns 503 when any is down, so the load balancer removes the instance.
* **Graceful shutdown.** On SIGTERM/SIGINT the listener stops accepting, in-flight requests drain
  within a bounded grace period, then the process exits -- so a rolling update never drops a request.
* **No fabricated success.** A plane that is not configured reports ``available: false`` with a
  reason; it is never presented as working.

Run::

    PYTHONPATH=src python3 -m agent_identity.server --host 0.0.0.0 --port 8443

Environment (see ``.env.example`` and ``docs/PHASE9_DEPLOYMENT.md``): ``AGENTGUARD_ENV``,
``AGENTGUARD_PG_*``, ``AGENTGUARD_REDIS_*``, ``AGENTGUARD_KMS_*``, ``AGENTGUARD_SESSION_SECRET``,
``AGENT_IDENTITY_MASTER_KEY``.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional, Tuple

from .api.enterprise_http import EnterpriseRouter, handle_enterprise
from .api.management import ManagementApi
from .core.clock import Clock
from .observability.logging import SecurityLogger
from .observability.phase8 import Observability
from .security import (AdminOps, EnterpriseAuthConfig, EnterpriseAuthService)
from .security.admin_ops import bootstrap_platform_admin

CONSOLE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "console")

#: environments in which development-only defaults are refused
_STRICT_ENVS = ("staging", "production")


class ConfigError(RuntimeError):
    """Raised when the process environment is not safe to start with."""


# --------------------------------------------------------------------------- config
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def validate_environment() -> dict:
    """Validate the process environment and return the resolved settings.

    Raises :class:`ConfigError` (fail closed) rather than starting with an unsafe default.
    """
    env = _env("AGENTGUARD_ENV", "development").lower()
    if env not in ("development", "staging", "production"):
        raise ConfigError("AGENTGUARD_ENV must be development|staging|production")

    secret = _env("AGENTGUARD_SESSION_SECRET")
    master = _env("AGENT_IDENTITY_MASTER_KEY")
    kms_provider = _env("AGENTGUARD_KMS_PROVIDER", "local-dev")

    if env in _STRICT_ENVS:
        if not secret or len(secret) < 32:
            raise ConfigError("AGENTGUARD_SESSION_SECRET (>=32 chars) is required outside development")
        if not master:
            raise ConfigError("AGENT_IDENTITY_MASTER_KEY is required outside development")
        if kms_provider == "local-dev":
            raise ConfigError("AGENTGUARD_KMS_PROVIDER=local-dev is refused outside development")
        if _env("AGENTGUARD_PG_SSLMODE", "verify-full") not in ("verify-full", "verify-ca"):
            raise ConfigError("PostgreSQL TLS with certificate verification is required outside development")
        if _env("AGENTGUARD_REDIS_TLS", "0") != "1":
            raise ConfigError("AGENTGUARD_REDIS_TLS=1 is required outside development")

    return {"environment": env, "session_secret": secret, "master_key": master,
            "kms_provider": kms_provider}


# --------------------------------------------------------------------------- stack
class Stack:
    """The composed runtime: services + health + shutdown coordination."""

    def __init__(self, *, environment: str, session_secret: str, master_key: str,
                 bootstrap_admin: bool = False, admin_email: str = "", admin_password: str = ""):
        self.environment = environment
        self.logger = SecurityLogger(use_python_logging=True)
        self.clock = Clock()
        self.observability = Observability(logger=self.logger)
        self._closers = []

        # --- authoritative store: PostgreSQL outside development, memory only in development.
        if environment in _STRICT_ENVS:
            from .storage.postgres.config import PgConfig
            from .storage.postgres.enterprise import PgEnterpriseStore
            from .storage.postgres.factory import build_postgres_storage
            pg_cfg = PgConfig.from_env()
            self.pg = build_postgres_storage(pg_cfg, [master_key.encode()], ensure_schema=True)
            self._closers.append(self.pg.close)
            self.store = PgEnterpriseStore(self.pg.db)
            self.observability.set_dependency("database", up=True, detail="postgresql")
        else:
            from .security import MemoryEnterpriseStore
            self.pg = None
            self.store = MemoryEnterpriseStore()
            self.observability.set_dependency("database", up=True, detail="memory (development)")

        # --- distributed security state (Redis). Required for a correct replay decision.
        self.state = None
        try:
            from .state.config import RedisConfig
            from .state.factory import build_security_state
            self.state = build_security_state(RedisConfig.from_env())
            self._closers.append(self.state.close)
            self.observability.set_dependency("redis", up=True, detail="redis")
        except Exception as e:  # noqa: BLE001
            if environment in _STRICT_ENVS:
                raise ConfigError(f"distributed security state (Redis) is required: {type(e).__name__}")
            self.observability.set_dependency("redis", up=False, detail="unavailable (development)")

        # --- auth + RBAC + audit
        cfg = EnterpriseAuthConfig(environment=environment,
                                   session_secret=session_secret.encode("utf-8") if session_secret else b"d" * 32,
                                   cookie_secure=(environment == "production"))
        self.auth_config = cfg
        self.auth = EnterpriseAuthService(self.store, cfg, backend=(self.state.backend if self.state else None),
                                          logger=self.logger, clock=self.clock)
        self.admin_ops = AdminOps(self.store, self.auth.audit, cfg,
                                  permission_cache=self.auth.permission_cache,
                                  sessions=self.auth.sessions, clock=self.clock)
        self.observability.set_dependency("audit_log", up=True, detail="ok")

        # --- Phase 8 management API + legacy /v1 router
        self.management = ManagementApi(auth_service=self.auth, admin_ops=self.admin_ops, config=cfg,
                                        clock=self.clock, observability=self.observability)
        self.router = EnterpriseRouter(self.auth, self.admin_ops, cfg)

        if bootstrap_admin and admin_email and admin_password:
            bootstrap_platform_admin(self.store, self.auth.audit, email=admin_email,
                                     password=admin_password, display_name="Bootstrap Admin")

    # ------------------------------------------------------------------ health
    def liveness(self) -> dict:
        return {"status": "alive"}

    def readiness(self) -> Tuple[int, dict]:
        checks = {}
        # database
        if self.pg is not None:
            try:
                checks["database"] = bool(self.pg.db.readiness()["ready"])
            except Exception:  # noqa: BLE001
                checks["database"] = False
        else:
            checks["database"] = True
        # redis
        if self.state is not None:
            try:
                checks["redis"] = bool(self.state.backend.ping())
            except Exception:  # noqa: BLE001
                checks["redis"] = False
        else:
            checks["redis"] = self.environment not in _STRICT_ENVS
        ready = all(checks.values())
        body = {"status": "ready" if ready else "not_ready",
                "checks": {k: ("ok" if v else "fail") for k, v in checks.items()}}
        return (200 if ready else 503), body

    def close(self) -> None:
        for fn in reversed(self._closers):
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuard/0.1"
    stack: Optional[Stack] = None
    max_body_bytes = 256 * 1024

    def log_message(self, fmt, *args):  # noqa: A003
        # Structured, secret-free access log (path only; never query strings or bodies).
        sys.stderr.write(json.dumps({"ts": time.time(), "event": "http_access",
                                     "method": self.command, "path": self.path.split("?")[0]}) + "\n")

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > self.max_body_bytes:
            return {"__oversize__": True}
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
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        for hdr in (extra or []):
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

    def _handle(self, method: str):
        st = self.stack
        path = self.path.split("?")[0]
        # Health endpoints are handled before any auth and never touch a dependency for liveness.
        if method == "GET" and path in ("/livez", "/healthz"):
            return self._send(200, st.liveness(), [])
        if method == "GET" and path == "/readyz":
            code, body = st.readiness()
            return self._send(code, body, [])
        if method == "GET" and self._serve_console(path):
            return
        body = self._read_body() if method in ("POST", "PUT", "PATCH") else {}
        if body.get("__oversize__"):
            return self._send(413, {"error": {"code": "payload_too_large",
                                              "message": "request body exceeds limit"}}, [])
        try:
            status, payload, extra = handle_enterprise(
                st.router, st.auth, method, self.path, body, dict(self.headers.items()),
                self._cookies(), fallback=None, management=st.management)
        except Exception as e:  # noqa: BLE001
            status, payload, extra = 500, {"error": {"code": "internal_error",
                                                     "message": "internal error"}}, []
        self._send(status, payload, extra)

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def do_PUT(self):  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self):  # noqa: N802
        self._handle("DELETE")


class GracefulHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server with bounded concurrency and graceful shutdown."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, max_workers: int = 64):
        super().__init__(addr, handler)
        self._sem = threading.BoundedSemaphore(max_workers)
        self._draining = threading.Event()

    def process_request(self, request, client_address):
        if self._draining.is_set():
            try:
                request.close()
            except OSError:
                pass
            return
        if not self._sem.acquire(blocking=False):
            # Shed load rather than queue unboundedly; never skip authentication.
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        finally:
            self._sem.release()

    def begin_drain(self):
        self._draining.set()


def build_server(stack: Stack, *, host: str, port: int, max_workers: int = 64) -> GracefulHTTPServer:
    Handler.stack = stack
    return GracefulHTTPServer((host, port), Handler, max_workers=max_workers)


def _run_migrate() -> int:
    """Apply schema migrations and exit. Used by the Kubernetes/Compose migration step.

    Production never auto-migrates at startup; this is the explicit, auditable migration path.
    """
    try:
        from .storage.postgres.config import PgConfig
        from .storage.postgres.db import Database
        from .storage.postgres import migrate
        cfg = PgConfig.from_env()
        db = Database(cfg)
        try:
            applied = migrate.migrate(db)
            head = migrate.current_version(db)
            sys.stderr.write(json.dumps({"event": "migrate_ok", "applied": applied,
                                         "head": head}) + "\n")
            return 0
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(json.dumps({"event": "migrate_failed", "type": type(e).__name__}) + "\n")
        return 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AgentGuard production server")
    p.add_argument("command", nargs="?", default="serve", choices=("serve", "migrate"),
                   help="serve (default) or migrate (apply schema migrations and exit)")
    p.add_argument("--host", default=_env("AGENTGUARD_LISTEN_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(_env("AGENTGUARD_LISTEN_PORT", "8443")))
    p.add_argument("--max-workers", type=int, default=int(_env("AGENTGUARD_MAX_WORKERS", "64")))
    p.add_argument("--grace-seconds", type=float, default=float(_env("AGENTGUARD_SHUTDOWN_GRACE_S", "25")))
    p.add_argument("--bootstrap-admin", action="store_true",
                   help="create a platform admin from AGENTGUARD_BOOTSTRAP_* (one-time, audited)")
    args = p.parse_args(argv)

    if args.command == "migrate":
        return _run_migrate()

    try:
        settings = validate_environment()
    except ConfigError as e:
        sys.stderr.write(json.dumps({"event": "startup_refused", "reason": str(e)}) + "\n")
        return 2

    # Bootstrap credentials: explicit env only outside development; documented dev defaults in
    # development so a local smoke test works without exporting secrets.
    boot_email = _env("AGENTGUARD_BOOTSTRAP_EMAIL")
    boot_password = _env("AGENTGUARD_BOOTSTRAP_PASSWORD")
    if args.bootstrap_admin and settings["environment"] == "development":
        boot_email = boot_email or "admin@agentguard.local"
        boot_password = boot_password or "ChangeMe-Dev-Only-1!"
    if args.bootstrap_admin and (not boot_email or not boot_password):
        sys.stderr.write(json.dumps({"event": "startup_refused",
                                     "reason": "AGENTGUARD_BOOTSTRAP_EMAIL/PASSWORD required outside development"}) + "\n")
        return 2

    try:
        stack = Stack(environment=settings["environment"], session_secret=settings["session_secret"],
                      master_key=settings["master_key"], bootstrap_admin=args.bootstrap_admin,
                      admin_email=boot_email, admin_password=boot_password)
    except ConfigError as e:
        sys.stderr.write(json.dumps({"event": "startup_refused", "reason": str(e)}) + "\n")
        return 2

    httpd = build_server(stack, host=args.host, port=args.port, max_workers=args.max_workers)
    stop = threading.Event()

    def _shutdown(signum, _frame):
        sys.stderr.write(json.dumps({"event": "shutdown_signal", "signal": signum}) + "\n")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            pass

    sys.stderr.write(json.dumps({"event": "started", "host": args.host, "port": args.port,
                                 "environment": settings["environment"]}) + "\n")
    t = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    t.start()
    try:
        while not stop.is_set():
            stop.wait(0.5)
    finally:
        # Graceful drain: stop accepting, let in-flight requests finish, then close.
        httpd.begin_drain()
        httpd.shutdown()
        deadline = time.monotonic() + args.grace_seconds
        while time.monotonic() < deadline and threading.active_count() > 1:
            time.sleep(0.05)
        httpd.server_close()
        stack.close()
        sys.stderr.write(json.dumps({"event": "stopped"}) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
