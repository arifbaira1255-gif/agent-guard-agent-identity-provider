"""Phase 9 -- production server entrypoint tests.

Exercises the real HTTP server (in-process, ephemeral port) end to end: health/readiness semantics,
authentication enforcement, the console asset, request-size limits, and graceful shutdown. These
are integration tests over the actual server object, not mocks.
"""
from __future__ import annotations

import json
import os
import threading
import unittest
import urllib.error
import urllib.request

from agent_identity.server import ConfigError, Stack, build_server, validate_environment


def _dev_env():
    os.environ.setdefault("AGENTGUARD_ENV", "development")
    os.environ.setdefault("AGENTGUARD_SESSION_SECRET", "dev-secret-dev-secret-dev-secret-32")
    if not os.environ.get("AGENT_IDENTITY_MASTER_KEY"):
        from cryptography.fernet import Fernet
        os.environ["AGENT_IDENTITY_MASTER_KEY"] = Fernet.generate_key().decode()


class EnvironmentValidationTests(unittest.TestCase):
    def test_production_refuses_local_dev_kms(self):
        saved = dict(os.environ)
        try:
            os.environ.update({"AGENTGUARD_ENV": "production",
                               "AGENTGUARD_SESSION_SECRET": "a" * 40,
                               "AGENT_IDENTITY_MASTER_KEY": "x",
                               "AGENTGUARD_KMS_PROVIDER": "local-dev"})
            with self.assertRaises(ConfigError):
                validate_environment()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_production_refuses_short_session_secret(self):
        saved = dict(os.environ)
        try:
            os.environ.update({"AGENTGUARD_ENV": "production", "AGENTGUARD_SESSION_SECRET": "short",
                               "AGENT_IDENTITY_MASTER_KEY": "x", "AGENTGUARD_KMS_PROVIDER": "aws-kms"})
            with self.assertRaises(ConfigError):
                validate_environment()
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def test_development_allows_defaults(self):
        saved = dict(os.environ)
        try:
            os.environ["AGENTGUARD_ENV"] = "development"
            s = validate_environment()
            self.assertEqual(s["environment"], "development")
        finally:
            os.environ.clear()
            os.environ.update(saved)


class ServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Snapshot the environment: this class sets AGENTGUARD_SESSION_SECRET / _MASTER_KEY, and
        # leaking them would change the behaviour of unrelated tests (e.g. TokenSigner's
        # production-requires-secret check). Restore in tearDownClass.
        cls._saved_env = dict(os.environ)
        _dev_env()
        cls.stack = Stack(environment="development",
                          session_secret=os.environ["AGENTGUARD_SESSION_SECRET"],
                          master_key=os.environ["AGENT_IDENTITY_MASTER_KEY"],
                          bootstrap_admin=True, admin_email="admin@agentguard.local",
                          admin_password="ChangeMe-Dev-Only-1!")
        cls.httpd = build_server(cls.stack, host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.begin_drain()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.stack.close()
        os.environ.clear()
        os.environ.update(cls._saved_env)

    def _get(self, path, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_liveness_is_process_only(self):
        code, body = self._get("/livez")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["status"], "alive")

    def test_readiness_reports_checks(self):
        code, body = self._get("/readyz")
        self.assertIn(code, (200, 503))
        self.assertIn("checks", json.loads(body))

    def test_console_is_served(self):
        code, body = self._get("/")
        self.assertEqual(code, 200)
        self.assertIn("<html", body.lower())

    def test_unauthenticated_session_is_401(self):
        code, _ = self._get("/v2/session")
        self.assertEqual(code, 401)

    def test_security_headers_present(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/livez")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIsNotNone(r.headers.get("Strict-Transport-Security"))

    def test_oversized_body_rejected(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/auth/login",
                                     data=b"x" * (300 * 1024), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        self.assertEqual(code, 413)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
