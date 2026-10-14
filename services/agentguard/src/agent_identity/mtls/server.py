"""Generic threaded mTLS server + loopback-only health listener + HTTP integration helpers."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from . import metrics as MM
from .endpoint import MtlsEndpoint
from .errors import M, MtlsConfigError, MtlsError


def _is_loopback(host: str) -> bool:
    return host in ("127.0.0.1", "::1", "localhost")


class MtlsServer:
    """Accepts TCP connections; the TLS handshake and peer authentication run in the WORKER thread
    (a slow/hostile client cannot block accepting). Bounded concurrency; graceful shutdown."""

    def __init__(self, endpoint: MtlsEndpoint, handler: Callable, host: Optional[str] = None,
                 port: Optional[int] = None):
        self.ep, self.handler = endpoint, handler
        cfg = endpoint.cfg
        self._sock = socket.create_server((host or cfg.listen_host, cfg.listen_port if port is None else port))
        self._sock.settimeout(0.2)
        self._sem = threading.BoundedSemaphore(cfg.max_concurrent_connections)
        self._stop = threading.Event()
        self._active = set()
        self._l = threading.Lock()
        self._thread = threading.Thread(target=self._loop, name="mtls-accept", daemon=True)

    @property
    def address(self):
        return self._sock.getsockname()

    def start(self) -> "MtlsServer":
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._sem.acquire(blocking=False):
                self.ep.metrics.inc(MM.CONN_REFUSED, M.OVERLOAD)
                raw.close()                                   # shed load; never skip authentication
                continue
            t = threading.Thread(target=self._serve, args=(raw,), daemon=True)
            with self._l:
                self._active.add(t)
            t.start()

    def _serve(self, raw):
        m = self.ep.metrics
        try:
            try:
                tls, peer = self.ep.accept(raw)
            except MtlsError:
                return
            m.add_gauge(MM.G_ACTIVE, 1)
            try:
                self.handler(tls, peer)
            except Exception:  # noqa: BLE001 - handler faults must not kill the server
                pass
            finally:
                m.add_gauge(MM.G_ACTIVE, -1)
                try:
                    tls.close()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            self._sem.release()
            with self._l:
                self._active.discard(threading.current_thread())

    def shutdown(self) -> bool:
        """Stop accepting, then wait up to shutdown_grace_seconds for in-flight connections."""
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
        end = self.ep.clock.now() + self.ep.cfg.shutdown_grace_seconds
        import time
        deadline = time.monotonic() + self.ep.cfg.shutdown_grace_seconds
        while time.monotonic() < deadline:
            with self._l:
                if not self._active:
                    return True
            time.sleep(0.02)
        return False


class HealthServer:
    """Plain-HTTP /livez and /readyz bound to LOOPBACK ONLY (refuses any other address), returning
    coarse ok/fail. Probe it with an exec probe from inside the container; it never exposes
    identities, versions or infrastructure details and offers no other route."""

    def __init__(self, endpoint: MtlsEndpoint, port: int = 0, host: str = "127.0.0.1"):
        if not _is_loopback(host):
            raise MtlsConfigError("health listener may only bind to loopback", M.PLAINTEXT_FORBIDDEN)
        ep = endpoint

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/livez":
                    code, body = 200, ep.liveness()
                elif self.path == "/readyz":
                    body = ep.readiness()
                    code = 200 if body["status"] == "ready" else 503
                else:
                    code, body = 404, {"error": "not_found"}
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass
        self.httpd = ThreadingHTTPServer((host, port), H)
        self.address = self.httpd.server_address
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self._t.start()
        return self

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
