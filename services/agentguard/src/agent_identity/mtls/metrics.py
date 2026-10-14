"""mTLS metrics: reuses the spiffe Metrics registry (counters + latency histogram) and adds gauges.
Labels come from closed reason sets only: never SPIFFE IDs, certificates, tokens or keys."""
import threading

from ..spiffe.metrics import Metrics

HANDSHAKES = "agentguard_mtls_handshakes_total"
HANDSHAKE_FAIL = "agentguard_mtls_handshake_failures_total"
PEER_REJECTED = "agentguard_mtls_peer_rejected_total"
CONN_FAIL = "agentguard_mtls_connection_failures_total"
CONN_REFUSED = "agentguard_mtls_connections_refused_total"
CERT_ROTATIONS = "agentguard_mtls_certificate_rotations_total"
BUNDLE_ROTATIONS = "agentguard_mtls_trust_bundle_changes_total"
WORKLOAD_API_FAIL = "agentguard_mtls_workload_api_failures_total"
POLICY_UPDATES = "agentguard_mtls_policy_updates_total"
POLICY_REJECTED = "agentguard_mtls_policy_rejected_total"
HANDSHAKE_LATENCY = "agentguard_mtls_handshake_seconds"
G_CERT_EXPIRY = "agentguard_mtls_certificate_expiry_seconds"
G_ACTIVE = "agentguard_mtls_active_connections"


class MtlsMetrics(Metrics):
    def __init__(self):
        super().__init__()
        self._g = {}
        self._gl = threading.Lock()

    def set_gauge(self, name: str, value: float) -> None:
        with self._gl:
            self._g[name] = float(value)

    def gauge(self, name: str) -> float:
        with self._gl:
            return self._g.get(name, 0.0)

    def add_gauge(self, name: str, delta: float) -> None:
        with self._gl:
            self._g[name] = self._g.get(name, 0.0) + delta

    def render_prometheus(self) -> str:
        with self._gl:
            g = "".join(f"{n} {v}\n" for n, v in sorted(self._g.items()))
        return super().render_prometheus() + g
