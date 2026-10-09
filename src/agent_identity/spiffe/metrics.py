"""Tiny thread-safe metrics registry (counters + latency histogram). Never records secrets,
SPIFFE IDs, tokens or certificates: only fixed metric names and a closed set of reason labels."""
import threading
from collections import defaultdict

BUCKETS = (0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)


class Metrics:
    def __init__(self):
        self._l = threading.Lock()
        self._c = defaultdict(int)
        self._h = defaultdict(lambda: {"count": 0, "sum": 0.0, "b": [0] * (len(BUCKETS) + 1)})

    def inc(self, name: str, label: str = "", n: int = 1) -> None:
        with self._l:
            self._c[(name, label)] += n

    def get(self, name: str, label: str = "") -> int:
        with self._l:
            return self._c[(name, label)]

    def total(self, name: str) -> int:
        with self._l:
            return sum(v for (n, _), v in self._c.items() if n == name)

    def observe(self, name: str, seconds: float) -> None:
        with self._l:
            h = self._h[name]
            h["count"] += 1
            h["sum"] += seconds
            for i, b in enumerate(BUCKETS):
                if seconds <= b:
                    h["b"][i] += 1
                    break
            else:
                h["b"][-1] += 1

    def snapshot(self) -> dict:
        with self._l:
            return {"counters": {f"{n}{{reason={l}}}" if l else n: v
                                 for (n, l), v in sorted(self._c.items())},
                    "histograms": {n: {"count": h["count"], "sum": h["sum"]}
                                   for n, h in self._h.items()}}

    def render_prometheus(self) -> str:
        out = []
        with self._l:
            for (n, l), v in sorted(self._c.items()):
                out.append(f'{n}{{reason="{l}"}} {v}' if l else f"{n} {v}")
            for n, h in sorted(self._h.items()):
                cum = 0
                for i, b in enumerate(BUCKETS):
                    cum += h["b"][i]
                    out.append(f'{n}_bucket{{le="{b}"}} {cum}')
                out.append(f'{n}_bucket{{le="+Inf"}} {h["count"]}')
                out.append(f"{n}_sum {h['sum']}")
                out.append(f"{n}_count {h['count']}")
        return "\n".join(out) + "\n"


SVID_ISSUED = "agentguard_svid_issued_total"
VERIFICATIONS = "agentguard_svid_verifications_total"
VERIFY_FAILURES = "agentguard_svid_verification_failures_total"
ROTATIONS = "agentguard_svid_rotations_total"
EXPIRED = "agentguard_svid_expired_total"
SPIRE_CONN_FAIL = "agentguard_spire_connection_failures_total"
BUNDLE_UPDATES = "agentguard_trust_bundle_updates_total"
BUNDLE_REJECTED = "agentguard_trust_bundle_rejected_total"
REFRESH_FAIL = "agentguard_svid_refresh_failures_total"
AUTH_LATENCY = "agentguard_authentication_latency_seconds"
