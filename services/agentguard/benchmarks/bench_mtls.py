"""Measures mTLS handshake + authentication cost on loopback with the MOCKED SPIRE (real TLS/X.509)."""
import statistics, sys, time, threading
sys.path.insert(0, "."); sys.path.insert(0, "src")
from tests.mtls_env import CLI, SRV, Node, echo_server, policy
from tests.spiffe_env import Env

env = Env(clock_start=time.time())
s = Node(env, SRV, policy(inbound=(CLI,)))
c = Node(env, CLI, policy(outbound=(SRV,)))
srv = echo_server(s)
N = 300
lat = []
for _ in range(N):
    t = time.perf_counter()
    tls, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
    tls.sendall(b"x"); tls.recv(8); tls.close()
    lat.append((time.perf_counter() - t) * 1000)
lat.sort()
pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))]
print(f"sequential full connect+auth+roundtrip n={N}: p50={pct(.5):.2f}ms p95={pct(.95):.2f}ms p99={pct(.99):.2f}ms mean={statistics.mean(lat):.2f}ms")
svid = c.provider.x509_source(CLI).current()
t = time.perf_counter()
for _ in range(2000):
    s.ep.auth.authenticate(svid.chain_der(), direction="inbound")
print(f"authenticator only: {(time.perf_counter()-t)/2000*1e3:.3f} ms/op")
done = []
def w():
    for _ in range(25):
        t = time.perf_counter(); tls, _ = c.ep.connect(*srv.address, expected_spiffe_id=SRV)
        tls.sendall(b"x"); tls.recv(8); tls.close(); done.append(time.perf_counter() - t)
t0 = time.perf_counter(); ts = [threading.Thread(target=w) for _ in range(8)]
[x.start() for x in ts]; [x.join() for x in ts]
print(f"8 threads x 25: {len(done)/(time.perf_counter()-t0):.0f} conn/s (single process, GIL-bound, loopback)")
srv.shutdown()
