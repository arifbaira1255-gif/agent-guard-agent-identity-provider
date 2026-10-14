"""Fixtures for Step 6. MOCKED SPIRE: DevSpireCA + DevWorkloadTransport (real X.509/TLS crypto and
real sockets, but NOT a real SPIRE deployment). Real-SPIRE coverage is in
tests/test_mtls_spire_integration.py (skipped unless a SPIRE stack is available)."""
import socket
import threading
import time
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agent_identity.core.clock import Clock, FixedClock
from agent_identity.mtls import (MtlsConfig, MtlsEndpoint, MtlsServer, PolicyHolder, TrustPolicy)
from agent_identity.mtls.policy import PeerRules
from agent_identity.spiffe.dev import DevSpireCA, DevWorkloadTransport
from agent_identity.spiffe.provider import SpiffeIdentityProvider
from tests.spiffe_env import TD, Env as SpiffeEnv, cfg as spire_cfg

SRV = f"spiffe://{TD}/service/identity-api"
CLI = f"spiffe://{TD}/service/gateway"
OTHER = f"spiffe://{TD}/service/billing"


def now_clock():
    return FixedClock(time.time())          # OpenSSL uses wall-clock time: keep both aligned


def mtls_cfg(sid, **kw):
    d = dict(environment="development", workload_spiffe_id=sid, listen_host="127.0.0.1",
             listen_port=8443, handshake_timeout_seconds=3, connect_timeout_seconds=3,
             bundle_refresh_interval_seconds=0.05)
    d.update(kw)
    return MtlsConfig(**d).validate()


def policy(version=1, inbound=(), outbound=(), allow_agents=False, denied=(), domains=(TD,), **kw):
    return TrustPolicy(version, tuple(domains), PeerRules(tuple(inbound), (), allow_agents),
                       PeerRules(tuple(outbound), ()), tuple(denied), **kw)


class Node:
    """One simulated service process: its own provider/transport/bundles/policy/endpoint."""

    def __init__(self, env: SpiffeEnv, sid: str, pol: TrustPolicy, ca: DevSpireCA = None, **cfg_kw):
        self.env, self.sid = env, sid
        self.ca = ca or env.ca
        self.sp_cfg = env.cfg
        self.transport = DevWorkloadTransport(self.sp_cfg, self.ca, entitled=[sid])
        self.provider = SpiffeIdentityProvider(env.svc, self.sp_cfg, self.transport, clock=env.clock,
                                               sleep=lambda s: None, bindings=env.p.bindings)
        self.provider.refresh_bundles()
        self.policies = PolicyHolder(env.clock)
        self.policies.set(pol)
        self.cfg = mtls_cfg(sid, **cfg_kw)
        self.ep = MtlsEndpoint(self.cfg, self.provider, self.policies, clock=env.clock)


def echo_server(node: Node, **kw):
    seen = []

    def handler(tls, peer):
        seen.append(peer)
        data = tls.recv(64)
        tls.sendall(b"echo:" + data)
    srv = MtlsServer(node.ep, handler, port=0, **kw).start()
    srv.seen = seen
    return srv


def issue_leaf(ca: DevSpireCA, sid: str, *, eku=(ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH),
               ttl=3600, not_before=None):
    """Hand-built leaf for purpose / profile tests (signed by the CA's real signer)."""
    cert, key, inters = ca._signer
    now = ca.clock.now() if not_before is None else not_before
    lk = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "w")]))
         .issuer_name(cert.subject).public_key(lk.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(datetime.fromtimestamp(now - 1, tz=timezone.utc))
         .not_valid_after(datetime.fromtimestamp(now + ttl, tz=timezone.utc))
         .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(sid)]), False)
         .add_extension(x509.BasicConstraints(False, None), True)
         .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False))
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), False)
    leaf = b.sign(key, hashes.SHA256())
    D = serialization.Encoding.DER
    chain = leaf.public_bytes(D) + b"".join(c.public_bytes(D) for c in inters)
    kd = lk.private_bytes(D, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return chain, kd


def fast_env(ttl=6):
    """REAL wall clock + short-lived SVIDs: the only honest way to exercise renewal against OpenSSL,
    which always validates certificates against real time."""
    env = SpiffeEnv(clock_start=time.time(), rotation_min_remaining_seconds=0, rotation_threshold_fraction=0.5)
    env.clock = Clock()
    env.ca = DevSpireCA(TD, env.clock, x509_ttl=ttl)
    return env
