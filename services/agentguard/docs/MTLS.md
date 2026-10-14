# Step 6 - Production mTLS and service-to-service trust

Package: `agent_identity.mtls`. Built **on** the Step 4 SPIFFE/SPIRE adapter (`SpiffeIdentityProvider`,
`X509Source`, `TrustBundleStore`, `verify_x509_svid`) and the Step 5 KMS interfaces. It creates no second
workload-identity system. It does authentication only; what an authenticated peer may *do* is Step 8.

## Architecture

```
SPIRE agent --Workload API--> X509Source (rotates before expiry) --> RotatingTlsContext --> SSLContext
                         \--> TrustBundleStore (per-domain, max-age) -^       (rebuilt only when serial/roots change)
peer cert chain --> PeerAuthenticator --> PeerIdentity | PeerRejected
     1 verify_x509_svid  (chain vs bundle of the SVID's OWN trust domain, validity, leaf profile)
     2 EKU purpose       (clientAuth for inbound peers, serverAuth for outbound; required in staging/prod)
     3 TrustPolicy       (accepted trust domains, inbound/outbound allow-lists, explicit denies)
     4 CertDenylist      (revoked leaf certificates)
     5 provider.verify_x509 for AgentGuard agent IDs (binding, org/agent/instance status, delegation, revocation)
     6 client side: exact pin of the expected service SPIFFE ID (mandatory argument)
```
Hostnames are never used for identity. OpenSSL's chain check is a first filter; the SPIFFE checks above are
re-run on the chain the peer *presented*, after the handshake.

TLS 1.3 note: the client's handshake completes before the server has authenticated the client, so a
server-side rejection appears to the client as EOF/alert on first read. The server handler never runs.

## Usage
```python
cfg = MtlsConfig.from_env()                       # production by default; no secrets needed
ep  = MtlsEndpoint(cfg, provider, policy_holder)  # provider = build_identity_provider(svc, SpireConfig...)
ep.start()                                        # background bundle refresh
srv = MtlsServer(ep, handler).start()             # handler(tls_sock, PeerIdentity)
tls, peer = ep.connect(host, port, expected_spiffe_id="spiffe://td/service/identity-api")
http_transport.make_server(svc, admin_token, host, port, mtls=ep)   # existing HTTP API over mTLS
HealthServer(ep, port=9100).start()               # loopback-only /livez /readyz
```
`make_server` keeps the bearer token requirement: mTLS authenticates the calling *service*, the token
authorises the admin call. The server sets `X-Peer-Spiffe-Id` itself and drops any client-supplied copy.

## Trust policy
Deny by default: no policy loaded, or empty rules, trusts nobody. Rules are exact SPIFFE IDs or
segment-bounded prefixes (`spiffe://td/service/` never matches `spiffe://td/service-evil/...`); no wildcards or
regexes. `allow_agents` admits canonical AgentGuard agent IDs, each additionally registry-checked at every
connection. `denied` always wins. Policy versions are monotonic (rollback refused) and may expire.

Signed distribution: `sign_policy(kms_provider, key_id, policy, issued_at=...)` signs with a KMS/HSM-held Ed25519
key via the existing `KeyManagementProvider.sign` (sign-only; no export). `load_signed_policy(bundle,
trusted_signers)` verifies locally (no KMS round-trip needed at load time), then `PolicyHolder.set()` enforces
the version. A KMS outage blocks *signing* a new policy; it never weakens the policy already in force.

## Trust domains
`MtlsConfig.workload_spiffe_id` must be in the provider's trust domain. Federation is the existing opt-in
`SpireConfig.federated_trust_domains` **and** the policy's `accepted_trust_domains`; both must name a domain.
Federated peers have no AgentGuard agent binding (`UNBOUND`) and can only match explicit service rules.

## Rotation
* SVID: `X509Source` renews before expiry; `RotatingTlsContext` rebuilds contexts when the serial changes. New
  connections use the new cert; established connections are untouched (tested).
* Bundles: `MtlsEndpoint.start()` polls SPIRE every `bundle_refresh_interval_seconds`. Roots are a union per
  accepted domain, so an overlap period (old + new root) works. **Retire an old root only after SVIDs have been
  re-issued under the new one**; until then peers fail closed (tested).
* If SPIRE is down: the current SVID keeps serving until it expires (no needless outage), then handshakes are
  refused. Bundles older than `bundle_max_age_seconds` are refused. Readiness reports both.

## TLS configuration
`min_tls_version` TLSv1.3 (default) or TLSv1.2. TLS 1.2 suites are limited to ECDHE + AEAD
(`SAFE_TLS12_CIPHERS`); anything else fails config validation. TLS 1.3 suites are OpenSSL's fixed AEAD set
(Python cannot narrow them). Compression and renegotiation are disabled.

## Environments
`MtlsConfig` reuses `AGENTGUARD_ENV`; the process env can only tighten. `allow_plaintext` and
`require_eku=false` are development-only. `make_server` without `mtls=` is refused in staging/production, and
off-loopback when `AGENTGUARD_ENV` is unset. `HealthServer` binds loopback only. The endpoint class has no
plaintext path at all. The dev SPIRE mock is refused outside development by Step 4's guards.

## Health / readiness
`liveness()` = process alive. `readiness()` = coarse `ok|fail` for `identity` (own SVID valid, >=
`min_ready_remaining_seconds`), `trust_bundle`, `policy`, and `kms` (only if wired and marked required). It
returns no IDs, versions, paths or timings. Use an *exec* probe against the loopback `HealthServer`
(`python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:9100/readyz')"`); kubelet httpGet probes
cannot present a client certificate.

## Observability
Metrics (Prometheus via `MtlsMetrics.render_prometheus()`): `agentguard_mtls_handshakes_total`,
`_handshake_failures_total{reason}`, `_peer_rejected_total{reason}`, `_connection_failures_total`,
`_connections_refused_total`, `_certificate_rotations_total`, `_trust_bundle_changes_total`,
`_workload_api_failures_total`, `_policy_updates_total`, `_policy_rejected_total`, `_handshake_seconds`,
`_certificate_expiry_seconds`, `_active_connections`. Log events: `mtls.handshake`, `mtls.peer.rejected`,
`mtls.cert.rotated`, `mtls.cert.expiring`, `mtls.bundle.rotated`, `mtls.connect`, `mtls.refresh`,
`mtls.policy.update`. Labels come from closed reason sets; the logger allow-list drops anything else.

## Failure behaviour (all fail closed; each has a test)
expired / not-yet-valid / malformed / untrusted-chain peer; wrong or unpinned service; peer outside policy;
foreign trust domain; revoked cert or agent; missing, stale or unknown-domain bundle; own SVID expired or not
entitled; Workload API outage; no policy; TLS < min version; weak TLS 1.2 cipher; no client cert; plaintext
or garbage bytes; slow handshake (timeout, others unaffected); connection limit (shed, never skip auth).

## KMS/HSM: what is and is not true
* **Operational:** KMS-signed trust-policy distribution (above); KMS health as an optional readiness input.
* **Not operational:** hardware-backed *TLS private keys*. SVID keys are generated by SPIRE and handed to the
  workload over the Workload API; Python's `ssl` loads them into process memory (briefly via a 0600 temp file
  that is unlinked immediately). Keeping TLS keys in an HSM would need a SPIRE KeyManager/UpstreamAuthority
  plugin for the *CA* keys and an OpenSSL PKCS#11 provider for workload keys; neither is integrated here.
  Do not describe this deployment as HSM-backed TLS.

## Limitations
* The underlying RFC 5280 validator (`cryptography`) requires `clientAuth` on every SVID chain, so
  serverAuth-only leaves are rejected. SPIRE issues both EKUs, so this is a no-op with SPIRE.
* Connections are authenticated at establishment. Long-lived connections are not torn down when the peer's
  cert expires or agent state changes; handlers should consult `PeerIdentity.not_after` or re-check, and
  the HTTP server uses one request per connection.
* `CertDenylist` and `PolicyHolder` are per-process; distributing them across replicas is Step 7.
* Real SPIRE coverage: `tests/test_mtls_spire_integration.py` (5 tests) exists but was **not run** here.

## Prerequisites
SPIRE server + agent, Workload API socket mounted into the pod (`unix:///run/spire/sockets/agent.sock`),
registration entries per service (selectors owned by operators), `pip install 'agentguard-agent-identity[spire]'`
(grpcio), PostgreSQL for durable bindings in staging/production (Step 3), a signed policy bundle.
Run the real-SPIRE test: `integration/spire/run.sh` (needs Docker).

## Troubleshooting
`identity_unavailable`: no registration entry matches the workload, SPIRE agent socket unreachable, or SVID
expired. `trust_bundle_unavailable`: bundle stale/missing, check Workload API connectivity. `peer_chain_invalid`:
peer's SVID not under a root you trust (root rotation order?) or expired. `peer_identity_not_allowed`: peer
authenticated but not in policy. `peer_identity_mismatch`: connected to a different service than pinned.
`trust_policy_*`: no policy loaded, expired, or rollback. Check `agentguard_mtls_*_total{reason}` first.
