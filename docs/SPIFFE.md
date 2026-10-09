# SPIFFE/SPIRE integration (WIP, not production-ready)

Status: unit/adversarial tests pass (134, in-process dev Workload API with the real wire format and real
X.509/JWT crypto). NOT yet verified: real SPIRE integration test, `GrpcTransport`. Run
`integration/spire/run.sh` on a Docker host before trusting any of this.

## Architecture
```
SPIRE agent --(gRPC, unix socket, peer-cred attested)--> GrpcTransport
  -> WorkloadApiClient (retry/backoff, validate every response, fail closed)
     -> X509Source / JwtSource (rotate before expiry, serve valid SVID while refresh fails)
     -> TrustBundleStore (own TD + explicit federated allow-list, max age, atomic update)
  -> SpiffeIdentityProvider (verify, issue, bind, spawn_sub_agent) -> IdentityService (registry, revocation)
```
ID mapping (deterministic, no wildcards):
- agent:    `spiffe://<td>/org/<org>/agent/<agent_id>`
- instance: `spiffe://<td>/org/<org>/agent/<agent_id>/instance/<instance_id>`

A SPIFFE ID verifies only if bound to an AgentGuard agent/instance; status, revocation and ancestors are
re-checked on every verification. Restart => new instance => new SPIFFE ID. Sub-agents are bound only through
`spawn_sub_agent`, authorized by the parent's single-use JWT-SVID (audience `SPAWN_AUDIENCE`).

## Install
```
pip install -e .            # cryptography
pip install -e '.[spire]'   # + grpcio for the real Workload API
```

## Local development (no SPIRE)
```python
cfg = SpireConfig(environment="development", provider="dev", trust_domain="dev.agentguard.internal")
provider = build_identity_provider(service, cfg)   # dev CA + dev Workload API
```
`provider="dev"` is rejected outside `development`. Setting `AGENTGUARD_ENV=production|staging` in the process
makes a weaker config invalid (the env var can only tighten rules).

## Real SPIRE test environment
```
integration/spire/run.sh
```
Starts SPIRE server 1.9.6 + agent (join_token, `insecure_bootstrap`: TEST ONLY) and runs
`tests/test_spire_integration.py` (fetch, verify, JWT, unregistered ID, rotation, outage). Needs Docker
Compose v2 and `grpcio`. Entry flags (`-x509SVIDTTL`) and image tag are unverified against your SPIRE version.

## Production deployment
1. Run the SPIRE server/agent per your platform; use a real node attestor (k8s_psat, aws_iid, ...) and a
   bundle bootstrap (`trust_bundle_path`/`url`), never `insecure_bootstrap`.
2. Register entries, one per agent and instance ID. The runtime process is selected by selectors:
```
spire-server entry create -parentID spiffe://<td>/spire/agent/<node> \
  -spiffeID spiffe://<td>/org/acme/agent/<agent_id>/instance/<instance_id> \
  -selector k8s:ns:agents -selector k8s:sa:agentguard-runtime -x509SVIDTTL 3600
```
3. Mount the agent socket (read-only dir) into the workload; set `SPIFFE_ENDPOINT_SOCKET`.
4. Config: `config/spire.example.json` or env (`AGENTGUARD_ENV`, `AGENTGUARD_SPIFFE_TRUST_DOMAIN`,
   `AGENTGUARD_SPIFFE_FEDERATED_DOMAINS`). No secrets are needed: SPIRE attests the caller.
5. Share revocation, binding and replay stores across verifier replicas (in-memory defaults are per process).

## Trust domains
Only the configured trust domain and the explicit `federated_trust_domains` list are trusted. Bundles for
other domains are ignored and counted (`agentguard_trust_bundle_rejected_total`). An SVID from another domain is denied.

## SVID lifecycle and rotation
Fetch -> validate (chain, SPIFFE ID, TD, key present) -> cache. Rotation starts when remaining lifetime is
<= max(`rotation_min_remaining_seconds`, `rotation_threshold_fraction` x lifetime). Refresh is single-flight.
If refresh fails the still-valid SVID keeps being served; after expiry `current()` raises (deny).
Bundles older than `bundle_max_age_seconds` => `trust_bundle_stale` (deny); a forced refresh is rate-limited (5s).

## Failure behavior (all DENY)
Workload API unavailable / network interruption (retry, then `WorkloadApiUnavailable`), expired or
not-yet-valid SVID, malformed or corrupted SVID/bundle (last good bundle kept), bad chain, wrong
signature/audience/issuer/algorithm, unknown trust domain or key, stale bundle, unexpected exception.

## Security invariants
I1 deny when trust cannot be established; I2 SPIFFE ID must be bound; I3 path must equal binding exactly;
I4 registry state rechecked each verify; I5 sub-agents only via authorized spawn; I6 no private keys in
repr/logs/metrics; I7 any exception => deny. Not covered: compromised host/agent, SPIRE server compromise,
single-process stores (see deployment step 5).

## Metrics (Prometheus text via `provider.metrics.render_prometheus()`)
`agentguard_svid_issued_total`, `_verifications_total`, `_verification_failures_total{reason}`,
`_rotations_total`, `_expired_total`, `agentguard_spire_connection_failures_total`,
`agentguard_trust_bundle_updates_total`, `_rejected_total`, `agentguard_svid_refresh_failures_total`,
`agentguard_authentication_latency_seconds`.

## Troubleshooting
- `workload_api_unavailable`: socket path wrong/permissions, agent down, `grpcio` missing.
- `unbound_spiffe_id`: no registration entry matches this workload's selectors, or wrong ID.
- `trust_bundle_stale`: agent not delivering bundles; check agent logs and `bundle_max_age_seconds`.
- `svid_not_yet_valid`/`svid_expired`: clock drift between hosts (`clock_skew_seconds` max 60 outside dev).
- `ConfigError ... weaker than AGENTGUARD_ENV`: config environment is below the process environment.

## Benchmarks
`PYTHONPATH=src:. python3 benchmarks/bench_spiffe.py`; results in `docs/BENCHMARK_SPIFFE.txt`
(dev transport: excludes real UDS/gRPC latency; single machine, one run).
