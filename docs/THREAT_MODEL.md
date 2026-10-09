# Threat Model — Agent Identity subsystem

## Assets
Root/issuer/agent/credential private keys · issuer certificates & trust roots · agent/instance/credential
registries · revocation registry · replay cache · bearer tokens (passports) · audit logs.

## Trust boundaries
1. Agent runtime ↔ verifier/service (untrusted network; agent runtime semi-trusted: may be compromised).
2. Control-plane callers ↔ IdentityService (must be authenticated/authorised by the transport).
3. Service ↔ storage/KeyStore backends (trusted, but integrity-critical).
4. Root key custody ↔ online system.

## Attackers
External forger · compromised/prompt-injected agent · malicious sub-agent · network replayer ·
insider with registry write access · stolen-token holder · malicious tenant/org.

## Attack → mitigation
| Attack | Mitigation | Test |
|---|---|---|
| Forged / modified passport | Ed25519 over exact payload bytes; issuer chain to root | `test_06`, `test_07` |
| Algorithm confusion | no `alg` field; fixed Ed25519; domain separation | `test_18` |
| Unknown / spoofed issuer | issuer cert must chain to trusted root | `test_17`, `test_untrusted_chain` |
| Expired / over-long credential | exp check, max TTL policy at issue and verify | `test_08`, `test_ttl_policy` |
| Revoked credential/instance/agent/issuer | revocation checked every verify, cascades to descendants | `test_09`, issuer/agent tests |
| Replay of captured request | PoP proof: nonce + request_id cache, timestamp window, audience | `test_16`, replay tests |
| Stolen token (no key) | bearer token alone fails: proof must be signed by credential key | `test_stolen_token_without_key_useless` |
| Credential substitution | payload digest + registry cross-check; expected_agent/instance | `test_credential_substitution` |
| Privilege confusion / capability tampering | capabilities taken from registry, compared on verify; child ⊆ parent | tests in SubAgents |
| Fake sub-agent | no `parent_agent_id` at registration; spawn needs authenticated parent + `agent:spawn` | `test_15` |
| Predictable IDs | `secrets`-based 96–128 bit IDs | `test_03` |
| Private-key leakage | sign-only KeyStore, encrypted at rest, allow-list logger, redacted repr | `test_19`, `test_20` |
| Malicious metadata / log injection | allow-list regex, size/depth caps, control & bidi chars rejected | `test_02`, logger test |
| Verifier bug/exception | fail closed (`internal_error`) | by design |
| Replay-cache exhaustion | bounded; fails closed rather than accept | `MemoryReplayCache` |
| Token flooding | `max_token_bytes`, HTTP body cap | design |

## Assumptions
Host clock reasonably synchronised (skew configurable) · storage backends preserve integrity ·
transport authenticates control-plane callers · TLS in transit · root key protected.

## Residual risks
* Compromised agent runtime can use its own credential until expiry/revocation (mitigation: short TTL, fast revocation).
* Insider with registry write access can alter records (mitigation: DB permissions, signed audit trail — not implemented).
* In-memory reference stores lose state on restart and don't share across replicas.
* Python memory cannot be zeroized; local Fernet master key sits in process env.
* Bundled HTTP server: single static admin token, no rate limiting, no TLS.
* Revocation is pull-at-verify: replicas with stale caches could accept briefly (reference impl has none).
* Clock skew window (default 30 s) slightly widens expiry/proof acceptance.
* SPIRE attestation not implemented; `create_agent_instance` trusts its (authenticated) caller.
