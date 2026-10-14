# Security posture and limitations (read before marketing this)

## What is verified in this build
`bash scripts/verify.sh` runs 25 tests (no network needed). They cover: deny-all/local/AgentGuard
gates, fail-closed behaviour on errors/timeouts/indeterminate answers, remote-deny-is-authoritative,
`allow_all` refused in production, audit history never storing arguments, `python_exec` disabled by
default, `unsafe_dev` refused in production and scrubbing the environment, and — on a host with a
jail backend — that jailed code cannot reach the network or read `/etc/passwd`, and that a real
Happy program runs inside the jail.

## NOT verified in this build
* The full AQL test suite, AgentGuard suite, Happy suite and the contract/platform suites were not
  re-run here (the build environment had no network and no web-stack dependencies installed).
  Their last reported results are in `docs/upstream/` and are the original authors' claims.
* Docker images were not built; the frontend was not built; compose syntax was only parsed.
* AgentGuard mode against a live server (credentials + proof-of-possession) — unit-tested with
  fakes only.
* No third-party penetration test. Isolation depends on the host's kernel and backend.

## Known limitations
* Happy LANG is **not** a security boundary by itself (it transpiles to Python). The boundary is
  the OS jail plus AgentGuard's decision.
* MCP client calls are not gated yet (see ARCHITECTURE).
* Plaintext HTTP between containers is acceptable only on a private network.
* `unsafe_dev` is for local development. It is not a sandbox.
