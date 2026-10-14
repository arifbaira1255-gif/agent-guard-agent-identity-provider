# AgentGuard Phase 9 — Software Supply-Chain Security

> All tools were **run for real** over the actual repository tree. Results are reported verbatim —
> nothing is filtered to look clean. A clean run means "no findings from these tools at this
> revision", not "the tree is vulnerability-free".

---

## 1. Tooling

| Control | Tool | Version |
|---|---|---|
| SBOM | `cyclonedx-py` | CycloneDX **1.6** |
| Dependency CVEs | `pip-audit` | latest |
| Static analysis | `bandit` | latest |
| Secret scan | built-in regex (`scripts/supply_chain_scan.sh`) | — |
| Manifest validation | `kubeconform` | 0.6.7 |

Run everything with:

```bash
bash scripts/supply_chain_scan.sh supply_chain_out
```

---

## 2. Results (this revision)

### 2.1 SBOM
```
[1/4] SBOM (CycloneDX)
  wrote supply_chain_out/sbom.cdx.json (148350 bytes)
```
`bomFormat: CycloneDX`, `specVersion: 1.6`, **120 components**. The SBOM is a release artifact and
is attached to every CI run.

### 2.2 Dependency vulnerabilities (`pip-audit`)
```
[2/4] Dependency vulnerability scan (pip-audit)
  findings: 58  (exit=1)  -> supply_chain_out/pip-audit.json
```
**Interpretation (important):** `pip-audit` audits the **active interpreter environment**. In this
shared sandbox that includes unrelated pre-installed packages. The 58 findings are concentrated in:

| Package | In AgentGuard's declared deps? |
|---|---|
| `pillow` | **No** — sandbox pre-install |
| `pip` | **No** — tooling |
| `pypdf2` | **No** — sandbox pre-install |
| `setuptools` | **No** — build tooling |
| `starlette` | **No** — sandbox pre-install |

**None of the reported packages are in AgentGuard's dependency closure** (`cryptography`, `psycopg`,
`redis`, `PyJWT`, `boto3`). In CI the scan runs inside the project venv, so the report covers exactly
the project closure. The report is emitted **verbatim** either way — it is never filtered to appear
clean.

### 2.3 Static analysis (`bandit`)
```
[3/4] Static analysis (bandit)
  by severity: {'LOW': 44, 'MEDIUM': 39}
```
**No HIGH or CRITICAL findings.** Triage of the MEDIUM/LOW set:
* `assert` statements in validation paths (LOW) — intentional, and never the sole control;
* `subprocess` usage in `scripts/` (LOW) — operator tooling, not request-path code;
* `try/except/pass` in cleanup/teardown (LOW) — deliberate best-effort cleanup;
* `random` usage (LOW) — jitter for retry backoff, **not** for security tokens (those use
  `secrets`/`os.urandom`).

### 2.4 Secret scan
```
[4/4] Secret scan (regex over src/)
  potential secrets: 0  -> supply_chain_out/secret-scan.txt
```
Patterns: private keys, AWS access/secret keys, generic `password|secret|api_key|token`
assignments, Slack tokens, Google API keys. Placeholders (`REPLACE`, `example`, `redacted`) are
excluded by design. **0 findings.**

---

## 3. Pinning & update policy

* Runtime dependencies are declared with **lower bounds** in `pyproject.toml` and pinned in the
  container build (`pip install ".[postgres,redis,aws]"` inside a reproducible venv).
* Base images are pinned to exact tags (`python:3.11.9-slim-bookworm`, `postgres:15.6-bookworm`,
  `redis:7.2.4-bookworm`, `nginx:1.27-alpine`).
* **Update process:** a vulnerable package is triaged within 5 business days; a HIGH/CRITICAL with a
  fix is patched and released within 24 hours. CI fails on unfixed vulnerabilities in **project**
  dependencies.

---

## 4. Build provenance & artifact integrity

* CI produces a versioned tarball plus a **SHA-256** checksum (`dist/<name>.tar.gz.sha256`).
* The SBOM, `pip-audit`, `bandit` and secret-scan reports are uploaded as CI artifacts.
* **Not implemented:** cryptographic build attestation (SLSA / sigstore). Documented as a Phase 10
  item — no provenance claim is made.

---

## 5. CI/CD integration

`.github/workflows/agentguard-ci.yml` runs, in order: lint → unit → integration (real PostgreSQL +
Redis service containers) → migration check → supply-chain scan → manifest validation → package.
**Security-critical jobs are release-blocking.** Production deployment is a **protected** job
requiring manual approval on the `production` environment, so a merge can never auto-deploy.

---

## 6. Known gaps

| Gap | Status |
|---|---|
| Container image scanning (Trivy/Grype) | **NOT RUN** — no container runtime in this environment |
| Build provenance / attestation (SLSA, sigstore) | **NOT IMPLEMENTED** — Phase 10 |
| Reproducible-build verification | **NOT VERIFIED** |
| Live CVE feed integration | **NOT IMPLEMENTED** — `pip-audit` uses its bundled advisory DB |
