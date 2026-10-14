# Provenance & Integrity Record

This file records what is **new work** produced for the integration, what is **upstream code**,
and the integrity evidence for both.

## 1. Upstream source trees (included, unmodified)

Both trees are included because `integration/tests/conftest.py` imports the **real** libraries and
the end-to-end test compiles the real `happy-lang/examples/banking.hpy` before authorizing it
against a real AgentGuard server. Excluding them would make the suite unrunnable and would mean the
tests no longer prove what they claim.

### Verification method

Content-checksum comparison (`rsync -rcn`, which compares file contents, not just mtimes) between
the audited extractions and the copies staged here, excluding only Python bytecode caches and
build metadata:

```bash
rsync -rcn --exclude=__pycache__ --exclude='*.pyc' \
      --exclude='*.egg-info' --exclude=.pytest_cache \
      --out-format='%n' audit/src/agentguard/agentguard_v7_phase9/ integration/agentguard/
```

| Tree | Origin archive | Files | Differing files |
|---|---|---|---|
| `integration/agentguard` | `agentguard_v7_phase9.zip` | 369 | **0** |
| `integration/happy-lang` | `happy-lang-v10-hardened.zip` | 136 | **0** |

**Result: 0 differing files in each tree.** No line of AgentGuard's `src/` or Happy LANG's `happy/`
was modified by the integration. The integration is purely additive.

Excluded from the package (build/run artefacts, not source):

* `__pycache__/`, `*.pyc` — Python bytecode caches
* `.pytest_cache/` — pytest run state
* `*.egg-info/` — editable-install metadata

`agentguard/supply_chain_out/` **is** retained: it ships inside the original upstream archive
(bandit / pip-audit / SBOM outputs) and is part of the audited artefact.

## 2. New work produced for the integration

| Path | Origin | Description |
|---|---|---|
| `integration/contract/agentguard_happy_contract/` | **NEW (M1)** | The integration package — 11 modules forming the versioned typed contract, validator, feature-flag config, PDPs, authorizer (trust boundary), executor and audit forwarding |
| `integration/contract/README.md` | **NEW (M1)** | Package-level install/config/limits documentation |
| `integration/tests/` | **NEW (M1)** | 5 test suites + `live_stack.py` harness + `conftest.py` |
| `docs/AUDIT_REPORT.md` | **NEW (Step 1)** | Integration audit, Markdown |
| `docs/AUDIT_REPORT.html` | **NEW (Step 1)** | Integration audit, rendered |
| `docs/INTEGRATION_README.md` | **NEW (M1)** | Installation, configuration, supported features, limitations, troubleshooting |
| `docs/INTEGRATION_IMPLEMENTATION_REPORT.html` | **NEW (M1)** | M1 implementation report with executed test evidence |
| `README.md`, `MANIFEST.md`, `PROVENANCE.md`, `requirements.txt`, `RUN_TESTS.sh` | **NEW (packaging)** | This package's own documentation and tooling |

## 3. Test evidence

Executed in a fresh sandbox from the staged package:

```
$ cd integration && python3 -m pytest tests/ -q
103 passed in 1.17s
```

Environment: Python 3.11.15, pytest 9.1.1, cryptography 50.0.2.

The end-to-end test performs a real authenticated `POST /v1/authorize` against a real AgentGuard
`IdentityService` HTTP server holding a real issued credential — the ALLOW and DENY decisions
observed are AgentGuard's own, not simulated responses.

## 4. Not included (and why)

* **PostgreSQL / Redis data directories, OPA binary, SPIFFE/SPIRE bundles, KMS material** — the
  integration suite does not require them; the audit's full-suite runs against real PostgreSQL and
  Redis are documented in `docs/AUDIT_REPORT.md`, not reproduced here.
* **`audit/src/*.zip` original archives and the `audit/` working tree** — upstream inputs to the
  audit, already represented by the two source trees above.
