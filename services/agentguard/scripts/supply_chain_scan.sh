#!/usr/bin/env bash
# AgentGuard Phase 9 -- software supply-chain scan.
#
# Runs, over the ACTUAL repository tree:
#   1. CycloneDX SBOM generation (Python dependencies)
#   2. Dependency vulnerability scan (pip-audit)
#   3. Static analysis (bandit)
#   4. Secret scan (regex over tracked source, excluding tests/fixtures)
#
# Every tool is invoked for real; the script reports what it actually found. It does NOT claim the
# tree is vulnerability-free -- a clean run means "no findings from these tools at this revision".
#
# Usage:  bash scripts/supply_chain_scan.sh [output_dir]
set -uo pipefail

OUT="${1:-supply_chain_out}"
mkdir -p "$OUT"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== AgentGuard supply-chain scan =="
echo "revision: $(git rev-parse --short HEAD 2>/dev/null || echo 'no-git')"
echo "date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "output:   $OUT"
echo

# --- 1. SBOM ---------------------------------------------------------------------------------
echo "[1/4] SBOM (CycloneDX)"
if command -v cyclonedx-py >/dev/null 2>&1; then
    cyclonedx-py environment --of json -o "$OUT/sbom.cdx.json" 2>"$OUT/sbom.err" \
        && echo "  wrote $OUT/sbom.cdx.json ($(wc -c < "$OUT/sbom.cdx.json") bytes)" \
        || { echo "  SBOM generation failed:"; cat "$OUT/sbom.err"; }
else
    echo "  cyclonedx-py not installed -- SKIPPED (install: pip install cyclonedx-bom)"
fi
echo

# --- 2. Dependency vulnerabilities -----------------------------------------------------------
# NOTE: pip-audit audits the ACTIVE interpreter environment. In CI this is the project venv, so
# the report covers exactly AgentGuard's dependency closure. In a shared sandbox it also covers
# unrelated pre-installed packages -- the report is emitted verbatim either way, never filtered to
# look clean.
echo "[2/4] Dependency vulnerability scan (pip-audit)"
if command -v pip-audit >/dev/null 2>&1; then
    pip-audit --format json --output "$OUT/pip-audit.json" 2>"$OUT/pip-audit.err"
    rc=$?
    if [ -f "$OUT/pip-audit.json" ]; then
        n=$(python3 -c "import json,sys;d=json.load(open('$OUT/pip-audit.json'));print(sum(len(x.get('vulns',[])) for x in d.get('dependencies',[])))" 2>/dev/null || echo "?")
        echo "  findings: $n  (exit=$rc)  -> $OUT/pip-audit.json"
    else
        echo "  pip-audit produced no report (exit=$rc):"; cat "$OUT/pip-audit.err" 2>/dev/null | head -5
    fi
else
    echo "  pip-audit not installed -- SKIPPED (install: pip install pip-audit)"
fi
echo

# --- 3. Static analysis ----------------------------------------------------------------------
echo "[3/4] Static analysis (bandit)"
if command -v bandit >/dev/null 2>&1; then
    bandit -r src -f json -o "$OUT/bandit.json" -q 2>"$OUT/bandit.err"
    rc=$?
    if [ -f "$OUT/bandit.json" ]; then
        python3 - "$OUT/bandit.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
sev = {}
for r in d.get("results", []):
    sev[r.get("issue_severity", "?")] = sev.get(r.get("issue_severity", "?"), 0) + 1
print("  by severity:", sev or "none")
PY
    else
        echo "  bandit produced no report (exit=$rc)"
    fi
else
    echo "  bandit not installed -- SKIPPED (install: pip install bandit)"
fi
echo

# --- 4. Secret scan --------------------------------------------------------------------------
echo "[4/4] Secret scan (regex over src/)"
python3 - "$OUT/secret-scan.txt" <<'PY'
import os, re, sys
out = sys.argv[1]
# High-signal patterns only (avoid noisy false positives on test fixtures).
pats = {
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}"),
    "generic_secret_assign": re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"][^'\"]{16,}['\"]"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
}
hits = []
for root, dirs, files in os.walk("src"):
    dirs[:] = [d for d in dirs if d not in ("__pycache__",)]
    for f in files:
        if not f.endswith((".py", ".json", ".yaml", ".yml", ".env", ".cfg", ".ini", ".toml")):
            continue
        p = os.path.join(root, f)
        try:
            for i, line in enumerate(open(p, encoding="utf-8", errors="ignore"), 1):
                for name, rx in pats.items():
                    if rx.search(line):
                        # Allow obvious placeholders / redaction markers.
                        low = line.lower()
                        if any(t in low for t in ("replace", "example", "redacted", "change-me",
                                                  "changeme", "dummy", "placeholder", "xxx", "<set>")):
                            continue
                        hits.append(f"{p}:{i}: {name}")
        except OSError:
            pass
with open(out, "w") as fh:
    fh.write("\n".join(hits) + ("\n" if hits else ""))
print(f"  potential secrets: {len(hits)}  -> {out}")
for h in hits[:20]:
    print("   ", h)
PY
echo
echo "== scan complete =="
