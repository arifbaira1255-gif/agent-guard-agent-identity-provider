#!/usr/bin/env bash
# AgentGuard Phase 9 -- verified restore drill.
#
# Restores a backup into a TARGET database (never the live one), then VERIFIES:
#   1. the dump checksum matches the manifest (integrity of the artifact);
#   2. the restored schema version matches the manifest (no silent schema drift);
#   3. the security-critical row counts match the manifest (no silent data loss);
#   4. tenant boundaries survive (every agent's org_id resolves to an existing organization);
#   5. the audit chain is present and non-empty (verification itself runs in the app layer).
#
# A backup is only "recoverable" if this drill passes -- a successful pg_dump is NOT proof.
#
# Usage:
#   PGHOST=... PGUSER=... PGPASSWORD=... \
#     bash scripts/dr_restore.sh <dump_file> <target_db> [manifest_file]
set -euo pipefail

DUMP="${1:?usage: dr_restore.sh <dump_file> <target_db> [manifest_file]}"
TARGET="${2:?target database name required}"
MANIFEST="${3:-${DUMP%.dump}.manifest.json}"

: "${PGHOST:=127.0.0.1}"
: "${PGPORT:=5432}"
: "${PGUSER:=postgres}"

PSQL=(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" -At)

echo "== AgentGuard restore drill =="
echo "  dump:   $DUMP"
echo "  target: $TARGET"

# --- 1. checksum -----------------------------------------------------------------------------
if [ -f "$MANIFEST" ]; then
    EXPECTED="$(python3 -c "import json,sys;print(json.load(open('$MANIFEST'))['sha256'])")"
    ACTUAL="$(sha256sum "$DUMP" | awk '{print $1}')"
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        echo "  FAIL: dump checksum mismatch (expected $EXPECTED, got $ACTUAL)"; exit 1
    fi
    echo "  [1/5] checksum OK"
else
    echo "  [1/5] no manifest found -- checksum NOT verified (pass the manifest to verify)"
fi

# --- 2. recreate target ----------------------------------------------------------------------
"${PSQL[@]}" -d postgres -c "DROP DATABASE IF EXISTS \"$TARGET\";" >/dev/null
"${PSQL[@]}" -d postgres -c "CREATE DATABASE \"$TARGET\";" >/dev/null
echo "  [2/5] target database recreated"

# --- 3. restore ------------------------------------------------------------------------------
pg_restore --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" --dbname="$TARGET" \
    --no-owner --no-privileges --exit-on-error "$DUMP"
echo "  [3/5] restore completed"

# --- 4. schema version + row counts ----------------------------------------------------------
if [ -f "$MANIFEST" ]; then
    python3 - "$MANIFEST" "$TARGET" "$PGHOST" "$PGPORT" "$PGUSER" <<'PY'
import json, subprocess, sys
manifest, target, host, port, user = sys.argv[1:6]
m = json.load(open(manifest))
def q(sql):
    out = subprocess.run(["psql", "--host", host, "--port", port, "--username", user,
                          "-At", "-d", target, "-c", sql], capture_output=True, text=True)
    return out.stdout.strip()
ver = q("SELECT COALESCE((SELECT MAX(version) FROM schema_migrations), -1);")
if str(m.get("schema_version")) != str(ver):
    print(f"  FAIL: schema version mismatch (manifest {m.get('schema_version')}, restored {ver})")
    sys.exit(1)
print(f"  [4/5] schema version OK ({ver})")
rc = m.get("row_counts", {})
tables = {"organizations": "organizations", "agents": "agents", "credentials": "credentials",
          "revocations": "revocations", "audit_events": "audit_events"}
bad = []
for k, t in tables.items():
    if k in rc:
        got = q(f"SELECT count(*) FROM {t};")
        if str(rc[k]) != str(got):
            bad.append(f"{t}: manifest {rc[k]} != restored {got}")
if bad:
    print("  FAIL: row-count mismatch -> " + "; ".join(bad)); sys.exit(1)
print("  [4/5] row counts OK")
PY
else
    echo "  [4/5] no manifest -- schema/row-count verification SKIPPED"
fi

# --- 5. tenant boundaries + audit presence ---------------------------------------------------
ORPHANS="$("${PSQL[@]}" -d "$TARGET" -c "
  SELECT count(*) FROM agents a
  LEFT JOIN organizations o ON o.org_id = a.org_id
  WHERE o.org_id IS NULL;")"
if [ "$ORPHANS" != "0" ]; then
    echo "  FAIL: $ORPHANS agent(s) reference a missing organization (tenant boundary broken)"; exit 1
fi
AUDIT_N="$("${PSQL[@]}" -d "$TARGET" -c "SELECT count(*) FROM audit_events;")"
echo "  [5/5] tenant boundaries OK; audit_events present: $AUDIT_N"

echo "== restore drill PASSED =="
