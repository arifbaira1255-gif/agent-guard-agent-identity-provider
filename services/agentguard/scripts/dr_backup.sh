#!/usr/bin/env bash
# AgentGuard Phase 9 -- PostgreSQL logical backup with integrity manifest.
#
# Produces a compressed custom-format dump plus a manifest carrying the SHA-256 of the dump, the
# schema version, the row counts of the security-critical tables, and the RPO/RTO targets. The
# manifest is what makes a restore VERIFIABLE: a restore drill re-checks the checksum and the
# schema version before trusting the data.
#
# This backs up the AUTHORITATIVE store (PostgreSQL). Redis holds only transient state and is
# rebuilt from PostgreSQL on recovery (see docs/PHASE9_DR.md).
#
# Usage:
#   PGHOST=... PGUSER=... PGPASSWORD=... PGDATABASE=agentguard \
#     bash scripts/dr_backup.sh [output_dir]
set -euo pipefail

OUT="${1:-backups}"
mkdir -p "$OUT"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
DUMP="$OUT/agentguard_${TS}.dump"
MANIFEST="$OUT/agentguard_${TS}.manifest.json"

: "${PGDATABASE:=agentguard}"
: "${PGHOST:=127.0.0.1}"
: "${PGPORT:=5432}"
: "${PGUSER:=postgres}"

echo "== AgentGuard backup =="
echo "  database: $PGDATABASE @ $PGHOST:$PGPORT as $PGUSER"
echo "  dump:     $DUMP"

# Custom format (-Fc) is compressed and restorable selectively with pg_restore.
pg_dump -Fc -Z 6 -f "$DUMP" \
    --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" --dbname="$PGDATABASE"

SHA="$(sha256sum "$DUMP" | awk '{print $1}')"
SIZE="$(wc -c < "$DUMP" | tr -d ' ')"

# Schema version + security-critical row counts (best-effort; missing tables are reported as null).
IFS='|' read -r SCHEMA_VERSION ROWCOUNTS <<EOF
$(psql --host="$PGHOST" --port="$PGPORT" --username="$PGUSER" --dbname="$PGDATABASE" -At -F'|' -c "
  SELECT COALESCE((SELECT MAX(version) FROM schema_migrations), -1) AS v,
         json_build_object(
           'organizations', (SELECT count(*) FROM organizations),
           'agents',        (SELECT count(*) FROM agents),
           'credentials',   (SELECT count(*) FROM credentials),
           'revocations',   (SELECT count(*) FROM revocations),
           'audit_events',  (SELECT count(*) FROM audit_events)
         )::text;
" 2>/dev/null || echo "-1|{}")
EOF
SCHEMA_VERSION="${SCHEMA_VERSION:--1}"
if [ -z "${ROWCOUNTS:-}" ]; then ROWCOUNTS='{}'; fi

cat > "$MANIFEST" <<JSON
{
  "product": "agentguard",
  "created_at": "$TS",
  "database": "$PGDATABASE",
  "host": "$PGHOST",
  "dump_file": "$(basename "$DUMP")",
  "sha256": "$SHA",
  "size_bytes": $SIZE,
  "schema_version": ${SCHEMA_VERSION:--1},
  "row_counts": ${ROWCOUNTS},
  "rpo_target_seconds": ${AGENTGUARD_RPO_SECONDS:-300},
  "rto_target_seconds": ${AGENTGUARD_RTO_SECONDS:-3600},
  "restore_command": "bash scripts/dr_restore.sh $DUMP <target_db>"
}
JSON

echo "  sha256:   $SHA"
echo "  manifest: $MANIFEST"
echo "== backup complete =="
