#!/usr/bin/env bash
# Usage: integration/spire/run.sh   (from repo root or anywhere). Needs docker compose v2, python3.10+, grpcio.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .run/sockets && chmod 777 .run/sockets
trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT
docker compose up -d spire-server
until [ "$(docker compose ps --format '{{.Health}}' spire-server)" = "healthy" ]; do sleep 1; done
export JOIN_TOKEN="$(docker compose exec -T spire-server /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://agentguard-it.internal/test-agent | awk '{print $2}')"
docker compose up -d spire-agent
for _ in $(seq 1 60); do [ -S .run/sockets/agent.sock ] && break; sleep 1; done
[ -S .run/sockets/agent.sock ] || { echo "agent socket did not appear"; docker compose logs spire-agent; exit 1; }
cd ../..
AGENTGUARD_SPIRE_INTEGRATION=1 \
AGENTGUARD_SPIRE_SOCKET="unix://$PWD/integration/spire/.run/sockets/agent.sock" \
AGENTGUARD_SPIRE_COMPOSE_DIR="$PWD/integration/spire" \
PYTHONPATH=src:. python3 -m unittest -v tests.test_spire_integration
