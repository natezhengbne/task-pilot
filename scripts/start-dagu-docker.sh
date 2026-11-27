#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.dagu.yml"

docker compose -f "${COMPOSE_FILE}" up -d "$@"

echo ""
echo "Dagu is running in background:"
echo "  UI URL        : http://localhost:${DAGU_PORT:-8080}"
echo "  DAGs Dir      : workflows/dagu"
echo "  TaskPilot API : ${TASKPILOT_API_URL:-http://127.0.0.1:3456}"
echo "  Logs          : docker compose -f scripts/docker-compose.dagu.yml logs -f dagu"
echo "  Stop          : docker compose -f scripts/docker-compose.dagu.yml down"
