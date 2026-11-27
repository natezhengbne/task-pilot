#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.windmill.yml"

docker compose -f "${COMPOSE_FILE}" up -d "$@"

echo ""
echo "Windmill is running in background:"
echo "  UI URL        : http://localhost:${WINDMILL_PORT:-8000}"
echo "  Default Login : admin@windmill.dev / changeme"
echo "  TaskPilot API : ${TASKPILOT_API_URL:-http://localhost:3456}"
echo "  Logs          : docker compose -f scripts/docker-compose.windmill.yml logs -f windmill_server windmill_worker"
echo "  Stop          : docker compose -f scripts/docker-compose.windmill.yml down"
