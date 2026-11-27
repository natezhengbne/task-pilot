#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.n8n.yml"

docker compose -f "${COMPOSE_FILE}" up -d "$@"

echo ""
echo "n8n is running in background:"
echo "  UI URL : http://localhost:${N8N_PORT:-5678}"
echo "  API    : ${TASKPILOT_API_URL:-http://localhost:3456}"
echo "  Logs   : docker compose -f scripts/docker-compose.n8n.yml logs -f n8n"
echo "  Stop   : docker compose -f scripts/docker-compose.n8n.yml down"
