#!/usr/bin/env bash
set -euo pipefail

docker compose up -d "$@"

echo ""
echo "n8n is running in background:"
echo "  UI URL : http://localhost:${N8N_PORT:-5678}"
echo "  API    : ${TASKPILOT_API_URL:-http://localhost:3456}"
echo "  Logs   : docker compose logs -f n8n"
echo "  Stop   : docker compose down"
