#!/usr/bin/env bash
set -euo pipefail

IMAGE="${N8N_IMAGE:-docker.n8n.io/n8nio/n8n:latest}"
CONTAINER_NAME="${N8N_CONTAINER_NAME:-taskpilot-n8n}"
PORT="${N8N_PORT:-5678}"
API_PORT="${TASKPILOT_PORT:-3456}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker CLI not found in WSL. Install Docker in WSL or enable Docker Desktop WSL2 integration." >&2
  exit 1
fi

# Detect Windows host IP reachable from WSL2 (falls back to host-gateway)
WIN_HOST_IP="$(ip route show | awk '/default/ {print $3; exit}' || true)"
if [ -n "$WIN_HOST_IP" ]; then
  HOST_MAPPING="host.docker.internal:${WIN_HOST_IP}"
else
  HOST_MAPPING="host.docker.internal:host-gateway"
fi

API_URL="http://host.docker.internal:${API_PORT}"

echo "Starting n8n in WSL Docker..."
echo "  Image           : ${IMAGE}"
echo "  Container       : ${CONTAINER_NAME}"
echo "  n8n UI URL      : http://localhost:${PORT}"
echo "  TaskPilot API   : ${API_URL} (${HOST_MAPPING})"
echo ""
echo "Make sure TaskPilot API is running on Windows:"
echo "  bun run dev:wsl"
echo ""

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

exec docker run -it --rm \
  --name "${CONTAINER_NAME}" \
  -p "${PORT}:5678" \
  -v taskpilot_n8n_data:/home/node/.n8n \
  --add-host="${HOST_MAPPING}" \
  -e "TASKPILOT_API_URL=${API_URL}" \
  -e "N8N_BLOCK_ENV_ACCESS_IN_NODE=false" \
  -e "N8N_SECURE_COOKIE=false" \
  "${IMAGE}"
