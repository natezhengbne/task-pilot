$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$n8nDataDir = Join-Path $repoRoot ".n8n"
New-Item -ItemType Directory -Force -Path $n8nDataDir | Out-Null

# Keep n8n state local to this workspace
$env:N8N_USER_FOLDER = $n8nDataDir
# Point n8n HTTP Request nodes to the local Bun TaskPilot API
if (-not $env:TASKPILOT_API_URL) {
  $env:TASKPILOT_API_URL = "http://127.0.0.1:3456"
}
$env:N8N_BLOCK_ENV_ACCESS_IN_NODE = "false"

Write-Host "Starting n8n (latest) natively on Windows (for local dev; workflow is v3-compatible)..."
Write-Host "  n8n Data        : $n8nDataDir"
Write-Host "  TaskPilot API   : $env:TASKPILOT_API_URL"
Write-Host "  n8n UI URL      : http://localhost:5678"
Write-Host ""
Write-Host "Make sure TaskPilot API is running in another terminal: bun run dev"

npx --yes n8n@latest start
