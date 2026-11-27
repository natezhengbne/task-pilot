param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

$ErrorActionPreference = "Stop"
$composeFile = Join-Path $PSScriptRoot "docker-compose.dagu.yml"

docker compose -f $composeFile up -d @ComposeArgs

$port = if ($env:DAGU_PORT) { $env:DAGU_PORT } else { "5678" }
$apiUrl = if ($env:TASKPILOT_API_URL) { $env:TASKPILOT_API_URL } else { "http://127.0.0.1:3456" }

Write-Host ""
Write-Host "Dagu is running in background:"
Write-Host "  UI URL        : http://localhost:$port"
Write-Host "  DAGs Dir      : workflows/dagu"
Write-Host "  TaskPilot API : $apiUrl"
Write-Host "  Logs          : docker compose -f scripts/docker-compose.dagu.yml logs -f dagu"
Write-Host "  Stop          : docker compose -f scripts/docker-compose.dagu.yml down"
