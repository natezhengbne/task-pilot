param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

$ErrorActionPreference = "Stop"
$composeFile = Join-Path $PSScriptRoot "docker-compose.windmill.yml"

docker compose -f $composeFile up -d @ComposeArgs

$port = if ($env:WINDMILL_PORT) { $env:WINDMILL_PORT } else { "8000" }
$apiUrl = if ($env:TASKPILOT_API_URL) { $env:TASKPILOT_API_URL } else { "http://localhost:3456" }

Write-Host ""
Write-Host "Windmill is running in background:"
Write-Host "  UI URL        : http://localhost:$port"
Write-Host "  Default Login : admin@windmill.dev / changeme"
Write-Host "  TaskPilot API : $apiUrl"
Write-Host "  Logs          : docker compose -f scripts/docker-compose.windmill.yml logs -f windmill_server windmill_worker"
Write-Host "  Stop          : docker compose -f scripts/docker-compose.windmill.yml down"
