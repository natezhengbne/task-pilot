param(
  [string]$Distro = "",
  [string]$Image = "docker.n8n.io/n8nio/n8n:latest",
  [string]$ContainerName = "taskpilot-n8n",
  [int]$Port = 5678,
  [int]$ApiPort = 3456
)

$ErrorActionPreference = "Stop"

$wslBaseArgs = @()
if ($Distro.Trim()) {
  $wslBaseArgs += @("-d", $Distro.Trim())
}

# Verify WSL + Docker are available
$dockerCheck = & wsl @wslBaseArgs -e sh -c "command -v docker >/dev/null 2>&1 && echo OK || echo MISSING"
if (($dockerCheck | Out-String).Trim() -ne "OK") {
  Write-Error "Docker CLI was not found inside WSL. Install Docker in WSL (or enable Docker Desktop WSL2 integration) and retry."
  exit 1
}

# Detect Windows host IP reachable from WSL2 (falls back to host-gateway for mirrored networking / Docker Desktop)
$winHostIp = (& wsl @wslBaseArgs -e sh -c "ip route show | awk '/default/ {print \$3; exit}'" | Out-String).Trim()
$hostMapping = if ($winHostIp) { "host.docker.internal:$winHostIp" } else { "host.docker.internal:host-gateway" }
$apiUrl = "http://host.docker.internal:$ApiPort"

Write-Host "Starting n8n in WSL Docker..."
Write-Host "  Image           : $Image"
Write-Host "  Container       : $ContainerName"
Write-Host "  n8n UI URL      : http://localhost:$Port"
Write-Host "  TaskPilot API   : $apiUrl ($hostMapping)"
Write-Host ""
Write-Host "Make sure TaskPilot API is running on Windows listening on 0.0.0.0:"
Write-Host "  bun run dev:wsl"
Write-Host ""
Write-Host "Note: If n8n cannot reach port $ApiPort on Windows, allow inbound TCP $ApiPort in Windows Defender Firewall for WSL."
Write-Host ""

# Remove stale container with the same name if stopped
& wsl @wslBaseArgs -e sh -c "docker rm -f $ContainerName >/dev/null 2>&1 || true"

$dockerCmd = @(
  "docker run -it --rm",
  "--name $ContainerName",
  "-p ${Port}:5678",
  "-v taskpilot_n8n_data:/home/node/.n8n",
  "--add-host=$hostMapping",
  "-e TASKPILOT_API_URL=$apiUrl",
  "-e N8N_BLOCK_ENV_ACCESS_IN_NODE=false",
  "-e N8N_SECURE_COOKIE=false",
  $Image
) -join " "

& wsl @wslBaseArgs -e sh -c $dockerCmd
