$ErrorActionPreference = "Stop"

$dataDirectory = Join-Path $env:LOCALAPPDATA "Kuruta"
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
$serverPath = Join-Path $PSScriptRoot "kuruta-server.exe"
$agentPath = Join-Path $PSScriptRoot "kuruta-agent.exe"

if (-not (Test-Path $serverPath) -or -not (Test-Path $agentPath)) {
    throw "Extract the complete Kuruta release ZIP before starting Kuruta."
}

$env:KURUTA_DB_PATH = Join-Path $dataDirectory "kuruta.db"
$server = Start-Process `
    -FilePath $serverPath `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $dataDirectory "server.log") `
    -RedirectStandardError (Join-Path $dataDirectory "server-error.log")
$agent = $null

try {
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($server.HasExited) {
            throw "Kuruta server exited during startup. Check $dataDirectory\server.log"
        }
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8765/health" -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $healthy = $true
                break
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not $healthy) {
        throw "Kuruta server did not become healthy at http://127.0.0.1:8765/health"
    }

    $agent = Start-Process `
        -FilePath $agentPath `
        -PassThru `
        -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $dataDirectory "agent.log") `
        -RedirectStandardError (Join-Path $dataDirectory "agent-error.log")

    Set-Content -Path (Join-Path $dataDirectory "server.pid") -Value $server.Id
    Set-Content -Path (Join-Path $dataDirectory "agent.pid") -Value $agent.Id
    Write-Host "Kuruta is running. Dashboard API: http://127.0.0.1:8765/docs"
    Write-Host "Logs and database: $dataDirectory"
    Write-Host "To stop Kuruta, run .\stop-kuruta.ps1"
}
catch {
    if ($agent -and -not $agent.HasExited) {
        Stop-Process -Id $agent.Id
    }
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id
    }
    throw
}
