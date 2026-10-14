$ErrorActionPreference = "Stop"

$dataDirectory = Join-Path $env:LOCALAPPDATA "Kuruta"
foreach ($name in @("agent", "server")) {
    $pidFile = Join-Path $dataDirectory "$name.pid"
    if (-not (Test-Path $pidFile)) {
        continue
    }

    $processId = 0
    $pidText = (Get-Content -Raw $pidFile).Trim()
    if (-not [int]::TryParse($pidText, [ref]$processId)) {
        throw "Invalid Kuruta $name process ID file: $pidFile"
    }
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -like "kuruta-*") {
        Stop-Process -Id $processId
    }
    Remove-Item -LiteralPath $pidFile
}

Write-Host "Kuruta stopped."
