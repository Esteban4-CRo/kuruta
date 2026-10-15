# Script de instalación rápida de Kuruta para Windows
# Instala en $env:LOCALAPPDATA\Programs\Kuruta y crea accesos directos con icono oficial

param (
    [switch]$Uninstall = $false
)

$ErrorActionPreference = "Stop"

$AppName = "Kuruta IDS"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\Kuruta"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Kuruta.lnk"
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "Kuruta"
$StartShortcut = Join-Path $StartMenuDir "Kuruta.lnk"

if ($Uninstall) {
    Write-Host "Desinstalando Kuruta IDS..." -ForegroundColor Cyan
    if (Test-Path $DesktopShortcut) { Remove-Item $DesktopShortcut -Force }
    if (Test-Path $StartMenuDir) { Remove-Item $StartMenuDir -Recurse -Force }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Write-Host "Kuruta IDS desinstalado correctamente." -ForegroundColor Green
    return
}

Write-Host "==========================================" -ForegroundColor White
Write-Host "      Instalador de Kuruta IDS" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor White

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..\..")
$SourceExe = Join-Path $ProjectRoot "dist\release\kuruta-windows-x64.exe"
$SourceIcon = Join-Path $ProjectRoot "assets\kuruta-logo.ico"
$SourceLogo = Join-Path $ProjectRoot "assets\kuruta-logo.png"

if (-not (Test-Path $SourceExe)) {
    Write-Host "Error: No se encontró el binario $SourceExe" -ForegroundColor Red
    Write-Host "Ejecuta primero: python scripts/build_release.py --platform windows" -ForegroundColor Yellow
    exit 1
}

# Crear carpetas de destino
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
$AssetsDir = Join-Path $InstallDir "assets"
if (-not (Test-Path $AssetsDir)) {
    New-Item -ItemType Directory -Path $AssetsDir -Force | Out-Null
}

$DestExe = Join-Path $InstallDir "kuruta-windows-x64.exe"
$DestIcon = Join-Path $AssetsDir "kuruta-logo.ico"
$DestLogo = Join-Path $AssetsDir "kuruta-logo.png"

# Copiar archivos
Copy-Item $SourceExe $DestExe -Force
Copy-Item $SourceIcon $DestIcon -Force
Copy-Item $SourceLogo $DestLogo -Force

# Crear acceso directo en el menú de inicio
if (-not (Test-Path $StartMenuDir)) {
    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null
}

$WshShell = New-Object -ComObject WScript.Shell

$Shortcut = $WshShell.CreateShortcut($StartShortcut)
$Shortcut.TargetPath = $DestExe
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.IconLocation = "$DestIcon,0"
$Shortcut.Description = "Kuruta IDS - Sniffer y Analizador de Red Local"
$Shortcut.Save()

# Crear acceso directo en el Escritorio
$Desk = $WshShell.CreateShortcut($DesktopShortcut)
$Desk.TargetPath = $DestExe
$Desk.WorkingDirectory = $InstallDir
$Desk.IconLocation = "$DestIcon,0"
$Desk.Description = "Kuruta IDS - Sniffer y Analizador de Red Local"
$Desk.Save()

Write-Host "Kuruta IDS instalado exitosamente en: $InstallDir" -ForegroundColor Green
Write-Host "Acceso directo creado en el Escritorio con icono oficial." -ForegroundColor Green
Write-Host "Acceso directo anadido al Menu Inicio." -ForegroundColor Green
Write-Host "Nota: Recuerda tener instalado Npcap (https://npcap.com/) para capturar tramas." -ForegroundColor Yellow
