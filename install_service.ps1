# FixAI Guardian — Windows Background Service Installer
# ========================================================
# Run this script in an elevated Administrator PowerShell prompt:
# powershell -ExecutionPolicy Bypass -File install_service.ps1

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  FixAI Guardian — Windows Autonomic Service Installer    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check for Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This installer requires Administrator privileges to register the background service."
    Write-Host "Please re-run this script in an Administrator PowerShell console." -ForegroundColor Yellow
    exit 1
}

# 2. Paths Configuration
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentScript = Join-Path $ProjectRoot "fixai-guardian\local_agent\main.py"
$ServiceScript = Join-Path $ProjectRoot "fixai-guardian\local_agent\service.py"
$PythonExe = (Get-Command py -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}

Write-Host "[*] Project Directory: $ProjectRoot" -ForegroundColor Gray
Write-Host "[*] Python Executable: $PythonExe" -ForegroundColor Gray
Write-Host "[*] Agent Entrypoint:  $AgentScript" -ForegroundColor Gray

# 3. Create ProgramData directories
$DataDir = "C:\ProgramData\FixAI"
$LogDir = Join-Path $DataDir "logs"
$VaultDir = Join-Path $DataDir "quarantine"

foreach ($dir in @($DataDir, $LogDir, $VaultDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Green
    }
}

# 4. Register Autostart Task
Write-Host "[*] Registering FixAIGuardian in Windows Task Scheduler..." -ForegroundColor Cyan
& py -3.11 $ServiceScript install

# 5. Verify Registration
& py -3.11 $ServiceScript status

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  FixAI Guardian Background Service Successfully Installed! " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "Useful commands:" -ForegroundColor White
Write-Host "  py -3.11 $ServiceScript start    # Start background agent" -ForegroundColor Yellow
Write-Host "  py -3.11 $ServiceScript stop     # Stop background agent" -ForegroundColor Yellow
Write-Host "  py -3.11 $ServiceScript status   # Query live service health" -ForegroundColor Yellow
