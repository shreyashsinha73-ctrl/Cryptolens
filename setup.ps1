# ==============================================================================
# Cryptolens One-Command Setup & Startup Script for Windows PowerShell
# Automatically checks Python, backend dependencies, Node/npm dependencies,
# and boots both the FastAPI backend and Vite frontend concurrently.
# Press Ctrl+C at any time to cleanly stop both services.
# ==============================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " Cryptolens Automated Setup & Launcher (Windows)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------
# 1. Python Environment Check
# ------------------------------------------------------------------------------
Write-Host "`n[1/4] Checking Python environment..." -ForegroundColor Yellow

$PythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $PythonCmd) {
    $PythonCmd = (Get-Command py -ErrorAction SilentlyContinue)
}

if (-not $PythonCmd) {
    Write-Error "Python was not found in PATH. Please install Python 3.10+ from python.org."
    exit 1
}

$PythonExe = $PythonCmd.Source
Write-Host "Using Python: $PythonExe"

# Ensure runtime directories exist
New-Item -ItemType Directory -Force -Path "$ProjectRoot\backend\uploads" | Out-Null
New-Item -ItemType Directory -Force -Path "$ProjectRoot\backend\stored_results" | Out-Null
New-Item -ItemType Directory -Force -Path "$ProjectRoot\backend\generated_reports" | Out-Null

# Verify requirements
if (Test-Path "$ProjectRoot\requirements.txt") {
    Write-Host "Verifying Python dependencies..." -ForegroundColor Yellow
    & $PythonExe -m pip install --quiet -r "$ProjectRoot\requirements.txt"
}

# ------------------------------------------------------------------------------
# 2. Node & Frontend Check
# ------------------------------------------------------------------------------
Write-Host "`n[2/4] Checking Node & Frontend environment..." -ForegroundColor Yellow

$NpmCmd = (Get-Command npm -ErrorAction SilentlyContinue)
if (-not $NpmCmd) {
    Write-Error "'npm' was not found in PATH. Please install Node.js 18+ from nodejs.org."
    exit 1
}

if (-not (Test-Path "$ProjectRoot\node_modules")) {
    Write-Host "Installing frontend dependencies via npm install..." -ForegroundColor Yellow
    & npm install
} else {
    Write-Host "Frontend dependencies already installed."
}

# ------------------------------------------------------------------------------
# 3. Launch Services
# ------------------------------------------------------------------------------
Write-Host "`n[3/4] Launching FastAPI Backend on http://localhost:8000 ..." -ForegroundColor Green
$BackendProcess = Start-Process -FilePath $PythonExe -ArgumentList "-m uvicorn backend.main:app --host 127.0.0.1 --port 8000" -PassThru -NoNewWindow

Start-Sleep -Seconds 2

Write-Host "[4/4] Launching Vite Frontend on http://localhost:5173 ..." -ForegroundColor Green
$FrontendProcess = Start-Process -FilePath "npm.cmd" -ArgumentList "run dev" -PassThru -NoNewWindow

Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host " Cryptolens is ready!" -ForegroundColor Green
Write-Host " - Web Dashboard:  http://localhost:5173" -ForegroundColor White
Write-Host " - REST API:       http://localhost:8000" -ForegroundColor White
Write-Host " - API Swagger UI: http://localhost:8000/docs" -ForegroundColor White
Write-Host " Press Ctrl+C at any time to stop both servers." -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor Cyan

try {
    # Keep script waiting while both processes run
    while ($BackendProcess.HasExited -eq $false -and $FrontendProcess.HasExited -eq $false) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host "`nShutting down Cryptolens servers..." -ForegroundColor Yellow
    if ($BackendProcess -and -not $BackendProcess.HasExited) {
        Stop-Process -Id $BackendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($FrontendProcess -and -not $FrontendProcess.HasExited) {
        Stop-Process -Id $FrontendProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "All servers stopped." -ForegroundColor Green
}
