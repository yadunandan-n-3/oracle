# ORACLE OS Setup Script (PowerShell)
# Run from project root: powershell -ExecutionPolicy Bypass -File scripts/setup.ps1

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  ORACLE OS - Setup Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

Write-Host "Project root: $ProjectRoot" -ForegroundColor Blue
Write-Host ""

# ─── Prerequisites ──────────────────────────────────────────────────────

Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Python
try {
    $pythonVersion = (python --version 2>&1).ToString()
    Write-Host "  Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  Python: not found" -ForegroundColor Red
    Write-Host "  Install Python 3.12+ from https://www.python.org/downloads/"
    exit 1
}

# Node.js
try {
    $nodeVersion = (node --version).ToString()
    Write-Host "  Node.js: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "  Node.js: not found" -ForegroundColor Red
    Write-Host "  Install Node.js 20+ from https://nodejs.org/"
    exit 1
}

Write-Host ""

# ─── Python Environment ─────────────────────────────────────────────────

Write-Host "Setting up Python environment..." -ForegroundColor Yellow

# Create virtual environment
if (-not (Test-Path ".venv")) {
    python -m venv .venv
    Write-Host "  Virtual environment: created" -ForegroundColor Green
} else {
    Write-Host "  Virtual environment: exists" -ForegroundColor Green
}

# Activate and install
$venvActivate = Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1"
. $venvActivate

pip install --upgrade pip -q
Write-Host "  Pip: upgraded" -ForegroundColor Green

pip install -e ".[dev]" -q
Write-Host "  Python dependencies: installed" -ForegroundColor Green

Write-Host ""

# ─── Docker Setup ───────────────────────────────────────────────────────

Write-Host "Setting up Docker infrastructure..." -ForegroundColor Yellow

try {
    docker compose -f docker/docker-compose.yml up -d 2>&1 | Out-Null
    Write-Host "  Docker services: started" -ForegroundColor Green
} catch {
    try {
        docker-compose -f docker/docker-compose.yml up -d 2>&1 | Out-Null
        Write-Host "  Docker services: started" -ForegroundColor Green
    } catch {
        Write-Host "  Docker: not available (optional)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ─── Summary ────────────────────────────────────────────────────────────

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  ORACLE OS setup complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Quick start:" -ForegroundColor White
Write-Host ""
Write-Host "  # Activate environment"
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "  # Start the backend"
Write-Host "  uvicorn backend.main:app --reload"
Write-Host ""
Write-Host "  # Open in browser"
Write-Host "  Backend:  http://localhost:8000"
Write-Host "  API Docs: http://localhost:8000/docs"
Write-Host ""
Write-Host "  # Run tests"
Write-Host "  pytest"
Write-Host ""
