# setup.ps1 - One-click setup + run for AI Threat Intelligence Aggregator (Windows)

$ErrorActionPreference = "Stop"
Write-Host "`n=== AI Threat Intel Aggregator: One-Click Setup (Windows) ===`n"

# Ensure script runs from project root
Set-Location -Path $PSScriptRoot

# Check project structure
if (!(Test-Path ".\app\main.py")) {
  Write-Host "ERROR: app\main.py not found. Run this from the project root." -ForegroundColor Red
  exit 1
}

# Select Python command
if (Get-Command py -ErrorAction SilentlyContinue) {
  $PYTHON = "py -3"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
  $PYTHON = "python"
} else {
  Write-Host "ERROR: Python not found. Install Python 3.10+ and add to PATH." -ForegroundColor Red
  exit 1
}

Write-Host "Using Python: $PYTHON`n"

# Create/recreate venv if needed
$activateScript = ".\.venv\Scripts\Activate.ps1"
if (!(Test-Path ".\.venv")) {
  Write-Host "Creating virtual environment..."
  Invoke-Expression "$PYTHON -m venv .venv"
} elseif (!(Test-Path $activateScript)) {
  Write-Host "Virtual environment is incomplete. Recreating .venv..." -ForegroundColor Yellow
  Remove-Item -Recurse -Force ".\.venv"
  Invoke-Expression "$PYTHON -m venv .venv"
} else {
  Write-Host "Virtual environment already exists."
}

# Enable activation in this session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force | Out-Null

# Activate venv
Write-Host "Activating virtual environment..."
. $activateScript

# Upgrade pip
Write-Host "Upgrading pip..."
python -m pip install --upgrade pip

# Create requirements.txt if missing
if (!(Test-Path ".\requirements.txt")) {
@"
fastapi
uvicorn[standard]
requests
sqlmodel
apscheduler
python-dateutil
lxml
"@ | Out-File -Encoding UTF8 ".\requirements.txt"
}

# Install dependencies
Write-Host "Installing dependencies..."
pip install -r .\requirements.txt

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host "Starting server at http://localhost:8000"
Write-Host "Press CTRL+C to stop.`n"

python -m uvicorn app.main:app --reload
