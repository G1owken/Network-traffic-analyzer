$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Create .venv and install requirements first. See README.md."
}
Push-Location $PSScriptRoot
try {
    & $python -m PyInstaller --noconfirm --clean --onefile --windowed `
        --name NetworkTrafficAnalyzer `
        --add-data "data/sample_traffic.csv;data" `
        gui_launcher.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "Built dist\NetworkTrafficAnalyzer.exe"
}
finally {
    Pop-Location
}
