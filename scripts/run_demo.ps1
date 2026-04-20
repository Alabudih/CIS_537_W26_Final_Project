$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

python src/simulate_attacks.py
python src/analyze_results.py
python controller/mock_controller.py

Write-Host ""
Write-Host "Demo complete."
Write-Host "See results\ for generated plots and CSV files."
