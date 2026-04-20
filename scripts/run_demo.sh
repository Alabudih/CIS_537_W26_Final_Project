#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python src/simulate_attacks.py
python src/analyze_results.py
python controller/mock_controller.py

echo
echo "Demo complete."
echo "See results/ for generated plots and CSV files."
