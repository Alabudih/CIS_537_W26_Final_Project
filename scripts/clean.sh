#!/usr/bin/env bash
set -e
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -f "$ROOT_DIR"/results/*.png
rm -f "$ROOT_DIR"/results/*.csv
rm -f "$ROOT_DIR"/results/*.json
echo "Cleaned generated result files."
