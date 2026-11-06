#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Launching SecureChain Auditor Backend (FastAPI) ==="
cd "$ROOT_DIR/backend"
source "$ROOT_DIR/.venv/bin/activate"
export PYTHONPATH=.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

