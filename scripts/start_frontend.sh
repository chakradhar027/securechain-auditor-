#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Launching SecureChain Auditor Frontend (React + Vite) ==="
cd "$ROOT_DIR/frontend"
exec npm run dev

