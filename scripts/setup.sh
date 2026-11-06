#!/usr/bin/env bash
set -e

echo "=== Setting up SecureChain Auditor Development Environment ==="

# 1. Setup Backend
echo "[1/3] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
pip install pytest-asyncio greenlet

# 2. Setup Frontend
echo "[2/3] Setting up Frontend Node dependencies..."
cd frontend
npm install
cd ..

# 3. Benchmark Dataset & Sample Contracts
echo "[3/3] Generating Benchmark Dataset..."
.venv/bin/python benchmark/generate_benchmark.py

echo "=== Setup complete! ==="
echo "To start backend:  ./scripts/start_backend.sh"
echo "To start frontend: ./scripts/start_frontend.sh"

