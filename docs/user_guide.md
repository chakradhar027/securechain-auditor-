# SecureChain Auditor – User Operations Guide

Welcome to the SecureChain Auditor platform. This guide explains how to audit your smart contracts, inspect findings, and download PDF audit certificates.

---

## 1. Quickstart

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm
- (Optional) Foundry `forge`, Slither, Mythril

### Running the Platform
1. Run backend setup:
   ```bash
   ./scripts/setup.sh
   ```
2. Start the backend API:
   ```bash
   ./scripts/start_backend.sh
   ```
   Backend listens at `http://localhost:8000`. Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.

3. In another terminal, start the frontend dashboard:
   ```bash
   ./scripts/start_frontend.sh
   ```
   Open `http://localhost:5173` in your browser.

---

## 2. Auditing a Smart Contract

1. Navigate to the **Security Scanner** tab in the sidebar.
2. Choose one of the submission options:
   - **Upload .sol File**: Drag & drop your Solidity contract.
   - **Direct Code Paste**: Paste contract source code into the editor.
   - **On-Chain Contract Address**: Enter a verified 0x contract address and network (Ethereum, Sepolia, BSC, Polygon).
3. Select your audit engines:
   - Custom AST Detectors (Reentrancy, Access Control, Unchecked Calls, Oracle Manipulation)
   - Slither Static Analyzer
   - Mythril Symbolic Engine
   - Foundry Fuzz Testing Suite
4. Click **Execute Multi-Engine Security Scan**.
5. Observe real-time progress and examine the generated findings, CVSS score, code evidence windows, and automated remediations.
6. Click **Download PDF Audit Report** to retrieve your formal audit certificate.

---

## 3. Benchmarking & Evaluation

Run the 60-contract benchmark evaluation suite:
```bash
.venv/bin/python benchmark/benchmark_runner.py
```
The suite measures True Positives, False Positives, Detection Accuracy, Precision, Recall, and F1-score across 50 vulnerable and 10 secure contracts.

