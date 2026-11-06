# SecureChain Auditor – Evaluator & Demonstration Guide

This guide provides step-by-step instructions for demonstrating the **SecureChain Auditor** platform, including exact terminal commands, verified URLs, sample contracts, expected outputs, and troubleshooting procedures.

---

## 1. Quick Launch (Clean Terminal Session)

Open two terminal tabs in the project root:

```bash
cd "/Users/muppurichakri/Desktop/Project SecureChain Auditor"
```

### Terminal 1: Backend API Service
```bash
./scripts/start_backend.sh
```
*Expected Output:*
```
=== Launching SecureChain Auditor Backend (FastAPI) ===
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### Terminal 2: Frontend Web Dashboard
```bash
./scripts/start_frontend.sh
```
*Expected Output:*
```
=== Launching SecureChain Auditor Frontend (React + Vite) ===
  VITE v5.4.21  ready in ~250 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

---

## 2. Platform URLs

| Resource | URL | Description |
|---|---|---|
| **Web Dashboard** | `http://localhost:5173` | React 18 / Tailwind security posture dashboard |
| **Backend REST API** | `http://localhost:8000` | FastAPI application endpoints |
| **Interactive OpenAPI Docs** | `http://localhost:8000/docs` | Swagger UI for exploring and testing endpoints |
| **API Health Status** | `http://localhost:8000/api/v1/health` | Health telemetry |

---

## 3. Demonstration Scenario 1: Vulnerable Contract Audit

### Objective
Demonstrate multi-engine detection of critical reentrancy vulnerabilities, Checks-Effects-Interactions (CEI) violations, and automated property-based fuzz counterexample discovery.

### Steps
1. Open `http://localhost:5173` in a browser.
2. In the sidebar, click **Security Scanner**.
3. Under **Smart Contract Submission**, select **Upload .sol File**.
4. Choose the sample file:
   ```
   contracts/vulnerable/ReentrancyVulnerable.sol
   ```
   *(Alternatively, copy/paste the code via the **Direct Code Paste** tab).*
5. In **Analysis Engine Orchestration**, ensure the following engines are enabled:
   - **Custom Detectors** (Active)
   - **Slither Static** (Ready)
   - **Foundry Fuzzing** (Ready)
   *(Note: Mythril is marked `Unverified (Docker)` when Docker daemon is not active; leave unchecked or checked—system skips it cleanly without failing).*
6. Click **Execute Multi-Engine Security Scan**.
7. Watch the live progress tracker step through:
   - *Dispatching multi-engine scan jobs...*
   - *Running Slither AST & custom semantic detectors...*
   - *Running Foundry invariant property fuzzing...*
   - *Correlating findings and calculating risk score...*

### Expected Results
- **Overall Posture**: **`CRITICAL`**
- **Risk Score**: **`100.0 / 100`**
- **Vulnerabilities Identified**: **5 Findings**
  1. `[CRITICAL]` **Potential Reentrancy Vulnerability in 'withdraw'** (Engine: `custom`, Lines 25–29)
  2. `[HIGH]` **Slither: Reentrancy Eth** (Engine: `slither`, Line 20)
  3. `[CRITICAL]` **Foundry Fuzz Invariant Broken: testFuzz_Reentrancy_Invariant_VaultSolvencyPreserved** (Engine: `foundry`)
  4. `[INFORMATIONAL]` **Slither: Solc Version** (Engine: `slither`)
  5. `[INFORMATIONAL]` **Slither: Low Level Calls** (Engine: `slither`)
- **Code Evidence Window**: Lines 25–29 highlighted with `>> (bool success, ) = msg.sender.call{value: balance}("");` occurring prior to `balances[msg.sender] = 0;`.
- **Exploitability Callout**: `Exploitability Assessment: High Exploitability (Checks-Effects-Interactions violation)`.
- **Foundry Fuzz Inspection**: Click **Foundry Fuzz Testing** in the sidebar. Observe that `testFuzz_Reentrancy_Invariant_VaultSolvencyPreserved` failed with a concrete counterexample trace showing pool insolvency under reentrant calls.
- **PDF Report**: Click **Download PDF Audit Report** to download the official ReportLab certificate (`SecureChain_Audit_Report_Scan_*.pdf`).

---

## 4. Demonstration Scenario 2: Patched & Secure Contract Audit

### Objective
Demonstrate that implementing the Checks-Effects-Interactions pattern, mutex guards (`nonReentrant`), and safe call handling reduces the risk posture to **SECURE (0.0 / 100)** while preserving compiler warnings as non-penalizing informational advisories.

### Steps
1. Return to the **Security Scanner** (`http://localhost:5173`).
2. Upload the fixed contract:
   ```
   contracts/secure/ReentrancyFixed.sol
   ```
3. Keep the same engine configuration (`Custom`, `Slither`, `Foundry`).
4. Click **Execute Multi-Engine Security Scan**.

### Expected Results
- **Overall Posture**: **`SECURE`**
- **Risk Score**: **`0.0 / 100`**
- **Vulnerability Breakdown**:
  - `CRITICAL`: **0**
  - `HIGH`: **0**
  - `MEDIUM`: **0**
  - `LOW`: **0**
  - `INFORMATIONAL`: **2** (Code-hygiene advisories: `solc-version` floating pragma, naming conventions)
- **Foundry Invariants**: **1/1 Passed (0 Failed)**. Solvency and boundary constraints held across all 256 randomized fuzz runs.
- **PDF Report**: Download the fixed audit report (`SecureChain_Audit_Report_Scan_*.pdf`), confirming a `0.0 SECURE` certificate.

---

## 5. Demonstration Scenario 3: Version Comparison & Risk Delta

### Objective
Demonstrate automated regression tracking and differential security auditing.

### Steps
1. Click **Scan History** in the sidebar.
2. In the **Contract Version & Audit Diff** card:
   - **Baseline Scan (Before)**: Select the vulnerable scan (e.g. `SCA-000044 - Contract #54 (CRITICAL)`).
   - **Patched Scan (After)**: Select the fixed scan (e.g. `SCA-000045 - Contract #55 (SECURE)`).
3. Click **Compute Audit Diff**.

### Expected Results
- **Status**: **`Security Improved`** (highlighted in emerald green).
- **Scan A Risk**: `100.0 (CRITICAL)`
- **Scan B Risk**: `0.0 (SECURE)`
- **Risk Delta**: **`-100.0 pts`**
- **Vulnerability Delta**: **`-3 issues`** (resolved all critical and high findings).

---

## 6. Automated Verification Commands

To run all automated test suites from the command line:

```bash
# 1. Run all 17 Pytest Unit & Regression Tests:
.venv/bin/pytest backend/tests/ -v

# 2. Run the 12-Step Full Workflow Audit:
PYTHONPATH=backend .venv/bin/python scripts/test_complete_user_workflow.py

# 3. Run Reliability & Security Verification:
PYTHONPATH=backend .venv/bin/python scripts/test_reliability_and_security.py

# 4. Run the 72-Contract Independent Benchmark Suite:
.venv/bin/python benchmark/benchmark_runner.py
```

---

## 7. Troubleshooting & FAQ

### Issue: Port 8000 or 5173 Already in Use
**Solution**: Check for running processes and free the ports:
```bash
lsof -ti :8000 | xargs kill -9 2>/dev/null || true
lsof -ti :5173 | xargs kill -9 2>/dev/null || true
```

### Issue: Mythril Marked as "Unverified (Docker)"
**Explanation**: Python 3.13 wheel packaging incompatibilities prevent native Mythril installation without binary conflicts. The platform is architected to run Mythril via Docker (`docker pull mythril/myth`). When Docker is not active, the UI transparently marks Mythril as `Unverified (Docker)` and skips it without failing the rest of the scan. To enable Mythril:
1. Start Docker Desktop.
2. Run `docker pull mythril/myth`.
3. Mythril will automatically switch to `Ready` in the engine list.

### Issue: Slither Reports Compilation Warning
**Explanation**: Slither uses `solc` (0.8.20 bundled in `.venv/bin/solc`). If a contract uses a different pragma, Slither automatically flags `solc-version` as an informational finding. This is expected behavior and does not penalize the security score.

### Issue: Resetting the Database
To clear test scans and start with a clean database:
```bash
rm -f storage/securechain.db storage/reports/*.pdf
```
The database and tables will automatically recreate on the next backend start.

