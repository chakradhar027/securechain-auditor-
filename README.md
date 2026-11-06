# SecureChain Auditor

> **Intelligent Multi-Engine Smart Contract Vulnerability Detection and Risk Assessment Platform**

SecureChain Auditor is an enterprise-grade automated security auditing platform for Solidity smart contracts. It combines multi-engine static analysis, symbolic execution, and property-based dynamic fuzz testing with custom vulnerability detectors to produce publication-ready PDF audit reports, interactive code evidence, and calibrated risk scores.

---

## 1. Problem Statement
Smart contracts manage billions of dollars in decentralized finance (DeFi) protocols and digital assets on immutable blockchains. A single logic flaw, reentrancy bug, or price oracle manipulation can lead to catastrophic, irreversible financial loss. Traditional security audits are manual, slow, and expensive. Conversely, existing automated tools often run in isolation, generate excessive false positives from benign compiler warnings, or produce non-actionable outputs that fail to verify real-world exploitability.

---

## 2. Project Objectives
- **Multi-Engine Orchestration**: Unify diverse static analyzers, symbolic execution engines, and dynamic fuzzing tools into a coherent, automated pipeline.
- **Precision & Low False Positives**: Differentiate true exploitable vulnerabilities from informational code-hygiene notices to ensure patched contracts are not falsely penalized.
- **Dynamic Exploit Verification**: Validate security properties dynamically using Foundry Forge invariant fuzzing to discover concrete exploit counterexamples.
- **Automated Formal Reporting**: Generate formal, cryptographically verified PDF audit reports with line-level code evidence and actionable remediation steps.
- **Audit Tracking & Diffing**: Provide comprehensive historical tracking with version-to-version vulnerability delta analysis.

---

## 3. Key Features
- **Multi-Engine Scanning Pipeline**: Orchestrates Slither, Mythril, Foundry, and custom AST security detectors.
- **Specialized Vulnerability Detectors**: High-precision AST and semantic detectors for Reentrancy (CEI violations), Access Control flaws, Unchecked Calls, and Oracle Manipulation.
- **Property-Based Invariant Fuzzing**: Automated 256-run Foundry fuzz suites evaluating solvency invariants, caller permissions, and counterexample extraction.
- **Finding Normalization & Correlation**: De-duplicates overlapping findings across engines and corroborates multi-scanner detections.
- **Calibrated Risk Engine**: Calculates a 0–100 CVSS-aligned risk score without penalizing contracts for informational compiler warnings.
- **Interactive Code Evidence**: Displays syntax-highlighted code snippets, line numbers, exploitability context, and remediation guidance.
- **Formal PDF Audit Reports**: Generates formal, publication-ready PDF audit certificates with ReportLab.
- **Audit Comparison Diff**: Compares baseline vs. patched audit iterations with automated risk delta calculations.
- **Blockchain Explorer Integration**: Imports verified Solidity source code directly from Etherscan, BSCScan, and PolygonScan.

---

## 4. Technology Stack
| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, TypeScript, Tailwind CSS, Lucide Icons, Vite |
| **Backend** | Python 3.11 / 3.13, FastAPI, Uvicorn, Pydantic V2 |
| **Database** | SQLite / PostgreSQL (Async SQLAlchemy 2.0 + aiosqlite / asyncpg) |
| **Static & Symbolic Analysis** | Slither 0.10.x, Mythril (Docker / Native EVM solver), Custom AST / Semantic Engine |
| **Dynamic Testing** | Foundry (`forge test --fuzz-runs 256`) & Dynamic Invariant Fuzzer |
| **PDF Reporting** | ReportLab 4.x |
| **DevOps & Containers** | Docker, Docker Compose |

---

## 5. System Architecture
```
[ User Browser (React 18 + TypeScript + Vite) ]
                     │
                     ▼
[ FastAPI Backend /api/v1 (Python 3.11 / 3.13) ]
   ├── [ File & Explorer Ingestion ] ──> /backend/storage/uploads/
   ├── [ Scanner Manager Orchestrator ]
   │      ├── Slither Static Engine
   │      ├── Mythril Symbolic Engine (Docker / Native)
   │      ├── Foundry Invariant Fuzzer (forge test 256 runs)
   │      └── Custom AST Detectors (CEI, Auth, Call, Oracle)
   ├── [ Finding Normalizer & Correlator ]
   ├── [ CVSS & Calibrated Risk Assessment Engine ]
   ├── [ ReportLab PDF Audit Generator ] ──> /backend/storage/reports/
   └── [ Canonical SQLAlchemy Database ] ──> /backend/storage/securechain.db
```

---

## 6. How the Multi-Engine Pipeline Works
1. **Ingestion & Validation**: Uploaded Solidity files or direct pastes are validated for syntax and compiler pragma versions, then stored in canonical storage with sanitized filenames.
2. **Concurrent Execution**: `ScannerManager` executes enabled analyzers asynchronously. Custom detectors perform AST pattern matching, Slither analyzes control-flow graphs, and Foundry executes invariant property tests.
3. **Normalization**: Diverse tool outputs are parsed into a uniform schema with standardized categories and line numbers.
4. **Correlation & Deduplication**: Findings targeting identical functions or overlapping line ranges (within $\pm 3$ lines) are merged, with corroboration increasing confidence.
5. **Calibrated Scoring**: The risk engine evaluates active vulnerabilities and Foundry failures, while preserving informational advisories with zero score penalty.
6. **Report Generation**: Publication-ready PDF certificates and interactive web views are generated immediately.

---

## 7. Vulnerability Categories Detected
- **Reentrancy (SWC-107)**: Checks-Effects-Interactions (CEI) violations, state updates occurring after raw external calls (`call.value`), and missing reentrancy guards.
- **Access Control (SWC-105 / SWC-106 / SWC-115)**: Sensitive administrative functions missing `onlyOwner`, dangerous `tx.origin` authentication, and unprotected `selfdestruct`.
- **Unchecked External Calls (SWC-104)**: Ignored boolean return values from `.call`, `.send`, or `.delegatecall`, and non-standard ERC-20 transfers.
- **Oracle Manipulation**: Spot reserve price derivations from AMM liquidity pools (`getReserves()`) vulnerable to flash loan price distortions, and unvalidated Chainlink oracle feeds.

---

## 8. Risk Assessment Methodology
The risk engine calculates a normalized 0–100 score based on finding severity and dynamic test results:
- **Base Severity Weights**: `CRITICAL` (35 pts), `HIGH` (20 pts), `MEDIUM` (8 pts), `LOW` (3 pts), `Foundry Invariant Failure` (15 pts).
- **Minimum Posture Thresholds**: A contract with any confirmed Critical issue automatically scores $\ge 80.0$ (`CRITICAL`), High $\ge 55.0$ (`HIGH`), Medium $\ge 25.0$ (`MEDIUM`), Low $\ge 5.0$ (`LOW`).
- **Informational Hygiene Zero-Weight**: Compiler version notices, naming conventions, and verified safe low-level calls carry 0.0 weight. Secure contracts receive a score of **0.0 (SECURE)**.

---

## 9. Foundry Fuzz Testing
Foundry Forge runs automated invariant fuzzing (`--fuzz-runs 256`) against parameterized test contracts in `contracts/test/SecurityTest.t.sol`:
- **Solvency Invariants**: Verifies vault assets equal or exceed user liabilities under randomized deposit/withdraw sequences.
- **Access Invariants**: Asserts unauthorized addresses cannot drain funds or trigger selfdestruct.
- **Counterexample Generation**: When an invariant fails, Forge extracts the exact randomized inputs, caller addresses, and calldata, which are rendered directly in the user interface.

---

## 10. Database and Scan History
All contracts, scan runs, findings, and fuzz details are persisted using asynchronous SQLAlchemy 2.0. Database paths are canonically anchored to `backend/storage/securechain.db`, ensuring complete directory independence. Scan history allows side-by-side comparison of baseline vs. fixed contracts to verify vulnerability remediation.

---

## 11. PDF Audit Report Generation
Using ReportLab, the platform automatically compiles comprehensive PDF audit reports including:
- Cryptographic report metadata and audit identifier (`SCA-XXXXXX`).
- Contract details (name, compiler version, sha256 fingerprint).
- Executive risk score dial and severity summary table.
- De-duplicated findings with CVSS severity, line ranges, highlighted source code evidence, and remediation advice.
- Foundry fuzz testing invariant verification status.

---

## 12. Installation Requirements
- **Python**: 3.11 or 3.13
- **Node.js**: 18+ and `npm`
- **Solidity Tooling**:
  - `slither`: Installed via python virtual environment
  - `foundry` (`forge`): Installed via `foundryup`
- **Optional**: Docker (for containerized Mythril symbolic execution)

---

## 13. Backend Setup Instructions
```bash
# Clone the repository
git clone https://github.com/your-username/securechain-auditor.git
cd securechain-auditor

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Start backend server
./scripts/start_backend.sh
```
Backend API will be running at `http://localhost:8000`.

---

## 14. Frontend Setup Instructions
```bash
# From repository root
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
cd ..
./scripts/start_frontend.sh
```
Frontend web application will be accessible at `http://localhost:5173`.

---

## 15. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Key configuration parameters:
```env
APP_NAME="SecureChain Auditor"
APP_ENV=development
PORT=8000
HOST=0.0.0.0
DATABASE_URL=sqlite+aiosqlite:///./backend/storage/securechain.db
STORAGE_DIR=./backend/storage
UPLOADS_DIR=./backend/storage/uploads
REPORTS_DIR=./backend/storage/reports
```

---

## 16. API Documentation
Key REST endpoints:
- `GET /api/v1/health`: System health status.
- `POST /api/v1/upload/file`: Upload Solidity source file.
- `POST /api/v1/scanner/start`: Execute multi-engine audit.
- `GET /api/v1/findings/?scan_id={id}`: Retrieve audit findings.
- `GET /api/v1/history/`: List completed audit history.
- `GET /api/v1/history/compare`: Compute delta between two audits.
- `GET /api/v1/reports/download/{scan_id}`: Download PDF audit certificate.

Interactive Swagger UI: `http://localhost:8000/docs`.

---

## 17. Example Usage
### Upload & Scan via cURL:
```bash
# 1. Upload contract
curl -X POST http://localhost:8000/api/v1/upload/file \
  -F "file=@contracts/vulnerable/ReentrancyVulnerable.sol"

# 2. Trigger scan
curl -X POST http://localhost:8000/api/v1/scanner/start \
  -H "Content-Type: application/json" \
  -d '{"contract_id": 1, "engines": ["custom", "slither", "foundry"]}'

# 3. Download report
curl -O http://localhost:8000/api/v1/reports/download/1
```

---

## 18. Testing Instructions
Execute the backend test suite:
```bash
./.venv/bin/pytest backend/tests/ -v
```
Build frontend production bundle:
```bash
cd frontend && npm run build && cd ..
```
Execute end-to-end user workflow test:
```bash
./.venv/bin/python scripts/test_complete_user_workflow.py
```
Execute reliability and security audit:
```bash
./.venv/bin/python scripts/test_reliability_and_security.py
```
Run 72-contract benchmark suite:
```bash
./.venv/bin/python benchmark/benchmark_runner.py
```

---

## 19. Screenshots
Screenshots of the running web application:
- **Executive Dashboard**: Telemetry overview, severity distribution pie charts, and recent audit activity.
- **Security Scanner**: Interactive file upload, engine toggle, and live progress bar.
- **Findings Catalog**: Expandable finding cards with syntax-highlighted code evidence.
- **Foundry Invariant Fuzzing**: Invariant execution table and counterexample traces.
- **PDF Audit Report**: Publication-ready audit report preview.

*(Place real screenshots in `screenshots/` directory when presenting).*

---

## 20. Limitations
- **Mythril Execution**: Under Python 3.13, native Mythril dependencies require Docker. When Docker is not running, Mythril is explicitly flagged as unverified and excluded from executed engines.
- **Fuzzing Scope**: Invariant fuzzing requires predefined test properties in `SecurityTest.t.sol`. Arbitrary custom protocols require tailored property definitions.
- **Benchmark Scope**: The 72-contract benchmark demonstrates consistency within the evaluated testbed and does not guarantee 100% detection on unseen mainnet contracts.

---

## 21. Future Enhancements
- Integration of EVM bytecode decompiler for unverified on-chain bytecode analysis.
- Support for automated generation of Foundry invariant harnesses using LLM code synthesis.
- Multi-contract protocol simulation supporting cross-contract call traces and flash loan environments.
- CI/CD GitHub Action integration for automated PR security checks.

---

## 22. Author & Academic Context
Developed as an advanced smart contract security research and engineering project demonstrating multi-engine static and dynamic vulnerability analysis for Ethereum smart contracts.

---

## 23. License
MIT License.
