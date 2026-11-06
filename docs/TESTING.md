# Comprehensive Testing Guide: SecureChain Auditor

This guide outlines the complete test suite, verification procedures, and automated regression testing workflows implemented in SecureChain Auditor.

---

## 1. Automated Backend Test Suite (`pytest`)

The backend test suite is located in `backend/tests/` and can be executed from either the repository root or the `backend/` directory without configuration changes.

### Running Tests from the Repository Root
```bash
./.venv/bin/pytest backend/tests/ -v
```

### Running Tests from the Backend Directory
```bash
cd backend
../.venv/bin/pytest tests/ -v
```

### Test Suite Structure
| Test File | Focus Area | Test Count | Status |
| :--- | :--- | :--- | :--- |
| `test_canonical_paths.py` | Directory-independent path resolution, database preservation, backup existence | 3 tests | PASS |
| `test_api.py` | Health endpoints, full scan API cycle, file rejection security, path traversal rejection | 3 tests | PASS |
| `test_detectors.py` | Custom AST detectors: Reentrancy, Access Control, Unchecked Calls, Oracle Manipulation | 4 tests | PASS |
| `test_risk_engine.py` | CVSS calculation, finding deduplication, score thresholds, informational advisory zero-weight | 3 tests | PASS |
| `test_scanners.py` | Scanner orchestration, Foundry fuzzing, Slither execution, Mythril parser, 4-pair regression | 7 tests | PASS |
| `test_pdf_and_contract_accuracy.py` | Contract name extraction, low-level call safety, PDF text stream inspection, report downloads | 6 tests | PASS |
| **Total** | | **26 tests** | **100% PASS** |

---

## 2. Frontend Production Build Verification

Verify TypeScript compilation, asset bundling, and zero syntax or type errors:

```bash
cd frontend
npm run build
```

Expected output:
```text
vite v5.4.21 building for production...
✓ 1597 modules transformed.
dist/index.html                   0.94 kB
dist/assets/index-BPnXut6T.css   26.84 kB
dist/assets/index-CEvJpDlG.js   212.44 kB
✓ built in ~1.5s
```

---

## 3. End-to-End Workflow Verification Script

Executes the complete 12-step user journey via ASGI AsyncClient:
1. Opens dashboard & checks system health.
2. Uploads `ReentrancyVulnerable.sol`.
3. Dispatches multi-engine security scan.
4. Monitors scanning progress status.
5. Reviews findings and categorization.
6. Inspects code evidence and line numbers.
7. Validates risk score (100.0 CRITICAL).
8. Validates Foundry fuzz testing (invariant broken + counterexample).
9. Downloads and verifies binary PDF audit report.
10. Checks historical audit registry.
11. Uploads and scans patched `ReentrancyFixed.sol` (0.0 SECURE).
12. Compares both audits (`/api/v1/history/compare`).

```bash
./.venv/bin/python scripts/test_complete_user_workflow.py
```

---

## 4. Reliability and Security Test Script

Tests storage persistence, input rejection, path traversal prevention, process isolation, and secret leakage prevention:

```bash
./.venv/bin/python scripts/test_reliability_and_security.py
```

Checks performed:
- Database re-instantiation and record persistence.
- Rejection of invalid file extensions (`.exe`, `.py`).
- Directory traversal path sanitization (`../../../../etc/passwd.sol`).
- Rejection of empty Solidity files.
- Non-existent contract 404 error handling.
- PDF ReportLab binary header validation (`%PDF-1.4`).
- Subprocess sandbox isolation and exit code trapping.
- Codebase-wide scan for hardcoded private keys or API tokens.

---

## 5. Vulnerable vs. Fixed Contract Regression Suite

Scans all four foundational vulnerable and patched contract pairs:
1. **Reentrancy**: `ReentrancyVulnerable.sol` (100.0 CRITICAL) vs `ReentrancyFixed.sol` (0.0 SECURE).
2. **Access Control**: `AccessControlVulnerable.sol` (100.0 CRITICAL) vs `AccessControlFixed.sol` (0.0 SECURE).
3. **Unchecked Calls**: `UncheckedCallVulnerable.sol` (55.0 MEDIUM) vs `UncheckedCallFixed.sol` (0.0 SECURE).
4. **Oracle Manipulation**: `OracleVulnerable.sol` (80.0 CRITICAL) vs `OracleFixed.sol` (0.0 SECURE).

```bash
./.venv/bin/python scripts/verify_all_four_pairs.py
```

---

## 6. Curated Benchmark Evaluation

Runs automated benchmark evaluation over 72 test contracts (60 synthetic parameterized contracts + 12 independent public contracts from the SWC Registry):

```bash
./.venv/bin/python benchmark/benchmark_runner.py
```

Ground truth is strictly isolated in `benchmark/expected_findings/benchmark_ground_truth.json` and is never provided to the scanning engines during execution.
