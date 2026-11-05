# SecureChain Auditor – REST API Documentation

Base URL: `/api/v1`

---

## 1. Smart Contract Ingestion

### `POST /api/v1/upload/file`
Upload a `.sol` smart contract file via `multipart/form-data`.
- **Request**: Form field `file` (`.sol` file)
- **Response**: `ContractResponse`

### `POST /api/v1/upload/code`
Submit raw Solidity source code.
- **Request Form**: `name` (string), `source_code` (string)
- **Response**: `ContractResponse`

### `POST /api/v1/contracts/on-chain`
Fetch verified smart contract source from a blockchain explorer.
- **Request JSON**:
  ```json
  {
    "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "network": "ethereum"
  }
  ```
- **Response**: `ContractResponse`

---

## 2. Security Scanning Engine

### `POST /api/v1/scanner/start`
Trigger multi-engine vulnerability scanning job.
- **Request JSON**:
  ```json
  {
    "contract_id": 1,
    "engines": ["custom", "slither", "mythril", "foundry"]
  }
  ```
- **Response**: `ScanResponse`

### `GET /api/v1/scanner/status/{scan_id}`
Get real-time job execution progress percentage and current activity step.

### `GET /api/v1/scanner/engines`
Returns list of configured security engines and capabilities.

---

## 3. Findings & History

### `GET /api/v1/findings/`
Query findings with filters:
- Query parameters: `scan_id`, `severity` (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL), `category`, `skip`, `limit`.

### `GET /api/v1/history/`
List historical security scans.

### `GET /api/v1/history/summary`
Get aggregated statistics (total scans, critical threats, average risk index) for dashboard widgets.

### `GET /api/v1/history/compare?scan_id_a=1&scan_id_b=2`
Compare two scans to compute risk score delta and vulnerability count delta.

---

## 4. Reports

### `GET /api/v1/reports/download/{scan_id}`
Download the official generated PDF security audit certificate.
