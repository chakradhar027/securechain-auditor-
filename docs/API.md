# API Documentation: SecureChain Auditor

SecureChain Auditor exposes a RESTful API versioned under `/api/v1`.

Interactive Swagger UI documentation is available at `http://localhost:8000/docs` and OpenAPI JSON at `http://localhost:8000/openapi.json`.

---

## 1. System Health

### `GET /health` and `GET /api/v1/health`
Checks whether the FastAPI backend is running and healthy.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "app": "SecureChain Auditor",
  "environment": "development",
  "version": "1.0.0"
}
```

---

## 2. Ingestion & Uploads

### `POST /api/v1/upload/file`
Uploads a Solidity (`.sol`) file for analysis.

- **Request**: Multipart form data with a `file` field.
- **Constraints**: Must have `.sol` extension, non-empty, valid UTF-8, sanitized path.

**Response (201 Created):**
```json
{
  "id": 1,
  "name": "ReentrancyVulnerable",
  "filename": "ReentrancyVulnerable.sol",
  "compiler_version": "^0.8.20",
  "source_code": "pragma solidity ^0.8.20; ...",
  "created_at": "2026-11-06T12:00:00Z"
}
```

### `POST /api/v1/upload/code`
Submits raw Solidity code via form data.

- **Parameters**: `name` (string), `source_code` (string), `compiler_version` (optional).

**Response (201 Created):** Same schema as `/api/v1/upload/file`.

### `GET /api/v1/contracts/`
Lists all uploaded and imported smart contracts.

---

## 3. Scanner Orchestration

### `GET /api/v1/scanner/engines`
Returns the status and metadata for all available scanning engines.

**Response (200 OK):**
```json
[
  {"id": "custom", "name": "Custom Detection Engine", "description": "AST pattern analysis", "enabled": true, "status": "operational"},
  {"id": "slither", "name": "Slither Static Analyzer", "description": "CFG and data-flow analysis", "enabled": true, "status": "operational"},
  {"id": "mythril", "name": "Mythril Symbolic Engine", "description": "EVM symbolic execution", "enabled": true, "status": "unverified"},
  {"id": "foundry", "name": "Foundry Invariant Fuzzer", "description": "Property fuzzing", "enabled": true, "status": "operational"}
]
```

### `POST /api/v1/scanner/start`
Triggers an asynchronous security audit for a contract.

**Request Body:**
```json
{
  "contract_id": 1,
  "engines": ["custom", "slither", "foundry"]
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "contract_id": 1,
  "contract_name": "ReentrancyVulnerable",
  "status": "COMPLETED",
  "risk_score": 100.0,
  "risk_level": "CRITICAL",
  "total_vulnerabilities": 6,
  "critical_count": 2,
  "high_count": 1,
  "medium_count": 0,
  "low_count": 0,
  "info_count": 3,
  "fuzz_passed": 1,
  "fuzz_total": 2,
  "engines_used": ["custom", "slither", "foundry"],
  "findings": [...]
}
```

### `GET /api/v1/scanner/status/{scan_id}`
Retrieves real-time status and progress percentage for a running audit.

---

## 4. Findings & Code Evidence

### `GET /api/v1/findings/`
Retrieves findings, optionally filtered by `scan_id`, `severity`, or `category`.

**Query Parameters:**
- `scan_id` (optional, integer)
- `severity` (optional: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
- `category` (optional: `REENTRANCY`, `ACCESS_CONTROL`, `UNCHECKED_CALL`, `ORACLE_MANIPULATION`, `OTHER`)

**Item Schema:**
```json
{
  "id": 10,
  "scan_id": 1,
  "title": "Potential Reentrancy Vulnerability in 'withdraw'",
  "category": "REENTRANCY",
  "severity": "CRITICAL",
  "cvss_score": 8.9,
  "confidence": "HIGH",
  "engine": "custom",
  "line_start": 25,
  "line_end": 29,
  "code_snippet": "(bool success, ) = msg.sender.call{value: balance}(\"\");\nrequire(success);\nbalances[msg.sender] = 0;",
  "description": "State change after external call...\n\n[Exploitability Assessment]: Confirmed active vulnerability.",
  "recommendation": "Apply Checks-Effects-Interactions (CEI) pattern."
}
```

---

## 5. Audit History & Comparison

### `GET /api/v1/history/`
Returns all completed audit records ordered by timestamp descending.

### `GET /api/v1/history/summary`
Returns system aggregate telemetry (total audits, critical threats, average risk score, severity distributions).

### `GET /api/v1/history/compare`
Compares two audits to calculate security posture delta.

**Query Parameters:**
- `scan_id_a`: Baseline audit ID.
- `scan_id_b`: Patched audit ID.

**Response (200 OK):**
```json
{
  "scan_a": {"id": 1, "risk_score": 100.0, "risk_level": "CRITICAL", "vuln_count": 6},
  "scan_b": {"id": 2, "risk_score": 0.0, "risk_level": "SECURE", "vuln_count": 2},
  "risk_delta": -100.0,
  "vuln_delta": -4,
  "is_improved": true
}
```

---

## 6. PDF Reports

### `GET /api/v1/reports/`
Lists all generated audit reports with metadata.

### `GET /api/v1/reports/download/{scan_id}`
Downloads the publication-ready PDF report for the specified scan.

- **Response**: `application/pdf` binary stream with `Content-Disposition: attachment; filename="SecureChain_Audit_Report_Scan_{scan_id}.pdf"`.
