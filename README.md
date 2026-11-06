[README.md](https://github.com/user-attachments/files/34474905/README.md)
# SecureChain Auditor

**Intelligent Multi-Engine Smart Contract Vulnerability Detection & Risk Assessment Platform**

SecureChain Auditor is a web-based security auditing platform for Solidity smart contracts. It brings together custom vulnerability detectors, Slither static analysis, and Foundry property-based fuzz testing in a single workflow. Findings are normalized and correlated, assigned severity and risk scores, stored in audit history, and presented with source-code evidence, remediation guidance, and downloadable PDF reports.

> **Research and portfolio project.** Automated analysis is not a substitute for a professional manual audit or formal verification. Results depend on the enabled engines, detector coverage, and test properties supplied for the contract.

## Project at a glance

- **Frontend:** React, TypeScript, Vite, Tailwind CSS
- **Backend:** Python, FastAPI, Uvicorn, Pydantic
- **Database:** SQLite with asynchronous SQLAlchemy
- **Analysis:** Custom Python/AST detectors, Slither, Foundry Forge
- **Reporting:** ReportLab PDF generation
- **Optional engine:** Mythril; live execution is currently unverified and depends on a working Docker/native setup

## Screenshots

### Security overview dashboard
![SecureChain Auditor dashboard](screenshots/dashboard.png)

### Multi-engine contract scanner
![Contract scanner](screenshots/scanner.png)

### Vulnerability findings catalog
![Vulnerability findings catalog](screenshots/findings-catalog.png)

### Audit history and comparisons
![Audit history](screenshots/scan-history.png)

### Foundry invariant fuzz testing
![Foundry fuzz testing](screenshots/foundry-fuzz-testing.png)

## Key capabilities

### Multi-engine scanning
- Upload a Solidity `.sol` file or paste source code.
- Select available analysis engines for a scan.
- Run custom detectors and Slither static analysis.
- Run Foundry fuzz and invariant tests when the required test harness is available.
- The interface also exposes on-chain address submission; explorer retrieval depends on the configured integration and supported explorer.

### Custom vulnerability detection
The custom detector categories documented for this project include:
- **Reentrancy:** checks-effects-interactions ordering and related external-call patterns.
- **Access control:** sensitive operations without appropriate authorization checks.
- **Unchecked external calls:** low-level call return-value handling.
- **Oracle manipulation:** potentially unsafe reliance on manipulatable AMM spot-reserve or oracle data.

Detector output is heuristic evidence and should be reviewed in context.

### Finding correlation and risk assessment
- Normalize results from different analysis engines.
- Identify overlapping findings and reduce duplicate reporting.
- Preserve severity, confidence, engine, source location, and vulnerability identifiers where available.
- Calculate a project-defined risk score from 0–100.
- Keep informational code-hygiene advisories distinct from active vulnerabilities.

The risk score is an automated prioritization aid, not proof that a contract is secure or exploitable.

### Foundry fuzz and invariant testing
Foundry Forge can execute property-based tests with a configured 256-run fuzz setting. The project test properties cover examples such as solvency, caller authorization, zero-value handling, and arithmetic bounds. When an invariant fails, the test output can provide a counterexample trace for investigation.

The results shown in the UI depend on the selected contract and configured test harness; a passing test suite does not prove the absence of vulnerabilities.

### Audit history and PDF reports
- Persist scan history and findings in the configured database.
- Compare baseline and patched audit runs.
- Review changes in risk scores and finding counts.
- Generate PDF reports with contract metadata, executive risk assessment, findings, source evidence, and remediation recommendations.
- Include fuzz verification results when available.

## Architecture

```text
React + TypeScript + Vite
          |
          v
     FastAPI REST API
          |
          v
 Scanner orchestration layer
   |          |          |
   v          v          v
 Custom     Slither    Foundry
 detectors  static     fuzz/invariant
   |          |          |
   +----------+----------+
              |
              v
   Finding normalization
       and correlation
              |
              v
      Risk assessment
              |
       +------+------+
       |             |
       v             v
 SQLAlchemy DB    PDF reports
       |
       v
 Scan history and audit comparison
```

## Technology stack

| Layer | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS, Lucide icons |
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Database | SQLite, SQLAlchemy async ORM |
| Static analysis | Slither, custom AST/semantic detectors |
| Dynamic testing | Foundry Forge fuzz and invariant tests |
| Symbolic analysis | Mythril integration is present in the design/UI; live execution remains unverified |
| PDF reports | ReportLab |
| Development tools | Git, GitHub, Docker (optional for Mythril setup) |

## Local setup

### Prerequisites

- Python 3.11 or 3.13
- Node.js 18+ and npm
- Slither installed in the Python environment
- Foundry (`forge`) installed and available on `PATH`
- Docker only if using the containerized Mythril configuration

### 1. Clone the repository

```bash
git clone https://github.com/chakradhar027/securechain-auditor-.git
cd securechain-auditor-
```

### 2. Configure the backend

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Review the settings in `.env` for your local environment. Example values documented by the project:

```dotenv
APP_NAME="SecureChain Auditor"
APP_ENV=development
PORT=8000
HOST=0.0.0.0
DATABASE_URL=sqlite+aiosqlite:///./backend/storage/securechain.db
STORAGE_DIR=./backend/storage
UPLOADS_DIR=./backend/storage/uploads
REPORTS_DIR=./backend/storage/reports
```

Do not commit secrets, local databases, uploaded contracts, generated reports, or environment files.

### 4. Start the backend

```bash
./scripts/start_backend.sh
```

The API is expected at `http://localhost:8000`.

### 5. Install and start the frontend

```bash
cd frontend
npm install
cd ..
./scripts/start_frontend.sh
```

The Vite application is expected at `http://localhost:5173`.

### 6. API documentation

When the backend is running, open:

- Swagger UI: `http://localhost:8000/docs`
- Health endpoint: `GET /api/v1/health`

## API overview

The project documentation identifies these API routes:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Backend health |
| `POST` | `/api/v1/upload/file` | Upload Solidity source |
| `POST` | `/api/v1/scanner/start` | Start a multi-engine scan |
| `GET` | `/api/v1/findings/?scan_id={id}` | Retrieve findings |
| `GET` | `/api/v1/history/` | List scan history |
| `GET` | `/api/v1/history/compare` | Compare two audits |
| `GET` | `/api/v1/reports/download/{scan_id}` | Download a PDF report |

Check the running Swagger documentation for the exact request schemas and current route behavior.

## Testing

The project documentation provides the following verification commands:

```bash
./.venv/bin/pytest backend/tests/ -v
cd frontend && npm run build && cd ..
./.venv/bin/python scripts/test_complete_user_workflow.py
./.venv/bin/python scripts/test_reliability_and_security.py
./.venv/bin/python benchmark/benchmark_runner.py
```

Reported project verification includes backend tests, a successful frontend production build, end-to-end workflow checks, vulnerable/fixed regression scans, and PDF report checks. Benchmark figures apply only to the evaluated test set and should not be interpreted as guaranteed accuracy on unseen contracts.

## Known limitations

- **Mythril:** Live execution is currently unverified in the reported environment. The UI may show the engine as unverified when Docker or its required runtime is unavailable; do not count it as an executed engine unless a scan confirms execution.
- **Fuzzing scope:** Invariant testing depends on suitable properties and test harnesses. Arbitrary protocols may require custom Foundry tests.
- **Detection coverage:** Static and custom detectors can miss issues or produce findings that require manual triage.
- **Benchmark scope:** Results from the project's benchmark are limited to that dataset and do not establish universal detection accuracy.
- **On-chain source retrieval:** Explorer integrations require valid configuration and supported verified-source endpoints.

## Security note

Only analyze contracts you are authorized to inspect. Treat uploaded Solidity source and generated findings as untrusted input. Run analysis of untrusted projects in an appropriately isolated environment. Before production use, review upload handling, subprocess isolation, resource limits, authentication, authorization, and deployment configuration.

## Future improvements

- Verify Mythril execution in a reproducible Docker environment.
- Expand evaluation with independently sourced smart contracts.
- Improve detector precision and false-positive triage.
- Add isolated execution environments for untrusted source.
- Expand multi-contract and cross-contract analysis.
- Add CI/CD integration for pull-request security checks.
- Deploy the platform with authentication and role-based access controls.

## Author

Developed as an advanced blockchain and cybersecurity portfolio/research project.

**GitHub:** [chakradhar027/securechain-auditor-](https://github.com/chakradhar027/securechain-auditor-)

## License

The supplied project notes specify the MIT License. Include the repository's `LICENSE` file to make that license effective.
