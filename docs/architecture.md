# SecureChain Auditor – System Architecture Documentation

## 1. System Overview
SecureChain Auditor is a multi-engine smart contract vulnerability analysis and risk assessment platform designed to identify critical security flaws in Solidity code.

The platform follows a 5-stage pipeline:
1. **Contract Ingestion**: Accepts raw Solidity `.sol` uploads, direct code pastes, or verified contracts pulled via blockchain explorer APIs (Etherscan, BSCScan, PolygonScan).
2. **Multi-Engine Static & Symbolic Execution**:
   - **Custom Detection Engine**: AST and syntactic/semantic pattern detectors specializing in Reentrancy (CEI violations), Access Control flaws, Unchecked External Calls, and Oracle Manipulation (AMM spot reserve pricing).
   - **Slither Static Analysis**: Deep AST and control-flow graph (CFG) analysis flagging compiler warnings, state shadowing, and dangerous assembly blocks.
   - **Mythril Symbolic Execution**: EVM bytecode symbolic solver discovering execution path constraints, front-running windows, timestamp dependencies, and weak PRNG.
   - **Foundry Dynamic Invariant Fuzzing**: Automated 256-run property-based state fuzz tests generating randomized caller addresses and reentrancy execution sequences to break solvency invariants.
3. **Finding Normalization & Correlation**:
   - Consolidates duplicated findings across engines pointing to the same line numbers or function targets.
   - Cross-engine corroboration elevates finding confidence and assigns unified CVSS scores.
4. **Risk Scoring Engine**:
   - Computes weighted vulnerability scores (Critical: 35, High: 20, Medium: 8, Low: 3, Info: 0.5, Fuzz failure: 15).
   - Classifies contracts into discrete postures: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `SECURE`.
5. **Reporting & Persistence**:
   - Generates publication-ready PDF security audit reports via ReportLab.
   - Persists contracts, audit history, and findings in PostgreSQL (or async SQLite).

```
[ User Browser ]
       │  (Vite + React + TypeScript + Tailwind CSS)
       ▼
[ FastAPI Backend /api/v1 ]
   ├── [ File & Explorer Ingestion ] ──> /storage/uploads/
   ├── [ Scanner Manager ]
   │      ├── Slither Static Engine
   │      ├── Mythril Symbolic Engine
   │      ├── Foundry Fuzz Tester (forge test --fuzz-runs 256)
   │      └── Custom Detectors (CEI, Auth, Calls, Oracles)
   ├── [ Correlation & Deduplication Engine ]
   ├── [ CVSS & Risk Assessment Engine ]
   ├── [ ReportLab PDF Audit Generator ] ──> /storage/reports/
   └── [ SQLAlchemy Database ] ──> PostgreSQL / SQLite
```
