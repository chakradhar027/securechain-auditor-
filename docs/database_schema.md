# SecureChain Auditor – Database Schema Specification

SecureChain Auditor supports both PostgreSQL and async SQLite engines via SQLAlchemy 2.0.

```
       ┌────────────────────────┐
       │       contracts        │
       ├────────────────────────┤
       │ id (PK, Integer)       │
       │ name (Varchar)         │
       │ filename (Varchar)     │
       │ file_path (Varchar)    │
       │ source_code (Text)     │
       │ byte_size (Integer)    │
       │ compiler_ver (Varchar) │
       │ address (Varchar)      │
       │ network (Varchar)      │
       │ created_at (DateTime)  │
       └───────────┬────────────┘
                   │ 1
                   │
                   │ N
       ┌───────────▼────────────┐
       │         scans          │
       ├────────────────────────┤
       │ id (PK, Integer)       │
       │ contract_id (FK)       │
       │ status (Varchar)       │
       │ engines_used (JSON)    │
       │ risk_score (Float)     │
       │ risk_level (Varchar)   │
       │ total_vulns (Integer)  │
       │ critical_count (Int)   │
       │ high_count (Int)       │
       │ medium_count (Int)     │
       │ low_count (Int)        │
       │ info_count (Int)       │
       │ fuzz_passed (Integer)  │
       │ fuzz_total (Integer)   │
       │ fuzz_details (JSON)    │
       │ report_path (Varchar)  │
       │ started_at (DateTime)  │
       │ completed_at (DateTime)│
       └───────────┬────────────┘
                   │ 1
                   │
                   │ N
       ┌───────────▼────────────┐
       │        findings        │
       ├────────────────────────┤
       │ id (PK, Integer)       │
       │ scan_id (FK)           │
       │ title (Varchar)        │
       │ category (Varchar)     │
       │ severity (Varchar)     │
       │ confidence (Varchar)   │
       │ engine (Varchar)       │
       │ description (Text)     │
       │ recommendation (Text)  │
       │ file_path (Varchar)    │
       │ line_start (Integer)   │
       │ line_end (Integer)     │
       │ code_snippet (Text)    │
       │ cwe_id (Varchar)       │
       │ swc_id (Varchar)       │
       │ cvss_score (Float)     │
       └────────────────────────┘
```
