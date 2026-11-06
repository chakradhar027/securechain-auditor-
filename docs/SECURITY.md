# Security Policy & Implementation: SecureChain Auditor

This document outlines the security architecture, threat model, input sanitization policies, and defensive design principles implemented in SecureChain Auditor.

---

## 1. Threat Model & Defense In Depth

SecureChain Auditor processes untrusted Solidity source code uploaded by external users. The platform implements multi-layered security controls to isolate untrusted code and prevent sandbox escape, command injection, and data tampering.

```
[ Untrusted Input ]
        │
        ▼
[ Layer 1: Input Validation & MIME/Extension Verification ]
        │
        ▼
[ Layer 2: Filename Sanitization & Path Sandboxing ]
        │
        ▼
[ Layer 3: Parameterized Subprocess Spawning (No Shell Execution) ]
        │
        ▼
[ Layer 4: Execution Timeouts & Process Tree Termination ]
        │
        ▼
[ Layer 5: Parameterized Database Queries (SQLAlchemy ORM) ]
```

---

## 2. File Ingestion & Path Traversal Protections

- **Extension Whitelist**: Only `.sol` extensions are permitted. All executable formats (`.exe`, `.sh`, `.py`, `.elf`), binaries, and ambiguous scripts are rejected with HTTP 400.
- **Path Sanitization**: Filenames are sanitized via `werkzeug.utils.secure_filename` or dedicated regex replacements. Characters such as `..`, `/`, `\`, and null bytes are stripped.
- **Unique Storage Keying**: Uploaded files are prefixed with a pseudo-random 8-character hex token (`{uuid[:8]}_{filename}`) and saved exclusively into the canonical directory `backend/storage/uploads/`.
- **Empty File & Size Guards**: Files smaller than 1 byte or larger than 5 MB are rejected upfront to mitigate denial-of-service (DoS) attacks.

---

## 3. Subprocess Execution & Command Injection Prevention

- **No `shell=True`**: All CLI tools (Slither, Foundry `forge`, Mythril) are invoked via Python's `asyncio.create_subprocess_exec` passing arguments as a strictly typed list of strings.
- **Argument Escaping**: User-controlled parameters (such as contract names or filenames) are never evaluated through shell variable interpolation, backticks, or command substitution.
- **Timeout Enforcement**: All external commands enforce a timeout (e.g., 60 seconds for Slither and 90 seconds for Forge). If a process hangs or enters an infinite loop, it is terminated immediately, preventing resource exhaustion.

---

## 4. Database & ORM Protections

- **Parameterized Queries**: All database interactions use SQLAlchemy 2.0 with asynchronous ORM models and strictly typed schemas.
- **No Raw SQL Concatenation**: User inputs are bound as parameters, eliminating SQL injection vectors.
- **Canonical Path Anchoring**: SQLite database paths are anchored absolutely to `backend/storage/securechain.db`, eliminating split-brain database behavior or directory-dependent write targets.

---

## 5. Secret & Credential Hygiene

- **Zero Hardcoded Secrets**: The repository contains zero private keys, API secrets, or database passwords.
- **Environment Isolation**: The `.gitignore` excludes `.env`, `.env.local`, `.env.production`, `*.pem`, `*.key`, and all SQLite database files (`*.db`).
- **Safe Template**: `.env.example` provides non-sensitive placeholders.

---

## 6. Audit & Exploitation Disclaimer

SecureChain Auditor is a vulnerability detection tool designed to identify common security vulnerabilities and code weaknesses. It does **not** guarantee that a contract is completely free of defects or economic vulnerabilities. Critical decentralized applications should always undergo comprehensive third-party human security audits before deployment.
