# Known Limitations & Scope Boundaries: SecureChain Auditor

This document provides a transparent, technically rigorous assessment of the design boundaries, environmental prerequisites, and operational limitations of SecureChain Auditor.

---

## 1. Multi-Engine & Symbolic Execution Limitations

### Mythril Docker Dependency
- **Current Architecture**: Mythril's EVM symbolic execution engine relies on native C-extensions (such as Z3 and pyevmasm) that currently lack full native wheel support on Python 3.13 macOS ARM64 environments.
- **Docker Requirement**: To execute full symbolic execution paths, Mythril is dispatched either via a local Docker daemon (`docker run mythril/myth`) or a compatible native binary.
- **Fail-Safe Behavior**: If neither Docker nor native `myth` is active, SecureChain Auditor explicitly flags Mythril as `unverified` and excludes it from the `executed_engines` list. The system **never** substitutes synthetic or heuristic alerts disguised as genuine Mythril output.

---

## 2. Dynamic Invariant Fuzzing Boundaries

### Scope of Property Verification
- **Invariant Harnesses**: Dynamic property fuzzing with Foundry Forge evaluates stateful invariants (e.g., contract balance solvency, owner-only authorization, reentrancy guards) against parameterized test suites (`SecurityTest.t.sol`).
- **Input Runs**: Default fuzz runs are bounded at 256 iterations to ensure sub-second API responses. While 256 iterations reliably discover common exploit paths, deep multi-transaction sequences requiring extreme edge-case calldata may escape detection.
- **Custom Protocol Logic**: For arbitrary novel protocols with proprietary business logic, custom invariant rules must be added to the test suite to evaluate domain-specific economic invariants.

---

## 3. Static Analysis Limitations

### Soundness vs. Completeness
- **Inline Assembly**: Deep EVM assembly blocks using dynamic memory or transient storage (`TSTORE`/`TLOAD`) can obscure dataflow from AST-based detectors.
- **Cross-Contract Composability**: The scanner evaluates self-contained Solidity files and imported interfaces. Arbitrary dynamic delegatecall proxy chains where implementation logic resides exclusively in on-chain bytecode without verified source require decompilation or on-chain trace simulation.

---

## 4. Benchmark Scope & Real-World Generalization

### Benchmark Testbed
- The platform was evaluated on a 72-contract benchmark suite consisting of:
  - 60 parameterized contracts covering core vulnerability classes and secure baselines.
  - 12 independent public contracts sourced from the Smart Contract Weakness Classification (SWC) Registry and real-world exploit post-mortems.
- **Result Interpretation**: While the platform achieved 100% precision and recall on this curated benchmark, this metric demonstrates internal detection consistency across known vulnerability patterns. It does **not** constitute a formal guarantee of 100% real-world detection across all arbitrary smart contracts.

---

## 5. Security Tooling vs. Human Auditing

SecureChain Auditor is designed as an automated developer-assistive tool and continuous security linting platform. It is **not** a replacement for formal verification and third-party human security audits by certified smart contract auditing firms.

