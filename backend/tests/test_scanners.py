import os
import pytest
from app.config import settings
from app.scanners.scanner_manager import ScannerManager
from app.scanners.foundry_scanner import FoundryScanner
from app.scanners.slither_scanner import SlitherScanner

def resolve_contract_path(rel: str) -> str:
    if os.path.isabs(rel):
        return rel
    if os.path.exists(rel):
        return os.path.abspath(rel)
    p = os.path.join(settings.BASE_DIR, rel)
    if os.path.exists(p):
        return p
    return rel

VULN_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TestVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    function withdraw() public {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        balances[msg.sender] = 0;
    }

    function kill() public {
        selfdestruct(payable(owner));
    }
}
"""

@pytest.mark.asyncio
async def test_scanner_manager_pipeline():
    manager = ScannerManager()
    findings, fuzz_meta = await manager.run_scanners(
        file_path="contracts/vulnerable/TestVault.sol",
        source_code=VULN_CODE,
        enabled_engines=["custom", "slither", "mythril", "foundry"]
    )

    assert len(findings) > 0
    assert fuzz_meta["total"] > 0
    engines_found = {f.engine for f in findings}
    assert "custom" in engines_found

@pytest.mark.asyncio
async def test_foundry_fuzz_vulnerable_counterexample():
    scanner = FoundryScanner()
    code_path = resolve_contract_path("contracts/vulnerable/AccessControlVulnerable.sol")
    with open(code_path, "r") as f:
        code = f.read()

    findings, fuzz_meta = await scanner.run_fuzz_tests(code_path, code)
    assert fuzz_meta["total"] > 0
    # Invariant failure should be detected with counterexample
    assert fuzz_meta["failed"] > 0
    failed_test = next(t for t in fuzz_meta["tests"] if t["status"] == "FAILED")
    assert "counterexample" in failed_test
    assert any(f.engine == "foundry" for f in findings)

@pytest.mark.asyncio
async def test_foundry_fuzz_secure_contract_clean():
    scanner = FoundryScanner()
    code_path = resolve_contract_path("contracts/secure/ReentrancyFixed.sol")
    with open(code_path, "r") as f:
        code = f.read()

    findings, fuzz_meta = await scanner.run_fuzz_tests(code_path, code)
    assert fuzz_meta["total"] > 0
    assert fuzz_meta["failed"] == 0
    assert len(findings) == 0

@pytest.mark.asyncio
async def test_slither_real_execution():
    scanner = SlitherScanner()
    code_path = resolve_contract_path("contracts/vulnerable/ReentrancyVulnerable.sol")
    with open(code_path, "r") as f:
        code = f.read()

    findings = await scanner.scan(code_path, code)
    # Slither should detect reentrancy-eth or similar
    assert len(findings) > 0
    assert any(f.engine == "slither" for f in findings)

@pytest.mark.asyncio
async def test_mythril_json_parser():
    from app.scanners.mythril_scanner import MythrilScanner
    scanner = MythrilScanner()
    mock_mythril_json = """{
        "success": true,
        "error": null,
        "issues": [
            {
                "title": "State change after external call",
                "swc-id": "107",
                "severity": "High",
                "description": "The contract account state is accessed after an external call to [attacker].",
                "function": "withdraw()",
                "lineno": 29,
                "address": 240,
                "code": "balances[msg.sender] = 0;"
            }
        ]
    }"""
    code = "function withdraw() public { msg.sender.call{value: 1}(''); balances[msg.sender] = 0; }"
    findings = scanner._parse_mythril_json(mock_mythril_json, code, "Test.sol", engine="mythril (docker)")
    assert len(findings) == 1
    f = findings[0]
    assert f.engine == "mythril (docker)"
    assert f.severity == "HIGH"
    assert f.category == "REENTRANCY"
    assert f.swc_id == "SWC-107"
    assert f.line_start == 29

@pytest.mark.asyncio
async def test_mythril_fallback_labeling():
    from app.scanners.mythril_scanner import MythrilScanner
    scanner = MythrilScanner()
    code = "function test() public { require(block.timestamp > 100); }"
    findings = scanner._fallback_symbolic_analysis(code, "Test.sol")
    assert len(findings) > 0
    # Must be explicitly labeled as 'symbolic-heuristic', NEVER as 'mythril'
    for f in findings:
        assert f.engine == "symbolic-heuristic"
        assert f.engine != "mythril"
        assert "[Heuristic]" in f.title

@pytest.mark.asyncio
async def test_all_four_contract_pairs_regression():
    from app.analysis.correlation import FindingCorrelator
    from app.analysis.risk_engine import RiskEngine

    manager = ScannerManager()
    correlator = FindingCorrelator()
    risk_engine = RiskEngine()

    pairs = [
        {
            "name": "Reentrancy",
            "vuln_path": resolve_contract_path("contracts/vulnerable/ReentrancyVulnerable.sol"),
            "fixed_path": resolve_contract_path("contracts/secure/ReentrancyFixed.sol"),
            "expected_category": "REENTRANCY",
            "min_vuln_score": 80.0
        },
        {
            "name": "Access Control",
            "vuln_path": resolve_contract_path("contracts/vulnerable/AccessControlVulnerable.sol"),
            "fixed_path": resolve_contract_path("contracts/secure/AccessControlFixed.sol"),
            "expected_category": "ACCESS_CONTROL",
            "min_vuln_score": 80.0
        },
        {
            "name": "Unchecked Call",
            "vuln_path": resolve_contract_path("contracts/vulnerable/UncheckedCallVulnerable.sol"),
            "fixed_path": resolve_contract_path("contracts/secure/UncheckedCallFixed.sol"),
            "expected_category": "UNCHECKED_CALL",
            "min_vuln_score": 55.0
        },
        {
            "name": "Oracle",
            "vuln_path": resolve_contract_path("contracts/vulnerable/OracleVulnerable.sol"),
            "fixed_path": resolve_contract_path("contracts/secure/OracleFixed.sol"),
            "expected_category": "ORACLE_MANIPULATION",
            "min_vuln_score": 80.0
        }
    ]

    for p in pairs:
        # 1. Test Vulnerable Contract
        with open(p["vuln_path"], "r") as f:
            vuln_code = f.read()
        raw_vuln, fuzz_vuln = await manager.run_scanners(
            p["vuln_path"], vuln_code, ["custom", "slither"]
        )
        corr_vuln = correlator.correlate(raw_vuln)
        v_score, v_level, v_counts = risk_engine.calculate_risk(corr_vuln, fuzz_vuln)

        assert v_score >= p["min_vuln_score"], f"{p['name']} vulnerable score {v_score} < {p['min_vuln_score']}"
        assert v_level in ["HIGH", "CRITICAL"], f"{p['name']} level {v_level} not HIGH/CRITICAL"
        categories_found = {f["category"] for f in corr_vuln}
        assert p["expected_category"] in categories_found, f"{p['expected_category']} not detected in {p['name']}"

        # 2. Test Fixed Contract
        with open(p["fixed_path"], "r") as f:
            fixed_code = f.read()
        raw_fixed, fuzz_fixed = await manager.run_scanners(
            p["fixed_path"], fixed_code, ["custom", "slither"]
        )
        corr_fixed = correlator.correlate(raw_fixed)
        f_score, f_level, f_counts = risk_engine.calculate_risk(corr_fixed, fuzz_fixed)

        assert f_score == 0.0, f"{p['name']} fixed score {f_score} != 0.0"
        assert f_level == "SECURE", f"{p['name']} fixed level {f_level} != SECURE"
        assert f_counts["CRITICAL"] == 0, f"{p['name']} fixed has CRITICAL findings"
        assert f_counts["HIGH"] == 0, f"{p['name']} fixed has HIGH findings"
        assert f_counts["MEDIUM"] == 0, f"{p['name']} fixed has MEDIUM findings"
        assert f_counts["LOW"] == 0, f"{p['name']} fixed has LOW findings"
