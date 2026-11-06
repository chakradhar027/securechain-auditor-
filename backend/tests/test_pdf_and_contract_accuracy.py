import os
import re
import base64
import zlib
import pytest
from app.config import settings
from app.utils.file_validator import extract_contract_name
from app.analysis.recommendations import inspect_call_safety, get_recommendation_for_finding
from app.reports.pdf_generator import PDFGenerator

def resolve_contract_path(rel: str) -> str:
    if os.path.isabs(rel):
        return rel
    if os.path.exists(rel):
        return os.path.abspath(rel)
    p = os.path.join(settings.BASE_DIR, rel)
    if os.path.exists(p):
        return p
    return rel

def extract_pdf_text(pdf_path: str) -> str:
    """Extracts decoded text streams from ReportLab PDF using standard library."""
    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    pos = 0
    all_text = []
    while True:
        s = pdf_bytes.find(b"stream", pos)
        if s == -1:
            break
        nl = pdf_bytes.find(b"\n", s)
        e = pdf_bytes.find(b"endstream", s)
        if e == -1:
            break
        raw = pdf_bytes[nl+1:e].strip()
        pos = e + 9

        try:
            a85 = base64.a85decode(raw, adobe=True)
            dec = zlib.decompress(a85)
            all_text.append(dec.decode("latin1", errors="replace"))
        except Exception:
            try:
                dec = zlib.decompress(raw)
                all_text.append(dec.decode("latin1", errors="replace"))
            except Exception:
                pass
    return " ".join(all_text)

def test_contract_name_extraction_handles_comments_and_abstract_bases():
    # 1. ReentrancyFixed.sol has '@notice Fixed contract adopting ...' and 'abstract contract ReentrancyGuard'
    with open(resolve_contract_path("contracts/secure/ReentrancyFixed.sol"), "r") as f:
        reentrancy_fixed_code = f.read()
    name = extract_contract_name(reentrancy_fixed_code, filename="ReentrancyFixed.sol")
    assert name == "ReentrancyFixed", f"Expected 'ReentrancyFixed', got '{name}'"
    assert name != "adopting", "Must not extract 'adopting' from docstring comment"
    assert name != "ReentrancyGuard", "Must not extract abstract base contract over primary contract"

    # 2. AccessControlFixed.sol has '@notice Fixed contract adopting ...'
    with open(resolve_contract_path("contracts/secure/AccessControlFixed.sol"), "r") as f:
        ac_fixed_code = f.read()
    name_ac = extract_contract_name(ac_fixed_code, filename="AccessControlFixed.sol")
    assert name_ac == "AccessControlFixed"
    assert name_ac != "adopting"

    # 3. OracleFixed.sol has interface AggregatorV3Interface and '@notice Fixed contract adopting ...'
    with open(resolve_contract_path("contracts/secure/OracleFixed.sol"), "r") as f:
        oracle_fixed_code = f.read()
    name_oracle = extract_contract_name(oracle_fixed_code, filename="OracleFixed.sol")
    assert name_oracle == "OracleFixed"
    assert name_oracle != "adopting"
    assert name_oracle != "AggregatorV3Interface"

    # 4. UncheckedCallFixed.sol has abstract contract ReentrancyGuard
    with open(resolve_contract_path("contracts/secure/UncheckedCallFixed.sol"), "r") as f:
        uc_fixed_code = f.read()
    name_uc = extract_contract_name(uc_fixed_code, filename="UncheckedCallFixed.sol")
    assert name_uc == "UncheckedCallFixed"
    assert name_uc != "ReentrancyGuard"

    # 5. Fallback behavior when no contract keyword exists
    no_contract_code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
    fallback_name = extract_contract_name(no_contract_code, default="ContractFallback", filename="MyVault.sol")
    assert fallback_name == "MyVault"

def test_low_level_call_safety_inspection():
    with open(resolve_contract_path("contracts/secure/ReentrancyFixed.sol"), "r") as f:
        fixed_code = f.read()
    safety_fixed = inspect_call_safety(fixed_code, line_no=45)
    assert safety_fixed["return_checked"] is True, "Expected return value to be checked in ReentrancyFixed"
    assert safety_fixed["reentrancy_protected"] is True, "Expected reentrancy protection in ReentrancyFixed"
    assert safety_fixed["is_safe"] is True

    with open(resolve_contract_path("contracts/secure/UncheckedCallFixed.sol"), "r") as f:
        uc_fixed_code = f.read()
    safety_uc_fixed = inspect_call_safety(uc_fixed_code, line_no=47)
    assert safety_uc_fixed["return_checked"] is True
    assert safety_uc_fixed["reentrancy_protected"] is True
    assert safety_uc_fixed["is_safe"] is True

    with open(resolve_contract_path("contracts/vulnerable/ReentrancyVulnerable.sol"), "r") as f:
        vuln_code = f.read()
    safety_vuln = inspect_call_safety(vuln_code, line_no=25)
    assert safety_vuln["return_checked"] is True
    assert safety_vuln["reentrancy_protected"] is False, "ReentrancyVulnerable must not be marked reentrancy protected"
    assert safety_vuln["is_safe"] is False

    with open(resolve_contract_path("contracts/vulnerable/UncheckedCallVulnerable.sol"), "r") as f:
        uc_vuln_code = f.read()
    safety_uc_vuln = inspect_call_safety(uc_vuln_code, line_no=26)
    assert safety_uc_vuln["return_checked"] is False, "UncheckedCallVulnerable must not have return checked"
    assert safety_uc_vuln["is_safe"] is False

def test_recommendation_enrichment_context_aware():
    with open(resolve_contract_path("contracts/secure/ReentrancyFixed.sol"), "r") as f:
        src = f.read()

    # Informational finding on safe low-level call in ReentrancyFixed
    finding_safe = {
        "title": "Slither: Low Level Calls",
        "category": "UNCHECKED_CALL",
        "severity": "INFORMATIONAL",
        "line_start": 45,
        "line_end": 45,
        "code_snippet": '(bool success, ) = msg.sender.call{value: balance}("");\nrequire(success, "ETH transfer failed");'
    }
    rec_safe = get_recommendation_for_finding(finding_safe, source_code=src)
    assert "Informational Advisory: Low-level call implementation verified" in rec_safe
    assert "SafeERC20" not in rec_safe
    assert "Always unpack boolean success flags" not in rec_safe

    # Active unchecked call vulnerability
    finding_vuln = {
        "title": "Unchecked Return Value of Low-Level 'call'",
        "category": "UNCHECKED_CALL",
        "severity": "HIGH",
        "line_start": 26,
        "line_end": 26,
        "code_snippet": "target.call(data);"
    }
    with open(resolve_contract_path("contracts/vulnerable/UncheckedCallVulnerable.sol"), "r") as f:
        vuln_src = f.read()
    rec_vuln = get_recommendation_for_finding(finding_vuln, source_code=vuln_src)
    assert "Capture and verify the return status" in rec_vuln

def test_pdf_generation_fixed_and_vulnerable():
    # 1. Generate PDF for ReentrancyFixed
    with open(resolve_contract_path("contracts/secure/ReentrancyFixed.sol"), "r") as f:
        fixed_src = f.read()

    contract_fixed = {
        "name": "adopting",  # Simulate existing corrupted db field to verify self-correction
        "filename": "ReentrancyFixed.sol",
        "compiler_version": "^0.8.20",
        "source_code": fixed_src,
        "address": None,
        "network": "ethereum"
    }
    scan_fixed = {
        "risk_score": 0.0,
        "risk_level": "SECURE",
        "engines_used": ["custom", "slither", "foundry"],
        "total_vulnerabilities": 2,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 2,
        "fuzz_passed": 1,
        "fuzz_total": 1
    }
    findings_fixed = [
        {
            "title": "Slither: Solc Version",
            "category": "OTHER",
            "severity": "INFORMATIONAL",
            "engine": "slither",
            "description": "Version constraint ^0.8.20 contains known severe issues.\n\n[Exploitability Assessment]: Informational / Non-Exploitable Advisory.",
            "recommendation": "Lock the pragma compiler version to a specific release.",
            "line_start": 2,
            "line_end": 2,
            "code_snippet": "pragma solidity ^0.8.20;"
        },
        {
            "title": "Slither: Low Level Calls",
            "category": "UNCHECKED_CALL",
            "severity": "INFORMATIONAL",
            "engine": "slither",
            "description": "Low level call in ReentrancyFixed.withdraw().\n\n[Static Inspection Verification]: Verified safe implementation.",
            "recommendation": "Informational Advisory: Low-level call implementation verified. Return value is explicitly checked.",
            "line_start": 45,
            "line_end": 45,
            "code_snippet": '(bool success, ) = msg.sender.call{value: balance}("");\nrequire(success, "ETH transfer failed");'
        }
    ]

    pdf_fixed_path = PDFGenerator.generate_report(
        scan_id=9901,
        contract_data=contract_fixed,
        scan_data=scan_fixed,
        findings=findings_fixed,
        fuzz_details={"tests": [{"name": "testFuzz_Reentrancy_Secure", "status": "PASSED", "runs": 256, "reason": "Invariant verified"}]}
    )

    assert os.path.exists(pdf_fixed_path)
    assert os.path.getsize(pdf_fixed_path) > 1000

    with open(pdf_fixed_path, "rb") as f:
        pdf_bytes = f.read()
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes[-1024:]

    # Inspect extracted text
    full_text_fixed = extract_pdf_text(pdf_fixed_path)
    assert "ReentrancyFixed" in full_text_fixed
    assert "adopting" not in full_text_fixed
    assert "0 Active Vulnerabilities" in full_text_fixed
    assert "Informational Advisory" in full_text_fixed
    assert "1 Passed / 1 Invariants Executed" in full_text_fixed

    # Test static-only scan (Foundry not selected) displays 'Not executed'
    scan_static = dict(scan_fixed)
    scan_static["engines_used"] = ["custom", "slither"]
    pdf_static_path = PDFGenerator.generate_report(
        scan_id=9903,
        contract_data=contract_fixed,
        scan_data=scan_static,
        findings=findings_fixed,
        fuzz_details={"tests": []}
    )
    full_text_static = extract_pdf_text(pdf_static_path)
    assert "Not executed" in full_text_static

    # 2. Generate PDF for ReentrancyVulnerable
    with open(resolve_contract_path("contracts/vulnerable/ReentrancyVulnerable.sol"), "r") as f:
        vuln_src = f.read()

    contract_vuln = {
        "name": "ReentrancyVulnerable",
        "filename": "ReentrancyVulnerable.sol",
        "compiler_version": "^0.8.20",
        "source_code": vuln_src,
        "address": None,
        "network": "ethereum"
    }
    scan_vuln = {
        "risk_score": 100.0,
        "risk_level": "CRITICAL",
        "engines_used": ["custom", "slither", "foundry"],
        "total_vulnerabilities": 2,
        "critical_count": 2,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
        "fuzz_passed": 2,
        "fuzz_total": 3
    }
    findings_vuln = [
        {
            "title": "[Multi-Engine] Potential Reentrancy Vulnerability in 'withdraw'",
            "category": "REENTRANCY",
            "severity": "CRITICAL",
            "engine": "consolidated (custom, slither)",
            "description": "In function 'withdraw', an external call is executed on line 25 before state is updated.\n\n[Exploitability Assessment]: High Risk / Active Vulnerability.",
            "recommendation": "Implement Checks-Effects-Interactions (CEI) & ReentrancyGuard",
            "line_start": 25,
            "line_end": 29,
            "code_snippet": "(bool success, ) = msg.sender.call{value: balance}(\"\");\nbalances[msg.sender] = 0;"
        }
    ]

    pdf_vuln_path = PDFGenerator.generate_report(
        scan_id=9902,
        contract_data=contract_vuln,
        scan_data=scan_vuln,
        findings=findings_vuln,
        fuzz_details={"tests": []}
    )

    assert os.path.exists(pdf_vuln_path)
    assert os.path.getsize(pdf_vuln_path) > 1000

    with open(pdf_vuln_path, "rb") as f:
        pdf_bytes_v = f.read()
    assert pdf_bytes_v.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes_v[-1024:]

    full_text_vuln = extract_pdf_text(pdf_vuln_path)
    assert "ReentrancyVulnerable" in full_text_vuln
    assert "CRITICAL" in full_text_vuln
    assert "Vulnerable Code" in full_text_vuln

@pytest.mark.asyncio
async def test_reports_api_contract_names_and_downloads():
    from httpx import AsyncClient, ASGITransport
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test history listing includes contract_name
        res = await client.get("/api/v1/history/?limit=100")
        assert res.status_code == 200
        scans = res.json()
        assert len(scans) > 0

        # Scan 6 and Scan 8 verification
        scan_6 = next((s for s in scans if s["id"] == 6), None)
        scan_8 = next((s for s in scans if s["id"] == 8), None)

        if scan_6:
            assert scan_6["contract_name"] == "ReentrancyVulnerable"
            assert scan_6["risk_score"] == 100.0
            assert scan_6["risk_level"] == "CRITICAL"
            assert "mythril" not in scan_6["engines_used"]
            dl_6 = await client.get("/api/v1/reports/download/6")
            assert dl_6.status_code == 200
            assert dl_6.headers.get("content-type") == "application/pdf"
            assert len(dl_6.content) > 1000

        if scan_8:
            assert scan_8["contract_name"] == "ReentrancyFixed"
            assert scan_8["risk_score"] == 0.0
            assert scan_8["risk_level"] == "SECURE"
            assert "mythril" not in scan_8["engines_used"]
            dl_8 = await client.get("/api/v1/reports/download/8")
            assert dl_8.status_code == 200
            assert dl_8.headers.get("content-type") == "application/pdf"
            assert len(dl_8.content) > 1000

        # Verify no scan in history has 'adopting' or generic 'Contract #X' as contract_name
        for s in scans:
            assert s["contract_name"] != "adopting", f"Scan {s['id']} still has 'adopting' as contract_name"

@pytest.mark.asyncio
async def test_executed_engines_distinction_without_docker():
    from app.scanners.scanner_manager import ScannerManager
    manager = ScannerManager()
    with open(resolve_contract_path("contracts/secure/ReentrancyFixed.sol"), "r") as f:
        code = f.read()
    
    # Request all four engines including mythril
    findings, fuzz_meta = await manager.run_scanners(
        file_path=resolve_contract_path("contracts/secure/ReentrancyFixed.sol"),
        source_code=code,
        enabled_engines=["custom", "slither", "mythril", "foundry"]
    )
    # When Docker is not running and myth binary is absent, mythril must NOT be in executed engines
    assert "mythril" not in manager.last_executed_engines
    assert "custom" in manager.last_executed_engines
    assert "slither" in manager.last_executed_engines
    assert "foundry" in manager.last_executed_engines

