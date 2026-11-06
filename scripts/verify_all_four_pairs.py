import asyncio
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from app.config import settings
from app.scanners.scanner_manager import ScannerManager
from app.analysis.correlation import FindingCorrelator
from app.analysis.risk_engine import RiskEngine
from app.reports.pdf_generator import PDFGenerator
from app.utils.file_validator import extract_contract_name

async def test_all_pairs():
    manager = ScannerManager()
    correlator = FindingCorrelator()
    risk_engine = RiskEngine()

    pairs = [
        {
            "category_name": "Reentrancy",
            "vuln_file": ROOT_DIR / "contracts" / "vulnerable" / "ReentrancyVulnerable.sol",
            "fixed_file": ROOT_DIR / "contracts" / "secure" / "ReentrancyFixed.sol",
            "expected_vuln_category": "REENTRANCY",
        },
        {
            "category_name": "Access Control",
            "vuln_file": ROOT_DIR / "contracts" / "vulnerable" / "AccessControlVulnerable.sol",
            "fixed_file": ROOT_DIR / "contracts" / "secure" / "AccessControlFixed.sol",
            "expected_vuln_category": "ACCESS_CONTROL",
        },
        {
            "category_name": "Unchecked External Calls",
            "vuln_file": ROOT_DIR / "contracts" / "vulnerable" / "UncheckedCallVulnerable.sol",
            "fixed_file": ROOT_DIR / "contracts" / "secure" / "UncheckedCallFixed.sol",
            "expected_vuln_category": "UNCHECKED_CALL",
        },
        {
            "category_name": "Oracle Manipulation",
            "vuln_file": ROOT_DIR / "contracts" / "vulnerable" / "OracleVulnerable.sol",
            "fixed_file": ROOT_DIR / "contracts" / "secure" / "OracleFixed.sol",
            "expected_vuln_category": "ORACLE_MANIPULATION",
        },
    ]

    print("=" * 80)
    print("      REAL REGRESSION SCAN VERIFICATION: ALL 4 CONTRACT PAIRS")
    print("=" * 80)

    results = []

    for idx, p in enumerate(pairs, 1):
        print(f"\n--- PAIR {idx}: {p['category_name']} ---")

        # 1. Scan Vulnerable Contract
        with open(p["vuln_file"], "r", encoding="utf-8") as f:
            v_code = f.read()
        v_name = extract_contract_name(v_code, p["vuln_file"].name)
        v_raw, v_fuzz = await manager.run_scanners(
            str(p["vuln_file"]), v_code, ["custom", "slither", "mythril", "foundry"]
        )
        v_engines = list(manager.last_executed_engines)
        v_corr = correlator.correlate(v_raw)
        v_score, v_level, v_counts = risk_engine.calculate_risk(v_corr, v_fuzz)

        print(f"  [Vulnerable: {p['vuln_file'].name}]")
        print(f"    Extracted Contract Name: {v_name}")
        print(f"    Executed Engines: {v_engines} (Mythril executed: {'mythril' in v_engines})")
        print(f"    Risk Score: {v_score}/100 ({v_level})")
        print(f"    Counts: {v_counts}")
        print(f"    Foundry Invariants: {v_fuzz['passed']}/{v_fuzz['total']} passed, {v_fuzz['failed']} failed")
        v_categories = {f['category'] for f in v_corr}
        print(f"    Detected Categories: {v_categories}")
        assert p["expected_vuln_category"] in v_categories, f"Expected {p['expected_vuln_category']} in vulnerable contract"
        assert v_score >= 50.0, f"Expected vulnerable risk score >= 50.0, got {v_score}"

        # 2. Scan Fixed Contract
        with open(p["fixed_file"], "r", encoding="utf-8") as f:
            f_code = f.read()
        f_name = extract_contract_name(f_code, p["fixed_file"].name)
        f_raw, f_fuzz = await manager.run_scanners(
            str(p["fixed_file"]), f_code, ["custom", "slither", "mythril", "foundry"]
        )
        f_engines = list(manager.last_executed_engines)
        f_corr = correlator.correlate(f_raw)
        f_score, f_level, f_counts = risk_engine.calculate_risk(f_corr, f_fuzz)

        print(f"  [Fixed: {p['fixed_file'].name}]")
        print(f"    Extracted Contract Name: {f_name}")
        print(f"    Executed Engines: {f_engines} (Mythril executed: {'mythril' in f_engines})")
        print(f"    Risk Score: {f_score}/100 ({f_level})")
        print(f"    Counts: {f_counts}")
        print(f"    Foundry Invariants: {f_fuzz['passed']}/{f_fuzz['total']} passed, {f_fuzz['failed']} failed")
        f_active_categories = {f['category'] for f in f_corr if f['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
        print(f"    Active Categories: {f_active_categories}")
        assert p["expected_vuln_category"] not in f_active_categories, f"Vulnerability {p['expected_vuln_category']} still active in fixed contract"
        assert f_score == 0.0, f"Expected 0.0 for fixed contract, got {f_score}"
        assert f_level == "SECURE"

        # 3. Generate PDF for both to verify generation
        v_pdf = PDFGenerator.generate_report(
            scan_id=9000 + idx * 2,
            contract_data={"name": v_name, "filename": p["vuln_file"].name, "source_code": v_code},
            scan_data={
                "risk_score": v_score,
                "risk_level": v_level,
                "engines_used": v_engines,
                "total_vulnerabilities": len(v_corr),
                "critical_count": v_counts.get("CRITICAL", 0),
                "high_count": v_counts.get("HIGH", 0),
                "medium_count": v_counts.get("MEDIUM", 0),
                "low_count": v_counts.get("LOW", 0),
                "info_count": v_counts.get("INFORMATIONAL", 0),
                "fuzz_passed": v_fuzz["passed"],
                "fuzz_total": v_fuzz["total"]
            },
            findings=v_corr,
            fuzz_details=v_fuzz
        )

        f_pdf = PDFGenerator.generate_report(
            scan_id=9000 + idx * 2 + 1,
            contract_data={"name": f_name, "filename": p["fixed_file"].name, "source_code": f_code},
            scan_data={
                "risk_score": f_score,
                "risk_level": f_level,
                "engines_used": f_engines,
                "total_vulnerabilities": len(f_corr),
                "critical_count": f_counts.get("CRITICAL", 0),
                "high_count": f_counts.get("HIGH", 0),
                "medium_count": f_counts.get("MEDIUM", 0),
                "low_count": f_counts.get("LOW", 0),
                "info_count": f_counts.get("INFORMATIONAL", 0),
                "fuzz_passed": f_fuzz["passed"],
                "fuzz_total": f_fuzz["total"]
            },
            findings=f_corr,
            fuzz_details=f_fuzz
        )

        assert os.path.exists(v_pdf) and os.path.getsize(v_pdf) > 2000
        assert os.path.exists(f_pdf) and os.path.getsize(f_pdf) > 2000
        print(f"    Generated Vulnerable PDF: {os.path.basename(v_pdf)} ({os.path.getsize(v_pdf)} bytes)")
        print(f"    Generated Fixed PDF: {os.path.basename(f_pdf)} ({os.path.getsize(f_pdf)} bytes)")

        results.append({
            "pair": p["category_name"],
            "vuln": {"file": p["vuln_file"].name, "score": v_score, "level": v_level, "vulns": len(v_corr)},
            "fixed": {"file": p["fixed_file"].name, "score": f_score, "level": f_level, "vulns": len(f_corr), "info": f_counts.get("INFORMATIONAL", 0)}
        })

    print("\n" + "=" * 80)
    print("  ALL 4 VULNERABLE/FIXED PAIRS SCANNED & VERIFIED WITH 100% SUCCESS!")
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(test_all_pairs())
