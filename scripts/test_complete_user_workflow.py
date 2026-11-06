import asyncio
import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import init_db

async def run_complete_workflow():
    print("=" * 76)
    print("     SECURECHAIN AUDITOR - COMPLETE 12-STEP USER WORKFLOW AUDIT    ")
    print("=" * 76)

    await init_db()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Step 1: Open Dashboard
        print("\n[Step 1] Opening Dashboard & Querying System Health...")
        r_health = await client.get("/api/v1/health")
        assert r_health.status_code == 200
        r_summary = await client.get("/api/v1/history/summary")
        assert r_summary.status_code == 200
        summary = r_summary.json()
        print(f"  -> System Healthy: {r_health.json()}")
        print(f"  -> Dashboard Initial: Total Audits={summary['total_scans']}, Avg Risk={summary['average_risk_score']:.1f}/100")

        # Step 2: Upload Vulnerable Solidity Contract
        print("\n[Step 2] Uploading Vulnerable Contract: ReentrancyVulnerable.sol...")
        vuln_path = ROOT_DIR / "contracts" / "vulnerable" / "ReentrancyVulnerable.sol"
        with open(vuln_path, "rb") as f:
            r_up_vuln = await client.post("/api/v1/upload/file", files={"file": ("ReentrancyVulnerable.sol", f, "text/plain")})
        assert r_up_vuln.status_code == 201
        vuln_contract = r_up_vuln.json()
        vuln_cid = vuln_contract["id"]
        print(f"  -> Registered Contract ID: {vuln_cid} ({vuln_contract['name']})")

        # Step 3: Start Security Scan on Vulnerable Contract
        print("\n[Step 3] Starting Multi-Engine Security Scan on Vulnerable Contract...")
        r_scan_v = await client.post("/api/v1/scanner/start", json={
            "contract_id": vuln_cid,
            "engines": ["custom", "slither", "foundry"]
        })
        assert r_scan_v.status_code == 200
        scan_v = r_scan_v.json()
        scan_v_id = scan_v["id"]
        print(f"  -> Scan Dispatched! Scan ID: {scan_v_id}")

        # Step 4: Observe Scanning Progress
        print("\n[Step 4] Observing Scanning Progress & Status Tracker...")
        r_status = await client.get(f"/api/v1/scanner/status/{scan_v_id}")
        assert r_status.status_code == 200
        status_info = r_status.json()
        print(f"  -> Progress: {status_info.get('progress_percent', 100)}% | Status: {status_info.get('status')} | Message: {status_info.get('message', 'Completed')}")

        # Step 5: Review Vulnerability Findings
        print("\n[Step 5] Reviewing Vulnerability Findings...")
        findings_v = scan_v["findings"]
        print(f"  -> Total Findings Identified: {len(findings_v)}")
        for idx, f in enumerate(findings_v, 1):
            print(f"     {idx}. [{f['severity']}] {f['title']} (Category: {f['category']}, Engine: {f['engine']}, CVSS: {f['cvss_score']})")

        # Step 6: Inspect Code Evidence and Line Numbers
        print("\n[Step 6] Inspecting Code Evidence & Line Numbers...")
        reentrancy_finding = next((f for f in findings_v if f["category"] == "REENTRANCY"), findings_v[0])
        print(f"  -> Target Finding: {reentrancy_finding['title']}")
        print(f"  -> Location: Line {reentrancy_finding.get('line_start')}-{reentrancy_finding.get('line_end')}")
        print(f"  -> Code Evidence:\n{reentrancy_finding.get('code_snippet', '(none)')}")
        assert "Exploitability Assessment" in reentrancy_finding["description"]
        print("  -> Exploitability Context Verified: YES")

        # Step 7: Review Risk Score
        print("\n[Step 7] Reviewing Vulnerable Risk Score...")
        print(f"  -> Score: {scan_v['risk_score']}/100 | Level: {scan_v['risk_level']}")
        assert scan_v["risk_level"] in ["CRITICAL", "HIGH"]
        assert scan_v["risk_score"] >= 80.0

        # Step 8: Review Foundry Fuzz Results
        print("\n[Step 8] Reviewing Foundry Fuzz Invariant Results...")
        fuzz_v = scan_v["fuzz_details"]
        print(f"  -> Invariants Evaluated: {fuzz_v['total']} | Passed: {fuzz_v['passed']} | Failed: {fuzz_v['failed']}")
        failed_test = next((t for t in fuzz_v["tests"] if t["status"] == "FAILED"), None)
        if failed_test:
            print(f"  -> Invariant Violation Detected: {failed_test['name']}")
            print(f"  -> Counterexample Trace: {failed_test.get('counterexample')}")

        # Step 9: Download PDF Audit Report
        print("\n[Step 9] Downloading PDF Security Audit Report...")
        r_pdf_v = await client.get(f"/api/v1/reports/download/{scan_v_id}")
        assert r_pdf_v.status_code == 200
        assert r_pdf_v.headers["content-type"] == "application/pdf"
        assert r_pdf_v.content.startswith(b"%PDF")
        print(f"  -> Download Successful! PDF Size: {len(r_pdf_v.content)} bytes, Magic Header: %PDF")

        # Step 10: Open Scan History
        print("\n[Step 10] Querying Historical Audit Registry...")
        r_history = await client.get("/api/v1/history/")
        assert r_history.status_code == 200
        history_scans = r_history.json()
        assert len(history_scans) > 0
        latest_scan = history_scans[0]
        print(f"  -> Latest Scan in History: SCA-{latest_scan['id']:06d} (Risk: {latest_scan['risk_score']}/100 {latest_scan['risk_level']})")

        # Step 11: Repeat Using Fixed Contract Version
        print("\n[Step 11] Uploading and Scanning Patched Version: ReentrancyFixed.sol...")
        fixed_path = ROOT_DIR / "contracts" / "secure" / "ReentrancyFixed.sol"
        with open(fixed_path, "rb") as f:
            r_up_fixed = await client.post("/api/v1/upload/file", files={"file": ("ReentrancyFixed.sol", f, "text/plain")})
        assert r_up_fixed.status_code == 201
        fixed_cid = r_up_fixed.json()["id"]

        r_scan_f = await client.post("/api/v1/scanner/start", json={
            "contract_id": fixed_cid,
            "engines": ["custom", "slither", "foundry"]
        })
        assert r_scan_f.status_code == 200
        scan_f = r_scan_f.json()
        scan_f_id = scan_f["id"]

        print(f"  -> Fixed Scan ID: {scan_f_id}")
        print(f"  -> Score: {scan_f['risk_score']}/100 | Level: {scan_f['risk_level']}")
        print(f"  -> Critical Issues: {scan_f['critical_count']} | High: {scan_f['high_count']} | Medium: {scan_f['medium_count']} | Low: {scan_f['low_count']}")
        print(f"  -> Informational Code-Hygiene Advisories: {scan_f['info_count']}")
        print(f"  -> Foundry Fuzz Invariants: {scan_f['fuzz_passed']}/{scan_f['fuzz_total']} Passed")
        assert scan_f["risk_score"] == 0.0
        assert scan_f["risk_level"] == "SECURE"

        r_pdf_f = await client.get(f"/api/v1/reports/download/{scan_f_id}")
        assert r_pdf_f.status_code == 200
        assert r_pdf_f.content.startswith(b"%PDF")
        print(f"  -> Fixed Audit PDF Downloaded: {len(r_pdf_f.content)} bytes")

        # Step 12: Compare Both Audit Results
        print("\n[Step 12] Performing Version Comparison (Audit A vs Audit B)...")
        r_diff = await client.get(f"/api/v1/history/compare?scan_id_a={scan_v_id}&scan_id_b={scan_f_id}")
        assert r_diff.status_code == 200
        diff = r_diff.json()
        print(f"  -> Security Improved: {diff['is_improved']}")
        print(f"  -> Risk Score Delta: {diff['risk_delta']} pts (from {diff['scan_a']['risk_score']} to {diff['scan_b']['risk_score']})")
        print(f"  -> Vulnerabilities Delta: {diff['vuln_delta']} issues (from {diff['scan_a']['vuln_count']} to {diff['scan_b']['vuln_count']})")
        assert diff["is_improved"] is True
        assert diff["risk_delta"] < 0

    print("\n" * 1 + "=" * 76)
    print("  SUCCESS: ALL 12 WORKFLOW STAGES EXECUTED AND VALIDATED FLAWLESSLY! ")
    print("=" * 76)

if __name__ == "__main__":
    asyncio.run(run_complete_workflow())
