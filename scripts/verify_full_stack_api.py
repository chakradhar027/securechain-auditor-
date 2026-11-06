import asyncio
import os
import sys

# Ensure backend in path
sys.path.insert(0, os.path.abspath("backend"))

from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database.connection import init_db

async def test_full_application():
    print("==================================================================")
    print("     SECURECHAIN AUDITOR - COMPLETE APPLICATION AUDIT TEST       ")
    print("==================================================================")

    await init_db()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Health Endpoint
        r_health = await client.get("/api/v1/health")
        assert r_health.status_code == 200, f"Health failed: {r_health.text}"
        print("  [1/9] Health Check Endpoint: OK (200)")

        # 2. Engines Endpoint
        r_engines = await client.get("/api/v1/scanner/engines")
        assert r_engines.status_code == 200
        engines_data = r_engines.json()
        assert len(engines_data) == 4
        print(f"  [2/9] Engines Endpoint: OK (200) - Available engines: {[e['id'] for e in engines_data]}")

        # 3. File Upload
        vuln_sol = "contracts/vulnerable/ReentrancyVulnerable.sol"
        with open(vuln_sol, "rb") as f:
            files = {"file": ("ReentrancyVulnerable.sol", f, "text/plain")}
            r_upload = await client.post("/api/v1/upload/file", files=files)
        assert r_upload.status_code == 201, f"Upload failed: {r_upload.text}"
        contract = r_upload.json()
        contract_id = contract["id"]
        print(f"  [3/9] Contract File Upload: OK (201) - Registered ID: {contract_id} ({contract['name']})")

        # 4. Code Paste Upload
        r_paste = await client.post(
            "/api/v1/upload/code",
            data={"name": "InlineVault", "source_code": "contract InlineVault { function drain() public {} }"}
        )
        assert r_paste.status_code == 201
        print("  [4/9] Direct Code Paste Upload: OK (201)")

        # 5. Execute Multi-Engine Scan
        scan_payload = {
            "contract_id": contract_id,
            "engines": ["custom", "slither", "foundry"]
        }
        r_scan = await client.post("/api/v1/scanner/start", json=scan_payload)
        assert r_scan.status_code == 200, f"Scan failed: {r_scan.text}"
        scan_res = r_scan.json()
        scan_id = scan_res["id"]
        print(f"  [5/9] Multi-Engine Scan Start: OK (200) - Scan ID: {scan_id}")
        print(f"        Risk: {scan_res['risk_score']}/100 ({scan_res['risk_level']}), Vulns: {scan_res['total_vulnerabilities']}")
        print(f"        Fuzz Invariants: {scan_res['fuzz_passed']}/{scan_res['fuzz_total']} passed")

        # 6. Scan Progress Status
        r_status = await client.get(f"/api/v1/scanner/status/{scan_id}")
        assert r_status.status_code == 200
        print(f"  [6/9] Scan Job Status: OK (200) - Status: {r_status.json().get('status')}")

        # 7. Scan History Retrieval
        r_history = await client.get("/api/v1/history/")
        assert r_history.status_code == 200
        history_items = r_history.json()
        assert len(history_items) > 0
        assert any(item["id"] == scan_id for item in history_items)
        print(f"  [7/9] Scan History Retrieval: OK (200) - Retrieved {len(history_items)} recorded audits")

        # 8. Findings & Code Evidence
        r_findings = await client.get(f"/api/v1/findings/?scan_id={scan_id}")
        assert r_findings.status_code == 200, f"Findings failed: {r_findings.text}"
        findings_data = r_findings.json()
        assert len(findings_data) > 0
        first_finding = findings_data[0]
        assert "code_snippet" in first_finding
        assert "Exploitability Assessment" in first_finding["description"]
        print(f"  [8/9] Findings & Code Evidence: OK (200) - {len(findings_data)} findings with exploitability context")

        # 9. PDF Report Download
        r_pdf = await client.get(f"/api/v1/reports/download/{scan_id}")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert "attachment" in r_pdf.headers["content-disposition"]
        pdf_bytes = r_pdf.content
        assert len(pdf_bytes) > 2000
        assert pdf_bytes.startswith(b"%PDF")
        print(f"  [9/9] PDF Report Download: OK (200) - Valid binary PDF header (%PDF), Size: {len(pdf_bytes)} bytes")

    print("\n==================================================================")
    print("  ALL 9 API & PIPELINE WORKFLOW TESTS PASSED CLEANLY!             ")
    print("==================================================================")

if __name__ == "__main__":
    asyncio.run(test_full_application())
