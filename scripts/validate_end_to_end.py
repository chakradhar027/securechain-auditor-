import asyncio
import os
import sys

# Ensure backend is in python path
sys.path.insert(0, os.path.abspath("backend"))

from app.database.connection import init_db, AsyncSessionLocal
from app.services.upload_service import UploadService
from app.services.scan_service import ScanService
from app.reports.pdf_generator import PDFGenerator
from app.models.contract import Contract
from app.models.scan import Scan
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

async def main():
    print("=" * 60)
    print("SECURECHAIN AUDITOR - COMPLETE END-TO-END VALIDATION")
    print("=" * 60)

    await init_db()
    scan_service = ScanService()

    contracts_to_test = [
        ("Reentrancy Vulnerable", "contracts/vulnerable/ReentrancyVulnerable.sol", True),
        ("Reentrancy Fixed (Secure)", "contracts/secure/ReentrancyFixed.sol", False),
        ("Access Control Vulnerable", "contracts/vulnerable/AccessControlVulnerable.sol", True),
        ("Access Control Fixed (Secure)", "contracts/secure/AccessControlFixed.sol", False),
        ("Unchecked Call Vulnerable", "contracts/vulnerable/UncheckedCallVulnerable.sol", True),
        ("Oracle Vulnerable", "contracts/vulnerable/OracleVulnerable.sol", True),
    ]

    for label, path, is_vulnerable in contracts_to_test:
        print(f"\n---> Testing Contract: {label} ({path})")
        with open(path, "r") as f:
            code = f.read()

        filename = os.path.basename(path)

        async with AsyncSessionLocal() as db:
            # 1. Register Contract using UploadService
            success, msg, meta = UploadService.save_contract_source(filename, code)
            assert success, f"Upload validation failed: {msg}"

            contract = Contract(
                name=meta["name"],
                filename=meta["filename"],
                file_path=meta["file_path"],
                source_code=meta["source_code"],
                byte_size=meta["byte_size"],
                compiler_version=meta["compiler_version"]
            )
            db.add(contract)
            await db.commit()
            await db.refresh(contract)
            print(f"  [+] Contract registered with ID: {contract.id} ({contract.name})")

            # 2. Run Scan
            engines = ["custom", "slither", "foundry"]
            scan = await scan_service.execute_scan(db=db, contract_id=contract.id, engines=engines)

            # 3. Reload Scan with findings
            res = await db.execute(
                select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan.id)
            )
            full_scan = res.scalars().first()

            print(f"  [+] Scan ID: {full_scan.id}")
            print(f"  [+] Risk Score: {full_scan.risk_score:.1f}/100 ({full_scan.risk_level})")
            print(f"  [+] Total Vulnerabilities: {full_scan.total_vulnerabilities}")
            print(f"  [+] Severity counts: Critical={full_scan.critical_count}, High={full_scan.high_count}, Med={full_scan.medium_count}, Low={full_scan.low_count}")
            failed_fuzz = full_scan.fuzz_total - full_scan.fuzz_passed
            print(f"  [+] Fuzzing tests: {full_scan.fuzz_passed}/{full_scan.fuzz_total} passed (failed: {failed_fuzz})")

            # Check engines contributing
            engines_seen = {f.engine for f in full_scan.findings}
            print(f"  [+] Contributing engines: {engines_seen or 'None (Clean)'}")

            for f in full_scan.findings[:3]:
                print(f"      - [{f.severity}] {f.title} (Engine: {f.engine}, Category: {f.category})")

            # Validate expectation
            if is_vulnerable:
                assert full_scan.total_vulnerabilities > 0, f"Expected vulnerabilities in {label}"
                print(f"  [OK] Successfully detected vulnerabilities in {label}")
            else:
                assert full_scan.critical_count == 0 and full_scan.high_count == 0, f"Unexpected high/critical in secure {label}"
                print(f"  [OK] Secure contract {label} passed without high/critical flags")

            # 4. Verify Generated PDF Report
            assert full_scan.report_path and os.path.exists(full_scan.report_path), f"Report path missing for {label}"
            pdf_size = os.path.getsize(full_scan.report_path)
            assert pdf_size > 1000, f"PDF report too small ({pdf_size} bytes) for {label}"
            print(f"  [+] PDF Audit Report generated automatically: {full_scan.report_path} ({pdf_size} bytes)")

    print("\n" + "=" * 60)
    print("ALL 6 BENCHMARK CONTRACTS TESTED & VALIDATED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
