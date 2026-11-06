import os
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.models.contract import Contract
from app.models.scan import Scan
from app.models.finding import Finding
from app.scanners.scanner_manager import ScannerManager
from app.analysis.correlation import FindingCorrelator
from app.analysis.risk_engine import RiskEngine
from app.analysis.recommendations import get_recommendation_for_finding, inspect_call_safety
from app.utils.file_validator import extract_contract_name
from app.reports.pdf_generator import PDFGenerator
from app.services.job_service import job_service
from app.utils.logger import logger

class ScanService:
    def __init__(self):
        self.scanner_manager = ScannerManager()

    async def execute_scan(
        self,
        db: AsyncSession,
        contract_id: int,
        engines: List[str]
    ) -> Scan:
        """
        Orchestrates full multi-engine audit pipeline.
        """
        # 1. Fetch Contract
        result = await db.execute(select(Contract).where(Contract.id == contract_id))
        contract = result.scalars().first()
        if not contract:
            raise ValueError(f"Contract with id {contract_id} not found.")

        # 2. Create Scan record
        scan = Scan(
            contract_id=contract.id,
            status="RUNNING",
            engines_requested=engines,
            engines_used=engines,
            started_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        job_service.start_job(scan.id)

        try:
            # 3. Execute scanners
            job_service.update_progress(scan.id, 25, "Running multi-engine security scanners...")
            actual_file_path = contract.file_path
            if not os.path.isabs(actual_file_path):
                canonical_fp = os.path.join(settings.UPLOADS_DIR, os.path.basename(actual_file_path))
                if os.path.exists(canonical_fp):
                    actual_file_path = canonical_fp

            raw_findings, fuzz_meta = await self.scanner_manager.run_scanners(
                file_path=actual_file_path,
                source_code=contract.source_code,
                enabled_engines=engines
            )
            executed_engines = getattr(self.scanner_manager, "last_executed_engines", None)
            if not executed_engines:
                from app.utils.process_runner import is_mythril_operational
                executed_engines = [e for e in engines if e != "mythril" or is_mythril_operational()]

            # 4. Correlation & Deduplication
            job_service.update_progress(scan.id, 60, "Correlating multi-engine findings and deduplicating...")
            consolidated = FindingCorrelator.correlate(raw_findings)

            # 5. Enrich with actionable recommendations and context-aware inspection
            source_code = contract.source_code or ""
            for f in consolidated:
                f["recommendation"] = get_recommendation_for_finding(
                    f,
                    source_code=source_code
                )
                # For low-level calls, if verified safe, explicitly document static inspection verification
                if f.get("severity") == "INFORMATIONAL" and ("low level call" in f.get("title", "").lower() or "low-level-call" in f.get("title", "").lower()):
                    safety = inspect_call_safety(source_code, f.get("line_start"), f.get("code_snippet", ""))
                    if safety["is_safe"] and "Static Inspection Verification" not in f["description"]:
                        f["description"] += (
                            "\n\n[Static Inspection Verification]: Verified safe implementation. The return boolean "
                            "status is explicitly checked with require(), and reentrancy protection (nonReentrant modifier "
                            "and Checks-Effects-Interactions pattern) is actively enforced. This finding is informational "
                            "advisory guidance and does not represent an exploitable vulnerability."
                        )

            # 6. Calculate overall Risk Metrics
            job_service.update_progress(scan.id, 75, "Evaluating risk metrics and vulnerability density...")
            risk_score, risk_level, severity_counts = RiskEngine.calculate_risk(consolidated, fuzz_meta)

            # 7. Generate PDF Audit Report
            job_service.update_progress(scan.id, 85, "Compiling PDF audit report with ReportLab...")
            
            # Resolve accurate contract name, falling back to uploaded filename stem without .sol
            resolved_contract_name = contract.name
            filename_stem = os.path.splitext(os.path.basename(contract.filename or ""))[0]
            if not resolved_contract_name or resolved_contract_name.lower() in ["adopting", "smartcontract", "unknown"]:
                if contract.source_code:
                    resolved_contract_name = extract_contract_name(contract.source_code, default=filename_stem or "Contract", filename=contract.filename)
                elif filename_stem:
                    resolved_contract_name = filename_stem

            contract_dict = {
                "name": resolved_contract_name,
                "filename": contract.filename,
                "compiler_version": contract.compiler_version,
                "address": contract.address,
                "network": contract.network,
                "source_code": contract.source_code
            }
            scan_dict = {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "engines_used": executed_engines,
                "engines_requested": engines,
                "total_vulnerabilities": len(consolidated),
                "critical_count": severity_counts["CRITICAL"],
                "high_count": severity_counts["HIGH"],
                "medium_count": severity_counts["MEDIUM"],
                "low_count": severity_counts["LOW"],
                "info_count": severity_counts["INFORMATIONAL"],
                "fuzz_passed": fuzz_meta.get("passed", 0),
                "fuzz_total": fuzz_meta.get("total", 0),
            }

            report_file_path = PDFGenerator.generate_report(
                scan_id=scan.id,
                contract_data=contract_dict,
                scan_data=scan_dict,
                findings=consolidated,
                fuzz_details=fuzz_meta
            )

            # 8. Persist Findings to Database
            for f_data in consolidated:
                finding = Finding(
                    scan_id=scan.id,
                    title=f_data["title"],
                    category=f_data["category"],
                    severity=f_data["severity"],
                    confidence=f_data.get("confidence", "MEDIUM"),
                    engine=f_data["engine"],
                    description=f_data["description"],
                    recommendation=f_data["recommendation"],
                    file_path=contract.file_path,
                    line_start=f_data.get("line_start"),
                    line_end=f_data.get("line_end"),
                    code_snippet=f_data.get("code_snippet"),
                    cwe_id=f_data.get("cwe_id"),
                    swc_id=f_data.get("swc_id"),
                    cvss_score=f_data.get("cvss_score", 0.0)
                )
                db.add(finding)

            # 9. Update Scan record
            scan.status = "COMPLETED"
            scan.engines_used = executed_engines
            scan.engines_requested = engines
            scan.risk_score = risk_score
            scan.risk_level = risk_level
            scan.total_vulnerabilities = len(consolidated)
            scan.critical_count = severity_counts["CRITICAL"]
            scan.high_count = severity_counts["HIGH"]
            scan.medium_count = severity_counts["MEDIUM"]
            scan.low_count = severity_counts["LOW"]
            scan.info_count = severity_counts["INFORMATIONAL"]
            scan.fuzz_passed = fuzz_meta.get("passed", 0)
            scan.fuzz_total = fuzz_meta.get("total", 0)
            scan.fuzz_details = fuzz_meta
            scan.report_path = report_file_path
            scan.completed_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(scan)

            job_service.complete_job(scan.id)
            logger.info(f"Scan {scan.id} completed. Risk Score: {risk_score} ({risk_level}).")
            return scan

        except Exception as e:
            logger.error(f"Scan {scan.id} execution failed: {e}", exc_info=True)
            scan.status = "FAILED"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            job_service.fail_job(scan.id, str(e))
            raise e

