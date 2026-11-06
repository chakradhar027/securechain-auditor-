import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from sqlalchemy.orm import selectinload

from app.dependencies import get_db
from app.models.scan import Scan

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/download/{scan_id}")
async def download_pdf_report(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Download the generated PDF security audit report.
    """
    res = await db.execute(
        select(Scan)
        .options(selectinload(Scan.contract), selectinload(Scan.findings))
        .where(Scan.id == scan_id)
    )
    scan = res.scalars().first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    report_file_path = scan.report_path
    if report_file_path and not os.path.isabs(report_file_path):
        from app.config import settings
        canonical_path = os.path.join(settings.REPORTS_DIR, os.path.basename(report_file_path))
        if os.path.exists(canonical_path):
            report_file_path = canonical_path

    if not report_file_path or not os.path.exists(report_file_path):
        from app.reports.pdf_generator import PDFGenerator
        from app.utils.file_validator import extract_contract_name

        contract = scan.contract
        resolved_name = contract.name if contract else f"Contract #{scan.contract_id}"
        filename = contract.filename if contract else f"Contract_{scan.contract_id}.sol"
        stem = os.path.splitext(os.path.basename(filename))[0]

        if not resolved_name or resolved_name.lower() in ["adopting", "smartcontract", "unknown"]:
            if contract and contract.source_code:
                resolved_name = extract_contract_name(contract.source_code, default=stem or "Contract", filename=filename)
            elif stem:
                resolved_name = stem

        contract_dict = {
            "name": resolved_name,
            "filename": filename,
            "compiler_version": contract.compiler_version if contract else "^0.8.0",
            "address": contract.address if contract else None,
            "network": contract.network if contract else "ethereum",
            "source_code": contract.source_code if contract else ""
        }
        scan_dict = {
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "engines_used": scan.engines_used or ["custom"],
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "info_count": scan.info_count,
            "fuzz_passed": scan.fuzz_passed,
            "fuzz_total": scan.fuzz_total,
        }
        findings_data = [
            {
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "engine": f.engine,
                "description": f.description,
                "recommendation": f.recommendation,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "code_snippet": f.code_snippet,
                "cwe_id": f.cwe_id,
                "swc_id": f.swc_id,
                "cvss_score": f.cvss_score
            }
            for f in (scan.findings or [])
        ]
        report_path = PDFGenerator.generate_report(
            scan_id=scan.id,
            contract_data=contract_dict,
            scan_data=scan_dict,
            findings=findings_data,
            fuzz_details=scan.fuzz_details or {}
        )
        scan.report_path = report_path
        report_file_path = report_path
        await db.commit()

    filename = os.path.basename(report_file_path)
    return FileResponse(
        path=report_file_path,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
