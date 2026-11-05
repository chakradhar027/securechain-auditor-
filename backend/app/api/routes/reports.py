import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

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
    res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = res.scalars().first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PDF audit report has not been generated for this scan or file is missing."
        )

    return FileResponse(
        path=scan.report_path,
        media_type="application/pdf",
        filename=os.path.basename(scan.report_path)
    )
