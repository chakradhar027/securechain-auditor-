from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.dependencies import get_db
from app.models.scan import Scan
from app.models.contract import Contract
from app.schemas.scan import ScanResponse, ScanSummary

router = APIRouter(prefix="/history", tags=["Scan History"])

@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve audit scan history ordered by recency."""
    query = (
        select(Scan)
        .options(selectinload(Scan.findings))
        .order_by(Scan.started_at.desc())
        .offset(skip)
        .limit(limit)
    )
    res = await db.execute(query)
    return res.scalars().all()

@router.get("/summary", response_model=ScanSummary)
async def get_dashboard_summary(db: AsyncSession = Depends(get_db)):
    """Aggregate statistics for executive security dashboard."""
    query = select(Scan).options(selectinload(Scan.findings)).order_by(Scan.started_at.desc())
    res = await db.execute(query)
    scans = res.scalars().all()

    total_scans = len(scans)
    critical_scans = sum(1 for s in scans if s.risk_level == "CRITICAL")
    high_scans = sum(1 for s in scans if s.risk_level == "HIGH")
    total_vulns = sum(s.total_vulnerabilities for s in scans)
    avg_risk = sum(s.risk_score for s in scans) / total_scans if total_scans > 0 else 0.0

    return ScanSummary(
        total_scans=total_scans,
        critical_scans=critical_scans,
        high_scans=high_scans,
        total_vulnerabilities=total_vulns,
        average_risk_score=round(avg_risk, 1),
        recent_scans=scans[:10]
    )

@router.get("/compare")
async def compare_scans(
    scan_id_a: int = Query(...),
    scan_id_b: int = Query(...),
    db: AsyncSession = Depends(get_db)
):
    """Compare security findings and risk scores between two scans/contract versions."""
    res_a = await db.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id_a))
    scan_a = res_a.scalars().first()
    res_b = await db.execute(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id_b))
    scan_b = res_b.scalars().first()

    if not scan_a or not scan_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or both scans not found.")

    diff = {
        "scan_a": {
            "id": scan_a.id,
            "risk_score": scan_a.risk_score,
            "risk_level": scan_a.risk_level,
            "vuln_count": scan_a.total_vulnerabilities
        },
        "scan_b": {
            "id": scan_b.id,
            "risk_score": scan_b.risk_score,
            "risk_level": scan_b.risk_level,
            "vuln_count": scan_b.total_vulnerabilities
        },
        "risk_delta": round(scan_b.risk_score - scan_a.risk_score, 1),
        "vuln_delta": scan_b.total_vulnerabilities - scan_a.total_vulnerabilities,
        "is_improved": scan_b.risk_score < scan_a.risk_score
    }
    return diff
