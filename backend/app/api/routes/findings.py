from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.dependencies import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    severity: Optional[str] = Query(None, description="Filter by CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"),
    category: Optional[str] = Query(None, description="Filter by REENTRANCY, ACCESS_CONTROL, UNCHECKED_CALL, etc."),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve security findings with optional filters."""
    query = select(Finding)
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity.upper())
    if category:
        query = query.where(Finding.category == category.upper())

    query = query.order_by(Finding.id.asc()).offset(skip).limit(limit)
    res = await db.execute(query)
    return res.scalars().all()

