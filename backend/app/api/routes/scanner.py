from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from app.dependencies import get_db
from app.models.scan import Scan
from app.schemas.scan import ScanCreateRequest, ScanResponse
from app.services.scan_service import ScanService
from app.services.job_service import job_service

router = APIRouter(prefix="/scanner", tags=["Scanner"])
scan_service = ScanService()

@router.post("/start", response_model=ScanResponse, status_code=status.HTTP_200_OK)
async def start_scan(
    req: ScanCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger multi-engine vulnerability scan for a registered contract.
    """
    try:
        scan = await scan_service.execute_scan(
            db=db,
            contract_id=req.contract_id,
            engines=req.engines
        )
        # Load findings for response
        res = await db.execute(
            select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan.id)
        )
        return res.scalars().first()
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Scan error: {str(e)}")

@router.get("/status/{scan_id}")
async def get_scan_status(scan_id: int):
    """
    Query real-time scan job progress and stage message.
    """
    status_info = job_service.get_status(scan_id)
    if not status_info:
        return {"scan_id": scan_id, "status": "COMPLETED", "progress_percent": 100, "message": "Job finished"}
    return status_info

@router.get("/engines")
async def list_available_engines():
    """
    Returns available security engines and their capabilities.
    """
    return [
        {
            "id": "custom",
            "name": "SecureChain Custom Detection Engine",
            "type": "Custom Static Rule & Semantic Analysis",
            "capabilities": ["Reentrancy (CEI)", "Access Control & tx.origin", "Unchecked Calls", "Oracle Manipulation & Spot Reserves"],
            "status": "READY"
        },
        {
            "id": "slither",
            "name": "Slither Static Analyzer",
            "type": "Static Analysis Framework",
            "capabilities": ["Delegatecall hijack", "Floating pragma", "Shadowed state", "Assembly inspection"],
            "status": "READY"
        },
        {
            "id": "mythril",
            "name": "Mythril Symbolic Engine",
            "type": "EVM Symbolic Execution",
            "capabilities": ["Execution path constraint solving", "Timestamp dependence", "Front-running", "Weak PRNG"],
            "status": "READY"
        },
        {
            "id": "foundry",
            "name": "Foundry Fuzz Testing Suite",
            "type": "Dynamic Property Invariant Fuzzing",
            "capabilities": ["Automated randomized fuzz inputs", "Solvency invariants", "Reentrancy depth verification"],
            "status": "READY"
        }
    ]
