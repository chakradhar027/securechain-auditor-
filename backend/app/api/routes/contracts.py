from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.dependencies import get_db
from app.models.contract import Contract
from app.schemas.contract import ContractResponse, OnChainFetchRequest
from app.services.explorer_service import ExplorerService
from app.services.upload_service import UploadService

router = APIRouter(prefix="/contracts", tags=["Contracts"])

@router.get("/", response_model=List[ContractResponse])
async def list_contracts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve all submitted smart contracts."""
    query = select(Contract).order_by(Contract.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/{contract_id}", response_model=ContractResponse)
async def get_contract(
    contract_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get single contract source and metadata."""
    result = await db.execute(select(Contract).where(Contract.id == contract_id))
    contract = result.scalars().first()
    if not contract:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contract not found")
    return contract

@router.post("/on-chain", response_model=ContractResponse, status_code=status.HTTP_201_CREATED)
async def fetch_on_chain_contract(
    req: OnChainFetchRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve verified Solidity source code directly from blockchain explorer (Etherscan, etc.).
    """
    ok, msg, data = await ExplorerService.fetch_verified_contract(req.address, req.network)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    # Save to uploads
    filename = f"{data['name']}_{req.address[:8]}.sol"
    save_ok, save_msg, meta = UploadService.save_contract_source(filename, data["source_code"])
    if not save_ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=save_msg)

    contract = Contract(
        name=data["name"],
        filename=filename,
        file_path=meta["file_path"],
        source_code=data["source_code"],
        byte_size=meta["byte_size"],
        compiler_version=data["compiler_version"],
        address=req.address,
        network=req.network
    )
    db.add(contract)
    await db.commit()
    await db.refresh(contract)

    return contract
