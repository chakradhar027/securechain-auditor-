from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_db
from app.models.contract import Contract
from app.schemas.contract import ContractResponse
from app.services.upload_service import UploadService

router = APIRouter(prefix="/upload", tags=["Upload"])

@router.post("/file", response_model=ContractResponse, status_code=status.HTTP_201_CREATED)
async def upload_contract_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a Solidity (.sol) smart contract file.
    """
    try:
        content_bytes = await file.read()
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to read uploaded file: {str(e)}"
        )

    success, message, meta = UploadService.save_contract_source(file.filename, content)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

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

    return contract

@router.post("/code", response_model=ContractResponse, status_code=status.HTTP_201_CREATED)
async def upload_contract_code(
    name: str = Form("SmartContract"),
    source_code: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Directly paste and register Solidity smart contract source code.
    """
    filename = f"{name}.sol" if not name.endswith(".sol") else name
    success, message, meta = UploadService.save_contract_source(filename, source_code)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

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

    return contract
