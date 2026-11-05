from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class ContractBase(BaseModel):
    name: str = Field(..., description="Contract Name")
    filename: str = Field(..., description="File name")
    compiler_version: Optional[str] = Field(default="^0.8.0")
    address: Optional[str] = Field(default=None)
    network: Optional[str] = Field(default="ethereum")

class ContractCreate(ContractBase):
    source_code: str
    file_path: str
    byte_size: int

class ContractResponse(ContractBase):
    id: int
    file_path: str
    byte_size: int
    source_code: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class OnChainFetchRequest(BaseModel):
    address: str = Field(..., description="Target contract address (0x...)")
    network: str = Field(default="ethereum", description="Blockchain network (ethereum, bsc, polygon, sepolia)")
