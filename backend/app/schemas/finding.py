from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

class FindingBase(BaseModel):
    title: str
    category: str = Field(..., description="REENTRANCY, ACCESS_CONTROL, UNCHECKED_CALL, ORACLE_MANIPULATION, OTHER")
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    confidence: str = Field(default="MEDIUM", description="HIGH, MEDIUM, LOW")
    engine: str = Field(..., description="slither, mythril, custom, foundry, consolidated")
    description: str
    recommendation: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    cvss_score: Optional[float] = 0.0

class FindingCreate(FindingBase):
    scan_id: int

class FindingResponse(FindingBase):
    id: int
    scan_id: int

    model_config = ConfigDict(from_attributes=True)
