from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.finding import FindingResponse

class ScanCreateRequest(BaseModel):
    contract_id: int
    engines: List[str] = Field(
        default=["custom", "slither", "mythril", "foundry"],
        description="Engines to run: custom, slither, mythril, foundry"
    )

class ScanResponse(BaseModel):
    id: int
    contract_id: int
    contract_name: Optional[str] = None
    status: str
    engines_used: List[str]
    engines_requested: Optional[List[str]] = None
    risk_score: float
    risk_level: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    fuzz_passed: int
    fuzz_total: int
    fuzz_details: Dict[str, Any]
    report_path: Optional[str] = None
    error_message: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: Optional[List[FindingResponse]] = []

    model_config = ConfigDict(from_attributes=True)

class ScanSummary(BaseModel):
    total_scans: int
    critical_scans: int
    high_scans: int
    total_vulnerabilities: int
    average_risk_score: float
    recent_scans: List[ScanResponse]
