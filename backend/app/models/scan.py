from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.base import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    contract_id = Column(Integer, ForeignKey("contracts.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="PENDING", nullable=False) # PENDING, RUNNING, COMPLETED, FAILED
    engines_used = Column(JSON, default=list, nullable=False) # ["slither", "mythril", "custom", "foundry"]
    
    # Risk Metrics
    risk_score = Column(Float, default=0.0, nullable=False) # 0.0 - 100.0
    risk_level = Column(String(32), default="SECURE", nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, SECURE
    
    # Counts
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    info_count = Column(Integer, default=0, nullable=False)
    
    # Fuzz testing summary
    fuzz_passed = Column(Integer, default=0, nullable=False)
    fuzz_total = Column(Integer, default=0, nullable=False)
    fuzz_details = Column(JSON, default=dict, nullable=False)
    
    # Artifacts
    report_path = Column(String(512), nullable=True)
    error_message = Column(Text, nullable=True)
    
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)

    contract = relationship("Contract", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
