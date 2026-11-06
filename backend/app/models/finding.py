from sqlalchemy import Column, Integer, String, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database.base import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False) # REENTRANCY, ACCESS_CONTROL, UNCHECKED_CALL, ORACLE_MANIPULATION, OTHER
    severity = Column(String(32), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    confidence = Column(String(32), default="MEDIUM", nullable=False) # HIGH, MEDIUM, LOW
    engine = Column(String(64), nullable=False) # slither, mythril, custom, foundry, consolidated
    
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    
    file_path = Column(String(512), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    
    cwe_id = Column(String(32), nullable=True) # e.g. CWE-841
    swc_id = Column(String(32), nullable=True) # e.g. SWC-107
    cvss_score = Column(Float, nullable=True, default=0.0)

    scan = relationship("Scan", back_populates="findings")

