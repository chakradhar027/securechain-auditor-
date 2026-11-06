from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from app.database.base import Base

class Contract(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    source_code = Column(Text, nullable=False)
    byte_size = Column(Integer, nullable=False, default=0)
    compiler_version = Column(String(64), nullable=True, default="^0.8.0")
    address = Column(String(64), nullable=True, index=True)
    network = Column(String(32), nullable=True, default="ethereum")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scans = relationship("Scan", back_populates="contract", cascade="all, delete-orphan")

