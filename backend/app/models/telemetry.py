from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class TelemetrySample(Base):
    __tablename__ = "telemetry_samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    cpu = Column(Float, nullable=False)
    ram = Column(Float, nullable=False)
    latency = Column(Float, nullable=False)
    error_rate = Column(Float, nullable=False)
    disk = Column(Float, nullable=False)

    device = relationship("Device", back_populates="telemetry_samples")
