import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, JSON, String
from sqlalchemy.orm import relationship

from app.database import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False, index=True)
    api_key = Column(String(255), nullable=True, index=True)
    api_key_hash = Column(String(255), nullable=True, index=True)
    status = Column(String(20), default="HEALTHY", nullable=False)  # HEALTHY, DEGRADED, CRITICAL
    health_score = Column(Float, default=100.0, nullable=False)
    failure_risk = Column(Float, default=0.0, nullable=False)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    agent_online = Column(Boolean, default=False, nullable=False)
    specs = Column(JSON, nullable=True)
    last_heartbeat = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    owner = relationship("User", back_populates="devices")
    incidents = relationship("Incident", back_populates="device", cascade="all, delete-orphan")
    telemetry_samples = relationship("TelemetrySample", back_populates="device", cascade="all, delete-orphan")
