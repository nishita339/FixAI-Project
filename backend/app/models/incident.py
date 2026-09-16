import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Float, ForeignKey, JSON, String
from sqlalchemy.orm import relationship

from app.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=False, index=True)
    status = Column(String(30), default="OPEN", nullable=False, index=True)  # OPEN, PENDING_APPROVAL, EXECUTING, RESOLVED, FAILED
    risk = Column(String(20), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH
    primary_cause = Column(String(100), nullable=False)
    explanation = Column(String(500), nullable=False)
    failure_probability = Column(Float, default=0.0, nullable=False)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    shap = Column(JSON, nullable=True)
    playbook_id = Column(String(50), ForeignKey("playbooks.id"), nullable=True)
    scenario_key = Column(String(100), nullable=True, index=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    device = relationship("Device", back_populates="incidents")
    playbook = relationship("Playbook", back_populates="incidents")
