from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.database import Base


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(String(50), primary_key=True)  # e.g., "flush_cache", "restart_container"
    name = Column(String(100), nullable=False)
    risk_tier = Column(String(20), nullable=False)  # "LOW", "MEDIUM", "HIGH"
    allowed_params = Column(JSON, default=dict, nullable=False)
    description = Column(String(255), nullable=True)
    verification_window_seconds = Column(Integer, default=15, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    incidents = relationship("Incident", back_populates="playbook")
