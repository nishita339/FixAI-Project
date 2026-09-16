import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, String

from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id = Column(String(36), ForeignKey("devices.id"), nullable=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    policy_decision = Column(String(20), nullable=False)  # "ALLOWED", "BLOCKED", "CONFIRMED"
    reason = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
