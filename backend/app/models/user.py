import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="SRE", nullable=False)  # "ADMIN", "SRE", "VIEWER"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    devices = relationship("Device", back_populates="owner", cascade="all, delete-orphan")
