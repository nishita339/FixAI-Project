"""
FixAI Authentication & Email OTP Router
======================================
Provides complete REST endpoints for:
1. POST /api/v1/auth/send-otp
2. POST /api/v1/auth/verify-otp
3. POST /api/v1/auth/resend-otp
4. GET  /api/v1/auth/me
5. GET  /api/v1/auth/status/{email}
"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.services.otp_service import otp_manager

logger = logging.getLogger("fixai.auth")
router = APIRouter(prefix="/auth", tags=["authentication"])


# ── Pydantic Request / Response Schemas ───────────────────────────────────

class SendOtpRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered user email address")


class SendOtpResponse(BaseModel):
    success: bool
    message: str
    cooldown_seconds: int
    expires_in_seconds: int
    dev_otp: Optional[str] = None  # Provided in development for rapid verification


class VerifyOtpRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered user email address")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class VerifyOtpResponse(BaseModel):
    success: bool
    message: str
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class ResendOtpRequest(BaseModel):
    email: EmailStr = Field(..., description="Registered user email address")


def create_access_token(user_id: str, email: str, role: str) -> str:
    """Creates a signed HS256 JWT access token for authenticated users."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": "fixai-auth-service",
    }
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def get_current_user_from_jwt(
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Dependency that resolves user from Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token claims")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation error: {str(exc)}")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# ── Route Handlers ────────────────────────────────────────────────────────

@router.post("/send-otp", response_model=SendOtpResponse)
async def send_otp_endpoint(req: SendOtpRequest):
    """
    POST /api/v1/auth/send-otp
    Generates a secure 6-digit OTP and delivers it to the requested email.
    Enforces email validation, expiration limits (5 min), and resend cooldowns (45s).
    """
    email = str(req.email).strip().lower()
    success, message, cooldown, code = await otp_manager.request_otp(email)

    if not success:
        if "Please wait" in message:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )

    # OTP is strictly delivered to the user's email inbox; never leaked in API response
    return SendOtpResponse(
        success=True,
        message=message,
        cooldown_seconds=cooldown,
        expires_in_seconds=settings.OTP_EXPIRE_SECONDS,
        dev_otp=None,
    )


@router.post("/resend-otp", response_model=SendOtpResponse)
async def resend_otp_endpoint(req: ResendOtpRequest):
    """
    POST /api/v1/auth/resend-otp
    Resends an OTP to the given email if the cooldown timer has elapsed.
    """
    email = str(req.email).strip().lower()
    success, message, cooldown, code = await otp_manager.request_otp(email, is_resend=True)

    if not success:
        if "Please wait" in message:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=message,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )

    return SendOtpResponse(
        success=True,
        message="OTP sent successfully to your email.",
        cooldown_seconds=cooldown,
        expires_in_seconds=settings.OTP_EXPIRE_SECONDS,
        dev_otp=None,
    )


@router.post("/verify-otp", response_model=VerifyOtpResponse)
async def verify_otp_endpoint(req: VerifyOtpRequest, db: AsyncSession = Depends(get_db)):
    """
    POST /api/v1/auth/verify-otp
    Validates the 6-digit OTP code against the active record.
    Returns:
    - 400 'Invalid OTP' for incorrect codes
    - 400 'OTP expired' when 5-minute validity has elapsed
    - 429 'Too many failed attempts' on brute-force triggers
    - 200 with JWT access token on success
    """
    email = str(req.email).strip().lower()
    code = req.otp.strip()

    is_valid, status_msg = otp_manager.verify_otp(email, code)

    if not is_valid:
        if status_msg == "Invalid OTP":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
        elif status_msg == "OTP expired":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP expired")
        elif "Too many failed attempts" in status_msg:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=status_msg)
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=status_msg)

    # User verified! Look up or auto-provision in database
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()

    username = email.split("@")[0]
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            username=f"{username}_{uuid.uuid4().hex[:6]}",
            hashed_password="otp_verified_session",
            role="OPERATOR",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    access_token = create_access_token(user.id, user.email, user.role)

    return VerifyOtpResponse(
        success=True,
        message="User authenticated successfully.",
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user.id,
            "email": user.email,
            "name": username.capitalize(),
            "role": user.role,
        },
    )


@router.get("/status/{email}")
async def get_otp_status_endpoint(email: str):
    """
    GET /api/v1/auth/status/{email}
    Returns remaining expiry seconds and resend cooldown seconds for the active OTP.
    """
    return {
        "email": email,
        "remaining_expiry_seconds": otp_manager.get_remaining_expiry(email),
        "remaining_cooldown_seconds": otp_manager.get_remaining_cooldown(email),
    }


@router.get("/me")
async def get_current_user_endpoint(user: User = Depends(get_current_user_from_jwt)):
    """
    GET /api/v1/auth/me
    Returns current authenticated operator profile.
    """
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
    }


@router.get("/local-otp")
async def get_local_dev_otp(email: str):
    """
    GET /api/v1/auth/local-otp?email=...
    Local development helper: returns the active 6-digit OTP for instant 1-click verification
    when testing locally or if email delivery is delayed by spam filters.
    In production (FIXAI_ENV=production), returns 403 Forbidden for security.
    """
    is_prod = os.getenv("FIXAI_ENV", "development").lower() == "production"
    if is_prod:
        raise HTTPException(status_code=403, detail="local-otp is disabled in production environment")
    clean_email = email.strip().lower()
    code = otp_manager.get_active_otp(clean_email)
    if not code:
        raise HTTPException(status_code=404, detail="No active OTP found for this email")
    return {
        "email": clean_email,
        "otp": code,
        "remaining_expiry_seconds": otp_manager.get_remaining_expiry(clean_email),
    }


@router.get("/email-service-status")
async def get_email_service_status():
    """
    GET /api/v1/auth/email-service-status
    Returns the active email transmission channel:
    - REAL_RESEND_API: sending real emails to user inboxes via Resend
    - REAL_SMTP: sending real emails to user inboxes via SMTP relay
    - LOCAL_DEV_RELAY: local development relay
    """
    has_resend = bool(settings.RESEND_API_KEY)
    has_smtp = bool(settings.SMTP_HOST and (settings.SMTP_USER or settings.SMTP_PORT == 25 or settings.SMTP_PORT == 1025))

    if has_resend:
        mode = "REAL_RESEND_API"
        details = f"Active Resend API ({settings.SMTP_FROM_EMAIL or 'onboarding@resend.dev'})"
    elif has_smtp:
        mode = "REAL_SMTP"
        details = f"Active SMTP Relay ({settings.SMTP_HOST}:{settings.SMTP_PORT})"
    else:
        mode = "LOCAL_DEV_RELAY"
        details = "Terminal Console Relay (Set SMTP_HOST or RESEND_API_KEY in .env for external inbox delivery)"

    return {
        "delivery_mode": mode,
        "is_live_email": has_resend or has_smtp,
        "details": details,
        "smtp_host": settings.SMTP_HOST if has_smtp else None,
        "smtp_port": settings.SMTP_PORT if has_smtp else None,
        "smtp_from": settings.SMTP_FROM_EMAIL or None,
    }

