"""
FixAI OTP Lifecycle & Security Service
======================================
Manages cryptographically secure 6-digit OTP generation, expiration tracking,
resend cooldowns, email validation, and brute-force protection.
"""

import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from app.config import settings
from app.services.email_service import send_otp_email

logger = logging.getLogger("fixai.otp")

# RFC 5322 simplified email regex pattern
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


@dataclass
class OtpEntry:
    code: str
    created_at: float
    expires_at: float
    resend_available_at: float
    attempts: int = 0
    max_attempts: int = 5


class OtpManager:
    """Thread-safe, in-memory OTP cache with automatic expiry and rate limiting."""

    def __init__(self):
        self._store: Dict[str, OtpEntry] = {}

    def is_valid_email(self, email: str) -> bool:
        """Validates that the provided email matches standard email formats."""
        if not email or len(email) > 255:
            return False
        return bool(EMAIL_REGEX.match(email.strip()))

    def generate_code(self) -> str:
        """Generates a cryptographically secure 6-digit integer formatted as string."""
        # Using secrets ensures unpredictable, cryptographically random generation (100000 - 999999)
        return f"{secrets.randbelow(900000) + 100000:06d}"

    async def request_otp(
        self,
        raw_email: str,
        is_resend: bool = False,
    ) -> Tuple[bool, str, int, Optional[str]]:
        """
        Processes an OTP request.
        
        Returns:
            (success: bool, message: str, cooldown_remaining: int, otp_code_or_none)
        """
        email = raw_email.strip().lower()

        # 1. Validate email format
        if not self.is_valid_email(email):
            return False, "Invalid email address format.", 0, None

        now = time.time()
        existing = self._store.get(email)

        # 2. Check Resend Cooldown
        if existing and now < existing.resend_available_at:
            remaining = int(existing.resend_available_at - now)
            return (
                False,
                f"Please wait {remaining} seconds before requesting a new OTP.",
                remaining,
                None,
            )

        # 3. Generate secure 6-digit code
        code = self.generate_code()
        expire_seconds = settings.OTP_EXPIRE_SECONDS  # 300 seconds (5 minutes)
        cooldown_seconds = settings.OTP_RESEND_COOLDOWN_SECONDS  # 45 seconds

        # 4. Dispatch email via EmailService
        expire_minutes = max(1, expire_seconds // 60)
        try:
            sent_ok, send_msg = await send_otp_email(email, code, expire_minutes=expire_minutes)
            if not sent_ok:
                logger.error("Failed to send OTP to %s: %s", email, send_msg)
                return False, "Unable to send OTP. Please try again.", 0, None
        except Exception as exc:
            logger.error("Unexpected exception delivering OTP to %s: %s", email, exc)
            return False, "Unable to send OTP. Please try again.", 0, None

        # 5. Store OTP record with lifecycle metadata (invalidates any old code)
        self._store[email] = OtpEntry(
            code=code,
            created_at=now,
            expires_at=now + expire_seconds,
            resend_available_at=now + cooldown_seconds,
            attempts=0,
            max_attempts=settings.OTP_MAX_ATTEMPTS,
        )

        logger.info("Generated and recorded OTP for %s (expires in %ds, cooldown %ds)", email, expire_seconds, cooldown_seconds)
        success_msg = "OTP sent successfully to your email."
        return True, success_msg, cooldown_seconds, code

    def verify_otp(self, raw_email: str, submitted_code: str) -> Tuple[bool, str]:
        """
        Validates the submitted OTP code against the active record.

        Returns:
            (is_valid: bool, status_message: str)
        """
        email = raw_email.strip().lower()
        code = submitted_code.strip()

        if not self.is_valid_email(email):
            return False, "Invalid email address."

        entry = self._store.get(email)

        # Case: No active OTP request found
        if not entry:
            return False, "No active OTP found. Please request a new code."

        now = time.time()

        # Case: Expired OTP (5 minutes exceeded)
        if now > entry.expires_at:
            del self._store[email]
            return False, "OTP expired"

        # Case: Max attempts exceeded (brute-force prevention)
        if entry.attempts >= entry.max_attempts:
            del self._store[email]
            return False, "Too many failed attempts. Please request a new OTP."

        # Case: Incorrect code
        if entry.code != code:
            entry.attempts += 1
            remaining_attempts = entry.max_attempts - entry.attempts
            if remaining_attempts <= 0:
                del self._store[email]
                return False, "Too many failed attempts. Please request a new OTP."
            return False, "Invalid OTP"

        # Case: Successful verification — consume OTP immediately to prevent replay
        del self._store[email]
        return True, "OTP verified successfully"

    def get_active_otp(self, raw_email: str) -> Optional[str]:
        """Returns the active OTP code for test verification / diagnostics without exposing it over API."""
        entry = self._store.get(raw_email.strip().lower())
        return entry.code if entry else None


    def get_remaining_expiry(self, raw_email: str) -> int:
        """Returns remaining validity seconds for active OTP, or 0 if expired/none."""
        email = raw_email.strip().lower()
        entry = self._store.get(email)
        if not entry:
            return 0
        remaining = int(entry.expires_at - time.time())
        return max(0, remaining)

    def get_remaining_cooldown(self, raw_email: str) -> int:
        """Returns remaining cooldown seconds before a resend is permitted."""
        email = raw_email.strip().lower()
        entry = self._store.get(email)
        if not entry:
            return 0
        remaining = int(entry.resend_available_at - time.time())
        return max(0, remaining)

    def clear(self):
        """Empties the OTP store (used for test setup/teardown)."""
        self._store.clear()


# Global singleton instance
otp_manager = OtpManager()
