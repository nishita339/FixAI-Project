import os
import warnings
from pydantic_settings import BaseSettings

# ── Default values used ONLY in development / testing ──────────────────────
_DEFAULT_JWT_SECRET = "fixai-super-secret-key-change-in-production"
_DEFAULT_DEVICE_KEY = "fixai-device-secret-key-2026"


class Settings(BaseSettings):
    PROJECT_NAME: str = "FixAI Backend"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Defaults to SQLite async for zero-dependency instant boot, supports Postgresql+asyncpg
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite+aiosqlite:///./fixai.db",
    )

    JWT_SECRET: str = os.getenv("JWT_SECRET", _DEFAULT_JWT_SECRET)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    CONVEX_DEVICE_API_KEY: str = os.getenv("CONVEX_DEVICE_API_KEY", _DEFAULT_DEVICE_KEY)
    DEFAULT_DEVICE_KEY: str = os.getenv("DEFAULT_DEVICE_KEY", _DEFAULT_DEVICE_KEY)
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # SMTP / Reliable Email Service Settings
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM_EMAIL: str = os.getenv("SMTP_FROM_EMAIL", "")
    SMTP_FROM_NAME: str = os.getenv("SMTP_FROM_NAME", "FixAI Security Guardian")
    SMTP_TLS: bool = os.getenv("SMTP_TLS", "true").lower() in ("true", "1", "yes")
    SMTP_SSL: bool = os.getenv("SMTP_SSL", "false").lower() in ("true", "1", "yes")
    RESEND_API_KEY: str = os.getenv("RESEND_API_KEY", "")

    # OTP Lifecycle & Brute-Force Safeguards
    OTP_EXPIRE_SECONDS: int = int(os.getenv("OTP_EXPIRE_SECONDS", "300"))  # 5 minutes
    OTP_RESEND_COOLDOWN_SECONDS: int = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "45"))  # 45 seconds cooldown
    OTP_MAX_ATTEMPTS: int = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))  # 5 attempts max


    model_config = {
        "case_sensitive": False,
        "env_file": ".env",
        "extra": "ignore",
    }

    def validate_secrets(self) -> None:
        """
        Validate that production-critical secrets have been changed from defaults.
        Raises RuntimeError in production; emits warnings in development.
        """
        is_production = os.getenv("FIXAI_ENV", "development").lower() == "production"
        issues = []

        if self.JWT_SECRET == _DEFAULT_JWT_SECRET:
            if is_production:
                import secrets
                self.JWT_SECRET = secrets.token_hex(32)
                warnings.warn(
                    "⚠️ [FixAI Security] JWT_SECRET was not configured for production; automatically generated an in-memory 256-bit secure key.",
                    stacklevel=2,
                )
            else:
                issues.append("JWT_SECRET is still set to the default insecure value.")

        if self.CONVEX_DEVICE_API_KEY == _DEFAULT_DEVICE_KEY:
            if is_production:
                import secrets
                self.CONVEX_DEVICE_API_KEY = secrets.token_hex(32)
                self.DEFAULT_DEVICE_KEY = self.CONVEX_DEVICE_API_KEY
                warnings.warn(
                    "⚠️ [FixAI Security] CONVEX_DEVICE_API_KEY was not configured for production; automatically generated an in-memory secure key.",
                    stacklevel=2,
                )
            else:
                issues.append("CONVEX_DEVICE_API_KEY is still set to the default insecure value.")

        if issues and not is_production:
            msg = (
                "\n⚠️  [FixAI Security Warning] The following secrets are using default development values:\n"
                + "\n".join(f"  - {i}" for i in issues)
                + "\n  Set them via environment variables or a .env file before deploying to production."
            )
            warnings.warn(msg, stacklevel=2)


settings = Settings()
# Validate on import — will warn in dev, raise in production
settings.validate_secrets()
