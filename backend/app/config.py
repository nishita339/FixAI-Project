import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "FixAI Backend"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Defaults to SQLite async for zero-dependency instant boot, supports Postgresql+asyncpg
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", 
        "sqlite+aiosqlite:///./fixai.db"
    )
    
    JWT_SECRET: str = os.getenv("JWT_SECRET", "fixai-super-secret-key-change-in-production")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    
    CONVEX_DEVICE_API_KEY: str = "fixai-device-secret-key-2026"
    DEFAULT_DEVICE_KEY: str = "fixai-device-secret-key-2026"

    model_config = {
        "case_sensitive": False,
        "env_file": ".env",
        "extra": "ignore",
    }

settings = Settings()
