from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.agent_bridge import router as agent_router
from app.api.v1.recovery import router as recovery_router
from app.api.v1.playbooks import router as playbooks_router
from app.config import settings
from app.database import Base, engine


def _sync_schema(sync_conn):
    Base.metadata.create_all(sync_conn)
    # Auto-reconcile missing columns on existing SQLite databases
    try:
        from sqlalchemy import text
        res = sync_conn.execute(text("PRAGMA table_info(playbooks)")).fetchall()
        cols = [r[1] for r in res]
        if cols and "verification_window_seconds" not in cols:
            sync_conn.execute(text("ALTER TABLE playbooks ADD COLUMN verification_window_seconds INTEGER DEFAULT 15"))
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables & reconcile schema on startup
    async with engine.begin() as conn:
        await conn.run_sync(_sync_schema)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

# Enable CORS for React frontend (Vite runs on 5173)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include agent bridge routes (/api/v1/agent/...)
app.include_router(agent_router, prefix=settings.API_V1_STR)
# Include recovery routes (/api/v1/recovery/...)
app.include_router(recovery_router, prefix=settings.API_V1_STR)
# Include playbooks catalog routes (/api/v1/playbooks)
app.include_router(playbooks_router, prefix=settings.API_V1_STR)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


@app.get("/")
async def root():
    return {"message": "FixAI Backend API is operational"}
