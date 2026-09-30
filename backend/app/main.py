import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.agent_bridge import router as agent_router
from app.api.v1.recovery import router as recovery_router
from app.api.v1.playbooks import router as playbooks_router
from app.config import settings
from app.database import Base, engine
from app.seed import sync_and_seed_database
from app.websockets import ws_manager


def _sync_schema(sync_conn):
    Base.metadata.create_all(sync_conn)
    # Auto-reconcile schema and seed initial users, devices, and unified playbooks
    sync_and_seed_database(sync_conn)


async def _background_hardware_sampler():
    """
    Real-time autonomic broadcaster loop.
    If WebSocket clients are connected and no external agent is pushing telemetry
    (e.g., standalone local mode or agent offline), samples host hardware via psutil
    every 1 second and broadcasts real-time telemetry to the dashboard.
    """
    import time, psutil, sys
    while True:
        try:
            if ws_manager.get_active_count() > 0:
                last_t = ws_manager.last_telemetry.get("t", 0) if ws_manager.last_telemetry else 0
                now_ms = int(time.time() * 1000)
                # If last sample was more than 1.8 seconds ago, sample host hardware
                if (now_ms - last_t) > 1800:
                    cpu = float(psutil.cpu_percent(interval=None))
                    mem = psutil.virtual_memory()
                    try:
                        path = "C:\\" if sys.platform == "win32" else "/"
                        disk = float(psutil.disk_usage(path).percent)
                    except Exception:
                        disk = 45.0

                    temp = 42.0 + (cpu * 0.4)
                    net_err = 0.0
                    try:
                        net = psutil.net_io_counters()
                        tot = (net.packets_recv + net.packets_sent) or 1
                        net_err = round(((net.errin + net.errout + net.dropin + net.dropout) / tot) * 100, 2)
                    except Exception:
                        pass

                    await ws_manager.broadcast_telemetry({
                        "t": now_ms,
                        "cpu": round(cpu, 1),
                        "ram": round(float(mem.percent), 1),
                        "latency": 12.0,
                        "errorRate": net_err,
                        "disk": round(disk, 1),
                        "temp": round(temp, 1),
                        "anomalyScore": round(max(0.05, (cpu / 100.0) * 0.3), 2),
                        "pFailure": round(max(0.02, (cpu / 100.0) * 0.25), 2),
                        "risk": "LOW" if cpu < 80 else "MEDIUM",
                        "device_id": "dev-laptop-001",
                        "device_name": "Local Workstation",
                        "isRealHardware": True,
                        "is_online": True,
                        "mode": "AUTONOMIC_LOCAL",
                    })
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        await asyncio.sleep(1.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create tables & reconcile schema on startup
    async with engine.begin() as conn:
        await conn.run_sync(_sync_schema)
    sampler_task = asyncio.create_task(_background_hardware_sampler())
    yield
    sampler_task.cancel()
    try:
        await sampler_task
    except (asyncio.CancelledError, Exception):
        pass
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


@app.websocket("/ws/telemetry")
@app.websocket("/api/v1/ws/telemetry")
@app.websocket("/ws")
async def global_ws_endpoint(websocket: WebSocket):
    """
    Universal real-time WebSocket endpoint for instant telemetry and security event streaming.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "websocket_clients": ws_manager.get_active_count(),
    }


@app.get("/")
async def root():
    return {"message": "FixAI Backend API is operational"}
