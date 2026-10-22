import asyncio
import os
import sys
import warnings
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure 'backend' directory is on sys.path so 'app.*' imports work from anywhere
# (including when running directly with 'python main.py' or VS Code Run button)
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# Filter noisy sklearn / pickle version warnings on newer Python runtimes
warnings.filterwarnings("ignore", message=".*unpickle estimator.*")
warnings.filterwarnings("ignore", message=".*serialized model.*")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
import logging
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.agent_bridge import router as agent_router
from app.api.v1.recovery import router as recovery_router
from app.api.v1.playbooks import router as playbooks_router
from app.api.v1.auth import router as auth_router
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
    every 1 second, executes real Edge AI inference on the metrics, and broadcasts
    real-time telemetry to the dashboard.
    """
    import time, psutil, sys, socket
    from pathlib import Path

    # Initialize EdgeAIEngine for real ML scoring
    edge_ai = None
    try:
        agent_dir = Path(__file__).resolve().parent.parent.parent / "fixai-guardian" / "local_agent"
        if str(agent_dir) not in sys.path:
            sys.path.append(str(agent_dir))
        from ai_engine.inference import EdgeAIEngine
        edge_ai = EdgeAIEngine(model_dir=agent_dir / "models")
    except Exception:
        edge_ai = None

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
                        disk = 0.0

                    # Real core temperature check
                    temp = None
                    try:
                        if hasattr(psutil, "sensors_temperatures"):
                            temps = psutil.sensors_temperatures()
                            if temps:
                                for name, entries in temps.items():
                                    for entry in entries:
                                        if entry.current and entry.current > 0:
                                            temp = round(float(entry.current), 1)
                                            break
                                    if temp is not None:
                                        break
                    except Exception:
                        temp = None

                    # Real network socket latency
                    latency_ms = None
                    try:
                        t0 = time.perf_counter()
                        s = socket.create_connection(("127.0.0.1", 8000), timeout=0.3)
                        s.close()
                        latency_ms = round((time.perf_counter() - t0) * 1000.0, 1)
                    except Exception:
                        latency_ms = None

                    # Real network error rate
                    net_err = 0.0
                    try:
                        net = psutil.net_io_counters()
                        tot = (net.packets_recv + net.packets_sent) or 1
                        net_err = round(((net.errin + net.errout + net.dropin + net.dropout) / tot) * 100, 2)
                    except Exception:
                        pass

                    # Real Edge ML Inference
                    anom_score = None
                    p_fail = None
                    risk_level = "LOW"
                    shap_data = None
                    nlg_diag = None
                    if edge_ai:
                        try:
                            ai_res = edge_ai.analyze({
                                "cpu": cpu,
                                "ram": float(mem.percent),
                                "disk": disk,
                                "latency": latency_ms or 0.0,
                                "error_rate": net_err,
                            })
                            anom_score = ai_res.get("anomaly_score")
                            p_fail = ai_res.get("p_failure")
                            risk_level = ai_res.get("risk", "LOW")
                            shap_data = ai_res.get("shap_weights")
                            nlg_diag = ai_res.get("nlg_explanation")
                        except Exception:
                            pass

                    # Real Battery sensing
                    battery_pct = None
                    is_plugged = None
                    try:
                        batt = psutil.sensors_battery()
                        if batt and batt.percent is not None:
                            battery_pct = round(float(batt.percent), 1)
                            is_plugged = bool(batt.power_plugged)
                    except Exception:
                        pass

                    await ws_manager.broadcast_telemetry({
                        "t": now_ms,
                        "cpu": round(cpu, 1),
                        "ram": round(float(mem.percent), 1),
                        "latency": latency_ms,
                        "errorRate": net_err,
                        "disk": round(disk, 1),
                        "temp": temp,
                        "temp_available": temp is not None,
                        "battery": battery_pct,
                        "battery_available": battery_pct is not None,
                        "is_plugged": is_plugged,
                        "anomalyScore": anom_score,
                        "pFailure": p_fail,
                        "risk": risk_level,
                        "shap": shap_data,
                        "nlg_explanation": nlg_diag,
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

# Enable CORS for React frontend (Vite local dev, Vercel, Render, Railway cloud deployments)
raw_cors = getattr(settings, "CORS_ORIGINS", "") or os.getenv("CORS_ORIGINS", "")
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
if raw_cors:
    allowed_origins.extend([o.strip() for o in raw_cors.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|.*\.vercel\.app|.*\.onrender\.com|.*\.railway\.app)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logging.getLogger("fixai.api").error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    origin = request.headers.get("origin", "*")
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc), "error": type(exc).__name__, "path": request.url.path},
        headers={
            "Access-Control-Allow-Origin": origin if origin else "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )


# Include agent bridge routes (/api/v1/agent/...)
app.include_router(agent_router, prefix=settings.API_V1_STR)
# Include recovery routes (/api/v1/recovery/...)
app.include_router(recovery_router, prefix=settings.API_V1_STR)
# Include playbooks catalog routes (/api/v1/playbooks)
app.include_router(playbooks_router, prefix=settings.API_V1_STR)
# Include authentication & Email OTP routes (/api/v1/auth/...)
app.include_router(auth_router, prefix=settings.API_V1_STR)


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


@app.get("/api/v1/system/db-status")
async def database_status():
    """
    GET /api/v1/system/db-status
    Improvement #11: Returns database connection status, dialect (PostgreSQL vs SQLite),
    and active connection pool health.
    """
    from app.database import check_database_health
    return await check_database_health()


@app.get("/")
async def root():
    return {"message": "FixAI Backend API is operational"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)

