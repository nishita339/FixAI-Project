/**
 * Central API & WebSocket configuration for FixAI Guardian.
 *
 * Windows 10/11 DNS resolution:
 * Resolving 'localhost' often prioritizes IPv6 [::1]. If uvicorn/Python binds to IPv4 (0.0.0.0 / 127.0.0.1),
 * connections to [::1] are refused or experience 15s timeout delays.
 * We normalize 'localhost:8000' -> '127.0.0.1:8000' for reliable, instant local connectivity.
 */

const rawFastApi = (import.meta as any).env?.VITE_FASTAPI_URL || "http://127.0.0.1:8000";
export const FASTAPI_URL = rawFastApi.replace("://localhost:", "://127.0.0.1:");

const rawWs = (import.meta as any).env?.VITE_WS_URL || `${FASTAPI_URL.replace(/^http/, "ws")}/api/v1/ws/telemetry`;
export const WS_URL = rawWs.replace("://localhost:", "://127.0.0.1:");
