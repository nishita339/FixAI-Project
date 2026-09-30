"""
FixAI Backend — Real-Time WebSocket Streaming Manager
=====================================================

Provides high-throughput, low-latency (<50ms) bidirectional WebSocket
communication for real-time telemetry, EDR alerts, incident transitions,
and online/offline device heartbeat synchronization.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("fixai.websockets")


class ConnectionManager:
    """Manages active WebSocket client connections with broadcast capabilities."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.last_telemetry: Optional[Dict[str, Any]] = None
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept new WebSocket connection and immediately transmit latest state."""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info("📡 WebSocket client connected. Active clients: %d", len(self.active_connections))

        # Immediately send cached telemetry if available so dashboard populates instantly
        if self.last_telemetry:
            try:
                await websocket.send_json({
                    "type": "INITIAL_STATE",
                    "telemetry": self.last_telemetry,
                })
            except Exception:
                pass

    async def disconnect(self, websocket: WebSocket) -> None:
        """Safely remove disconnected client."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info("🔌 WebSocket client disconnected. Remaining clients: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Broadcast JSON message to all active clients concurrently."""
        dead_connections: List[WebSocket] = []

        async with self._lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        if dead_connections:
            async with self._lock:
                for dead in dead_connections:
                    if dead in self.active_connections:
                        self.active_connections.remove(dead)

    async def broadcast_telemetry(self, data: Dict[str, Any]) -> None:
        """Cache and broadcast live telemetry tick to all connected clients."""
        self.last_telemetry = data
        await self.broadcast({
            "type": "TELEMETRY_UPDATE",
            "data": data,
        })

    async def broadcast_alert(self, alert_data: Dict[str, Any]) -> None:
        """Broadcast high-priority incident or EDR alert."""
        await self.broadcast({
            "type": "SECURITY_ALERT",
            "data": alert_data,
        })

    async def broadcast_action(self, action_data: Dict[str, Any]) -> None:
        """Broadcast playbook remediation state change."""
        await self.broadcast({
            "type": "RECOVERY_ACTION",
            "data": action_data,
        })

    def get_active_count(self) -> int:
        """Return total active WebSocket clients."""
        return len(self.active_connections)


# Global singleton instance
ws_manager = ConnectionManager()
