"""
FastAPI WebSocket connection manager for broadcasting
live telemetry to connected React dashboard clients.
"""

import asyncio
import json
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Active clients: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Active clients: {len(self.active_connections)}"
        )

    async def broadcast(self, message: dict[str, Any]):
        """Send JSON message to all connected clients."""
        payload = json.dumps(message)
        disconnected = []
        for conn in self.active_connections:
            try:
                await conn.send_text(payload)
            except Exception:
                disconnected.append(conn)
        for conn in disconnected:
            self.disconnect(conn)

    async def send_personal(self, websocket: WebSocket, message: dict):
        await websocket.send_text(json.dumps(message))


# Singleton instance
ws_manager = ConnectionManager()

