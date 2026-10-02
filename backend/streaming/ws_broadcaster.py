import asyncio
import json
import logging
import time
from typing import Any, Optional
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections, heartbeat, and non-blocking broadcasts."""

    def __init__(self, send_timeout: float = 0.5, heartbeat_interval: float = 20.0):
        self.active_connections: list[WebSocket] = []
        self.send_timeout = send_timeout
        self.heartbeat_interval = heartbeat_interval
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Active clients: {len(self.active_connections)}"
        )
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Active clients: {len(self.active_connections)}"
        )
        if not self.active_connections and self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    async def _send_with_timeout(self, conn: WebSocket, payload: str) -> bool:
        """Send a message to a single connection with per-send timeout."""
        try:
            await asyncio.wait_for(conn.send_text(payload), timeout=self.send_timeout)
            return True
        except Exception:
            return False

    async def broadcast(self, message: dict[str, Any]):
        """
        Send JSON message concurrently to all connected clients using asyncio.gather
        with a per-send timeout so a slow or stalled client cannot stall others.
        """
        if not self.active_connections:
            return

        payload = json.dumps(message)
        conns = list(self.active_connections)
        results = await asyncio.gather(
            *(self._send_with_timeout(c, payload) for c in conns),
            return_exceptions=True,
        )

        for conn, success in zip(conns, results):
            if success is not True:
                self.disconnect(conn)

    async def send_personal(self, websocket: WebSocket, message: dict):
        payload = json.dumps(message)
        await asyncio.wait_for(websocket.send_text(payload), timeout=self.send_timeout)

    async def _heartbeat_loop(self):
        """Server heartbeat sending ping every 15-30 seconds."""
        try:
            while self.active_connections:
                await asyncio.sleep(self.heartbeat_interval)
                if not self.active_connections:
                    break
                await self.broadcast({
                    "type": "heartbeat",
                    "timestamp": time.time(),
                })
        except asyncio.CancelledError:
            pass


# Singleton instance
ws_manager = ConnectionManager()

