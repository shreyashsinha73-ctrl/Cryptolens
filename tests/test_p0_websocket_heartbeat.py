import asyncio
import json
import time
import pytest

from backend.streaming.ws_broadcaster import ConnectionManager


class FastClient:
    def __init__(self):
        self.received = []

    async def accept(self):
        pass

    async def send_text(self, text: str):
        self.received.append(json.loads(text))


class SlowStalledClient:
    """Simulates a slow or completely stalled WebSocket client."""
    def __init__(self):
        self.received = []

    async def accept(self):
        pass

    async def send_text(self, text: str):
        # Hangs longer than send_timeout (0.2s)
        await asyncio.sleep(2.0)
        self.received.append(json.loads(text))


@pytest.mark.asyncio
async def test_slow_client_does_not_stall_others():
    """
    P0-7 Test:
    Verify that when broadcasting across multiple clients, a slow or stalled client
    times out cleanly and does not stall delivery to healthy clients.
    """
    mgr = ConnectionManager(send_timeout=0.15, heartbeat_interval=0.5)
    fast1 = FastClient()
    slow = SlowStalledClient()
    fast2 = FastClient()

    await mgr.connect(fast1)
    await mgr.connect(slow)
    await mgr.connect(fast2)

    assert len(mgr.active_connections) == 3

    t0 = time.perf_counter()
    await mgr.broadcast({"type": "metric_update", "val": 42})
    elapsed = time.perf_counter() - t0

    # Broadcast should return quickly (around send_timeout ~ 0.15s), NOT 2.0s!
    assert elapsed < 0.5, f"Broadcast took too long ({elapsed:.2f}s) due to slow client!"

    # Fast clients must have received the message
    assert len(fast1.received) == 1
    assert fast1.received[0]["val"] == 42
    assert len(fast2.received) == 1
    assert fast2.received[0]["val"] == 42

    # Slow client timed out and should be disconnected
    assert slow not in mgr.active_connections

    # Cleanup
    mgr.disconnect(fast1)
    mgr.disconnect(fast2)


@pytest.mark.asyncio
async def test_server_heartbeat_dispatch():
    """
    P0-7 Test:
    Verify server heartbeat emits periodic heartbeat pings to connected clients.
    """
    mgr = ConnectionManager(send_timeout=0.2, heartbeat_interval=0.2)
    client = FastClient()
    await mgr.connect(client)

    # Wait for at least one heartbeat
    await asyncio.sleep(0.45)
    mgr.disconnect(client)

    heartbeats = [m for m in client.received if m.get("type") == "heartbeat"]
    assert len(heartbeats) >= 1, f"Expected heartbeat messages, got: {client.received}"
