import asyncio
import time
from unittest.mock import patch
import pytest
from starlette.websockets import WebSocketState

from backend.routes.remediation import generate_remediation, _store
from backend.streaming.ws_broadcaster import ConnectionManager


class MockWsConnection:
    """Mock WebSocket that supports async ping-pong."""

    def __init__(self):
        self.client_state = WebSocketState.CONNECTED
        self.received = []

    async def accept(self):
        pass

    async def send_text(self, data: str):
        self.received.append(data)


@pytest.mark.asyncio
async def test_websocket_responsiveness_during_slow_remediation():
    """
    P0-4 Test:
    Verify that while a slow remediation request is in flight (blocking LLM call for 2.0s),
    the async event loop remains free and a WebSocket message/ping round-trips in < 200 ms.
    """
    test_job_id = "test_perf_job_001"
    _store.save(test_job_id, {
        "job_id": test_job_id,
        "control_plane": {
            "ike_version": 2,
            "proposals": [{"encryption": "3des", "dh_group": 2}]
        },
        "findings": [{"title": "Deprecated 3DES", "severity": "CRITICAL"}]
    })

    ws_mgr = ConnectionManager()
    client = MockWsConnection()
    await ws_mgr.connect(client)

    def slow_llm_generation(*args, **kwargs):
        # Blocking sleep representing 2.0s Ollama/Gemini generation
        time.sleep(2.0)
        return {
            "engine_used": "mock_ollama",
            "validation_passed": True,
            "config": {},
        }

    with patch("backend.routes.remediation._engine.generate_remediation", side_effect=slow_llm_generation):
        # 1. Launch slow remediation task in background
        remediation_task = asyncio.create_task(generate_remediation(test_job_id))

        # Yield control so remediation task starts running in thread
        await asyncio.sleep(0.05)
        assert not remediation_task.done(), "Remediation task finished prematurely"

        # 2. Measure WebSocket broadcast round-trip while remediation is running
        t_start = time.perf_counter()
        await ws_mgr.broadcast({"type": "ping", "timestamp": time.time()})
        t_end = time.perf_counter()

        elapsed_ms = (t_end - t_start) * 1000.0

        # Assert WebSocket operation finished in well under 200ms
        assert elapsed_ms < 200.0, f"WebSocket operation blocked! Took {elapsed_ms:.2f} ms (expected < 200 ms)"

        # 3. Await remediation completion
        result = await remediation_task
        assert result["remediation"]["engine_used"] == "mock_ollama"
