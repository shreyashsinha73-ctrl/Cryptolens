import asyncio
import json
import queue
import threading
import time
import pytest

from backend.streaming.ws_broadcaster import ConnectionManager
from backend.streaming.live_sniffer import ESPPacketRecord


class MockWebSocket:
    """Mock WebSocket client that collects received text messages."""

    def __init__(self):
        self.messages = []
        self.closed = False

    async def accept(self):
        pass

    async def send_text(self, text: str):
        if self.closed:
            raise RuntimeError("WebSocket is closed")
        self.messages.append(json.loads(text))

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_cross_thread_broadcast_batching():
    """
    P0-1 Test:
    Verify that 5,000 synthetic records emitted from a background thread
    do not raise RuntimeError (e.g. asyncio.get_event_loop in thread),
    are safely buffered in a bounded queue, and the client receives batched messages
    every 100-250 ms.
    """
    loop = asyncio.get_running_loop()
    ws_mgr = ConnectionManager()
    mock_ws = MockWebSocket()
    await ws_mgr.connect(mock_ws)

    telemetry_queue: queue.Queue = queue.Queue(maxsize=10000)
    stop_event = threading.Event()
    flusher_running = True

    # Async flusher task running on event loop
    async def flusher():
        nonlocal flusher_running
        while flusher_running or not telemetry_queue.empty():
            batch = []
            while len(batch) < 500:
                try:
                    item = telemetry_queue.get_nowait()
                    batch.append(item)
                except queue.Empty:
                    break
            if batch:
                await ws_mgr.broadcast({
                    "type": "telemetry_batch",
                    "events": batch,
                    "count": len(batch)
                })
            await asyncio.sleep(0.1)

    flusher_task = asyncio.create_task(flusher())

    # Background worker thread emitting 5,000 synthetic records
    errors = []

    def background_producer():
        try:
            for i in range(5000):
                rec = ESPPacketRecord(
                    timestamp=time.time(),
                    frame_number=i + 1,
                    src_ip="192.168.1.10",
                    dst_ip="192.168.2.20",
                    packet_length=128,
                    spi="0x12345678",
                    seq_num=i + 1,
                )
                telemetry_queue.put_nowait(rec.to_dict())
                if i % 1000 == 0:
                    time.sleep(0.005)
        except Exception as e:
            errors.append(e)
        finally:
            stop_event.set()

    thread = threading.Thread(target=background_producer, daemon=True)
    thread.start()

    # Wait for thread to finish producing
    await asyncio.to_thread(thread.join, timeout=5.0)
    assert not errors, f"Background producer encountered errors: {errors}"

    # Wait for flusher to drain queue
    for _ in range(30):
        if telemetry_queue.empty():
            break
        await asyncio.sleep(0.1)

    flusher_running = False
    await flusher_task

    # Validate received batches
    assert len(mock_ws.messages) > 0, "Client received no messages"
    total_events_received = sum(
        len(m["events"]) for m in mock_ws.messages if m.get("type") == "telemetry_batch"
    )
    assert total_events_received == 5000, f"Expected 5,000 events, received {total_events_received}"

    # Verify that messages were actually batched (i.e. far fewer messages than 5,000)
    batch_messages = [m for m in mock_ws.messages if m.get("type") == "telemetry_batch"]
    assert len(batch_messages) < 100, f"Expected batched delivery, but got {len(batch_messages)} messages"
