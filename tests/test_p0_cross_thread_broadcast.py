import asyncio
import json
import threading
import time
import pytest

import backend.routes.live as live_module
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
    into backend.routes.live._telemetry_queue do not raise RuntimeError,
    and backend.routes.live._telemetry_flusher correctly batches them
    over ws_manager every 100-250 ms.
    """
    mock_ws = MockWebSocket()
    await live_module.ws_manager.connect(mock_ws)

    # Set mock stream ID and keep sniffer flag active during producer run
    test_stream_id = "test-stream-p0-1"
    live_module._current_stream_id = test_stream_id
    live_module._sniffer = object()  # Non-None indicator to keep flusher alive

    # Drain any existing stale items
    while not live_module._telemetry_queue.empty():
        try:
            live_module._telemetry_queue.get_nowait()
        except Exception:
            break

    flusher_task = asyncio.create_task(live_module._telemetry_flusher(flush_interval=0.05))

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
                pkt_dict = rec.to_dict()
                pkt_dict["type"] = "esp_event"
                live_module._telemetry_queue.put_nowait(pkt_dict)
                if i % 1000 == 0:
                    time.sleep(0.005)
        except Exception as e:
            errors.append(e)

    try:
        thread = threading.Thread(target=background_producer, daemon=True)
        thread.start()

        # Wait for thread to finish producing
        await asyncio.to_thread(thread.join, timeout=5.0)
        assert not errors, f"Background producer encountered errors: {errors}"

        # Signal sniffer stop so flusher exits once queue is drained
        live_module._sniffer = None

        # Wait for flusher to drain queue and complete
        for _ in range(50):
            if live_module._telemetry_queue.empty():
                break
            await asyncio.sleep(0.05)

        await asyncio.wait_for(flusher_task, timeout=3.0)
    finally:
        live_module._sniffer = None
        if not flusher_task.done():
            flusher_task.cancel()
            try:
                await flusher_task
            except asyncio.CancelledError:
                pass
        live_module.ws_manager.disconnect(mock_ws)

    # Validate received batches
    batch_messages = [m for m in mock_ws.messages if m.get("type") == "telemetry_batch"]
    assert len(batch_messages) > 0, "Client received no telemetry_batch messages"

    total_events_received = sum(len(m["events"]) for m in batch_messages)
    assert total_events_received == 5000, f"Expected 5,000 events, received {total_events_received}"

    # Verify that messages were actually batched (i.e. far fewer messages than 5,000)
    assert len(batch_messages) < 100, f"Expected batched delivery, but got {len(batch_messages)} messages"

    # Verify stream_id propagation
    assert all(m.get("stream_id") == test_stream_id for m in batch_messages)
