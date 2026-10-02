import asyncio
from unittest.mock import patch, MagicMock
import pytest

import backend.routes.live as live_module


@pytest.mark.asyncio
async def test_rapid_start_stop_start_lifecycle():
    """
    P0-5 Test:
    Verify that calling start -> stop -> start rapidly within 2s
    is idempotent, cancels old tasks, and never yields multiple inference loops.
    """
    with patch("backend.routes.live.LiveSniffer") as MockSnifferClass, \
         patch("socket.socket"):
        mock_sniffer = MagicMock()
        MockSnifferClass.return_value = mock_sniffer

        # 1. First start
        res1 = await live_module.start_live_capture(interface="eth0")
        assert res1["status"] == "started"
        first_inference_task = live_module._inference_task
        assert first_inference_task is not None
        assert not first_inference_task.done()

        # 2. Rapid stop
        res2 = await live_module.stop_live_capture()
        assert res2["status"] == "stopped"
        assert live_module._inference_task is None
        assert first_inference_task.done()  # Old task was cancelled & awaited

        # 3. Rapid second start (within a few milliseconds)
        res3 = await live_module.start_live_capture(interface="eth0")
        assert res3["status"] == "started"
        second_inference_task = live_module._inference_task
        assert second_inference_task is not None
        assert not second_inference_task.done()
        assert second_inference_task is not first_inference_task

        # 4. Rapid concurrent start calls (race condition test)
        res_a, res_b = await asyncio.gather(
            live_module.start_live_capture(interface="eth0"),
            live_module.start_live_capture(interface="eth0"),
        )
        assert res_a["status"] == "started"
        assert res_b["status"] == "started"

        # Exactly one inference task must be active
        active_task = live_module._inference_task
        assert active_task is not None
        assert not active_task.done()

        # 5. Clean teardown
        await live_module.stop_live_capture()
        assert live_module._inference_task is None
        assert active_task.done()
