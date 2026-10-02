import pytest
import socket
from unittest.mock import patch
from fastapi import HTTPException
from starlette.requests import Request
from backend.routes.live import start_live_capture
from backend.core.security import get_active_token


@pytest.mark.asyncio
async def test_start_live_capture_permission_denied_returns_403(monkeypatch):
    """Test that PermissionError during socket creation returns HTTP 403 with setcap advice."""
    active_token = get_active_token()
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/live/start",
        "headers": [(b"authorization", f"Bearer {active_token}".encode("utf-8"))],
        "query_string": b"interface=lo",
    }
    req = Request(scope)

    def mock_socket_permission_error(*args, **kwargs):
        raise PermissionError("Operation not permitted (CAP_NET_RAW required)")

    with patch("socket.socket", side_effect=mock_socket_permission_error):
        with pytest.raises(HTTPException) as exc_info:
            await start_live_capture(request=req, interface="lo")

        assert exc_info.value.status_code == 403
        assert "sudo setcap cap_net_raw,cap_net_admin=eip" in exc_info.value.detail
        assert "Permission denied opening raw socket" in exc_info.value.detail
