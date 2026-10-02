import pytest
from fastapi import HTTPException
from starlette.requests import Request
from backend.core.security import (
    validate_job_id,
    validate_interface,
    verify_api_auth,
    get_active_token,
)


def test_path_traversal_job_id_rejected():
    """Verify that path traversal, absolute paths, and null bytes are rejected with 400."""
    invalid_ids = [
        "../../etc/passwd",
        "/etc/shadow",
        "job_123\0malicious",
        "job_123/../../secret",
        "job!@#$%",
        "",
        "a" * 65,  # Exceeds max length
    ]
    for bad_id in invalid_ids:
        with pytest.raises(HTTPException) as exc_info:
            validate_job_id(bad_id)
        assert exc_info.value.status_code == 400, f"Expected 400 for '{bad_id}', got {exc_info.value.status_code}"


def test_valid_job_ids_accepted():
    """Verify standard UUIDs and safe identifiers pass validation."""
    valid_ids = [
        "9f8b2c1a-1234-5678-9abc-def012345678",
        "config_01_tunnel_aes256gcm_dh19_pfson",
        "job_abc123",
        "test-job-42",
    ]
    for good_id in valid_ids:
        assert validate_job_id(good_id) == good_id


def test_interface_whitelist_enforced():
    """Verify interface parameter whitelist against untrusted inputs."""
    # Valid interfaces
    assert validate_interface("any") == "any"
    assert validate_interface("lo") == "lo"

    # Malicious or untrusted interfaces
    bad_ifaces = [
        "eth0; rm -rf /",
        "../../dev/null",
        "unauthorized_iface_9999",
        "eth0\0injected",
    ]
    for bad_iface in bad_ifaces:
        with pytest.raises(HTTPException) as exc_info:
            validate_interface(bad_iface)
        assert exc_info.value.status_code == 400


def test_api_auth_token_enforcement(monkeypatch):
    """Verify that missing/invalid tokens raise 401 and valid tokens pass."""
    monkeypatch.delenv("DISABLE_API_AUTH", raising=False)
    active_token = get_active_token()

    # 1. Missing token -> 401
    scope_missing = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/live/start",
        "headers": [],
        "query_string": b"",
    }
    req_missing = Request(scope_missing)
    with pytest.raises(HTTPException) as exc_info:
        verify_api_auth(req_missing)
    assert exc_info.value.status_code == 401

    # 2. Invalid Bearer token -> 401
    scope_invalid = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/live/start",
        "headers": [(b"authorization", b"Bearer wrong-token-12345")],
        "query_string": b"",
    }
    req_invalid = Request(scope_invalid)
    with pytest.raises(HTTPException) as exc_info:
        verify_api_auth(req_invalid)
    assert exc_info.value.status_code == 401

    # 3. Valid Bearer token -> 200 / True
    scope_valid_header = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/live/start",
        "headers": [(b"authorization", f"Bearer {active_token}".encode("utf-8"))],
        "query_string": b"",
    }
    req_valid = Request(scope_valid_header)
    assert verify_api_auth(req_valid) is True

    # 4. Valid query param token -> 200 / True
    scope_valid_query = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/live/start",
        "headers": [],
        "query_string": f"token={active_token}".encode("utf-8"),
    }
    req_query = Request(scope_valid_query)
    assert verify_api_auth(req_query) is True


@pytest.mark.asyncio
async def test_remediation_endpoint_requires_auth(monkeypatch):
    """Test that /api/v1/remediate/{job_id} rejects unauthenticated requests."""
    monkeypatch.delenv("DISABLE_API_AUTH", raising=False)
    from backend.routes.remediation import generate_remediation

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/remediate/job_123",
        "headers": [],
        "query_string": b"",
    }
    req = Request(scope)
    with pytest.raises(HTTPException) as exc_info:
        await generate_remediation(job_id="job_123", request=req)
    assert exc_info.value.status_code == 401
