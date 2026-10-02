"""
backend/core/security.py
------------------------
Security hardening utilities:
- API auth token verification for mutating endpoints (P2-1)
- Strict job_id validation and path-traversal prevention (P2-1)
- Network interface whitelisting against scapy/system interfaces (P2-1)
"""

import os
import re
import hmac
import secrets
import logging
from typing import Optional
from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

# API Auth Token: load from env or generate high-entropy session token
_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN")
if not _AUTH_TOKEN:
    _AUTH_TOKEN = secrets.token_urlsafe(24)
    logger.info(f"API_AUTH_TOKEN not set in environment. Generated session token: {_AUTH_TOKEN}")
else:
    logger.info("API_AUTH_TOKEN loaded from environment.")


def get_active_token() -> str:
    """Return the active API auth token."""
    return _AUTH_TOKEN


def verify_api_auth(request: Optional[Request] = None) -> bool:
    """
    Verify bearer token, X-API-Token header, or ?token= query parameter on mutating endpoints.
    Can be bypassed if DISABLE_API_AUTH=true is explicitly set in environment, or if request is None.
    """
    if request is None:
        return True
    if os.getenv("DISABLE_API_AUTH", "false").lower() in ("true", "1", "yes"):
        return True

    provided_token: Optional[str] = None

    # 1. Check Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        provided_token = auth_header[7:].strip()
    elif request.headers.get("X-API-Token"):
        provided_token = request.headers.get("X-API-Token").strip()
    elif "token" in request.query_params:
        provided_token = request.query_params["token"].strip()

    if not provided_token or not hmac.compare_digest(provided_token, _AUTH_TOKEN):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: missing or invalid API token. Pass Authorization: Bearer <token> or ?token=<token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


_SAFE_JOB_ID_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


def validate_job_id(job_id: str) -> str:
    """Validate job_id format and reject path traversal attempts."""
    if not job_id:
        raise HTTPException(status_code=400, detail="Missing job_id")
    if ".." in job_id or "/" in job_id or "\\" in job_id or "\0" in job_id:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid job_id '{job_id}': path traversal sequence detected",
        )
    if not _SAFE_JOB_ID_RE.match(job_id):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid job_id '{job_id}': must be 1-64 alphanumeric/dash/underscore characters",
        )
    return job_id


def validate_interface(interface: str) -> str:
    """Validate network interface against system interfaces and whitelist."""
    if not interface or "/" in interface or "\\" in interface or "\0" in interface or ".." in interface:
        raise HTTPException(status_code=400, detail=f"Invalid interface name '{interface}'")

    whitelist = {"any", "lo", "eth0", "eth1", "wlan0", "docker0", "veth0", "veth1"}
    try:
        from scapy.all import get_if_list
        whitelist.update(get_if_list())
    except Exception:
        pass

    if interface not in whitelist:
        raise HTTPException(
            status_code=400,
            detail=f"Interface '{interface}' not authorized. Allowed interfaces: {sorted(list(whitelist))}",
        )
    return interface
