# Non-Root Operation & Linux Capabilities Guide

CryptoLens is designed to run securely under non-root user accounts while performing passive IPsec network auditing and packet capturing.

## 1. Required Linux Capabilities

To open raw sockets (`SOCK_RAW`) and sniff ESP (IP proto 50) or IKE (UDP 500/4500) traffic on Linux network interfaces without running as the `root` superuser, grant the binary `CAP_NET_RAW` and `CAP_NET_ADMIN`:

```bash
# Grant capabilities to the Python binary in your virtual environment
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

# Verify assigned capabilities
getcap $(readlink -f $(which python3))
# Expected output:
# /usr/bin/python3.14 cap_net_admin,cap_net_raw=eip
```

## 2. Docker / Container Operation

When running in containerized environments (Docker / Kubernetes):

1. Set `network_mode: "host"` so the container has visibility into host IPsec ESP tunnel frames (standard Docker bridge networks isolate and drop external ESP packets).
2. Add Linux capabilities `NET_RAW` and `NET_ADMIN` to the container definition without requiring full `--privileged` access:

```yaml
services:
  backend:
    image: cryptolens-backend:latest
    network_mode: "host"
    cap_add:
      - NET_RAW
      - NET_ADMIN
```

## 3. Preflight Check & Graceful 403 Response

When `POST /api/v1/live/start` is invoked:
- The backend tests opening a raw socket.
- If unprivileged, it catches `PermissionError` and returns HTTP `403 Forbidden` with the exact remediation command:
  ```json
  {
    "detail": "Permission denied opening raw socket for live sniffing. Grant required Linux capabilities with: sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"
  }
  ```
- It never raises an unhandled `500 Internal Server Error`.
