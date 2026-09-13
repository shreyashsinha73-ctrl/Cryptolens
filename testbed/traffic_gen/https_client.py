#!/usr/bin/env python3
"""
CryptoLens Traffic Generator - HTTPS Web Browsing Simulation
Simulates real-world HTTPS browsing activity across the IPsec tunnel:
- Real TLS 1.3/1.2 handshake negotiation
- Bursty request/response patterns with variable payload sizes (HTML, JSON, CSS, images)
- Pipelined TCP connections and realistic user think-time intervals

Produces the characteristic bursty, variable-size packet footprint.
"""

import argparse
import http.server
import os
import random
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

DEFAULT_PORT = 8443
CERT_FILE = "/tmp/cryptolens_server.crt"
KEY_FILE = "/tmp/cryptolens_server.key"

def ensure_ssl_certificate(cert_path: str = CERT_FILE, key_path: str = KEY_FILE):
    """Generates an ephemeral self-signed SSL certificate if not present"""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "30", "-nodes",
        "-subj", "/CN=cryptolens.testbed.local/O=CryptoLens/C=IN"
    ]
    try:
        subprocess.run(cmd, capture_output=True, check=True)
    except Exception as e:
        print(f"[https_client] Warning: Failed to generate SSL cert via openssl: {e}")

class TestbedHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Responds with varying payload types and sizes to emulate real web servers"""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            # Emulate an HTML web page
            content = (
                "<!DOCTYPE html><html><head><title>CryptoLens IPsec Testbed</title></head>"
                "<body><h1>CryptoLens Secure Audit</h1>"
                "<p>Testing encrypted payload metadata footprint.</p>"
                + ("<!-- filler text -->\n" * 20) + "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        elif self.path.startswith("/api/telemetry"):
            # Emulate a JSON API response
            json_data = {
                "system": "CryptoLens-Probe",
                "timestamp": time.time(),
                "metrics": [random.randint(100, 999) for _ in range(50)],
                "status": "HEALTHY",
                "compliance": "NIST-800-77-Rev1"
            }
            import json
            content = json.dumps(json_data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        elif self.path.startswith("/assets/"):
            # Emulate medium-to-large asset payload (e.g. stylesheet or image)
            size = random.randint(1200, 4500)
            content = os.urandom(size)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress noisy standard server logging
        return

def run_https_server(bind_ip: str, port: int, stop_event: threading.Event = None):
    ensure_ssl_certificate()
    server_address = (bind_ip, port)
    httpd = http.server.HTTPServer(server_address, TestbedHTTPRequestHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"[https_client] HTTPS Server listening on https://{bind_ip}:{port}/")

    if stop_event:
        httpd.timeout = 0.5
        while not stop_event.is_set():
            httpd.handle_request()
        httpd.server_close()
    else:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()

def run_https_client(target_ip: str, port: int, num_bursts: int = 5, requests_per_burst: int = 4):
    """
    Executes multiple bursts of HTTPS requests mimicking user browsing:
    GET index page -> GET API data -> GET stylesheets/images
    """
    base_url = f"https://{target_ip}:{port}"
    print(f"[https_client] Starting HTTPS client simulation against: {base_url}")
    print(f"[https_client] Configuration: {num_bursts} bursts of {requests_per_burst} requests")

    # SSL context that ignores self-signed testbed certificate
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    endpoints = [
        "/",
        "/api/telemetry",
        "/assets/style.css",
        "/assets/logo.png",
        "/api/telemetry?query=sync"
    ]

    total_requests = 0
    start_total = time.time()

    for burst_idx in range(num_bursts):
        burst_start = time.time()
        print(f"[https_client] Executing burst #{burst_idx + 1}...")

        for req_idx in range(requests_per_burst):
            endpoint = random.choice(endpoints)
            url = f"{base_url}{endpoint}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CryptoLens-Browser-Sim/1.0"})
                with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
                    data = resp.read()
                    total_requests += 1
            except Exception as e:
                print(f"[https_client] Request error ({url}): {e}")

            # Micro-delay between requests in a burst (10ms - 80ms)
            time.sleep(random.uniform(0.01, 0.08))

        # Inter-burst user think time (100ms - 400ms)
        think_time = random.uniform(0.15, 0.40)
        time.sleep(think_time)

    elapsed = time.time() - start_total
    print(f"[https_client] HTTPS simulation finished: {total_requests} requests in {elapsed:.2f}s")

def main():
    parser = argparse.ArgumentParser(description="CryptoLens HTTPS Browsing Simulator")
    parser.add_argument("--mode", choices=["server", "client", "both"], default="client",
                        help="Operating mode: server, client, or both")
    parser.add_argument("--server-ip", default="192.168.2.1", help="HTTPS Server bind/target IP")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT, help="HTTPS Port")
    parser.add_argument("--bursts", "-b", type=int, default=5, help="Number of web browsing bursts")
    parser.add_argument("--requests", "-r", type=int, default=4, help="Requests per burst")
    args = parser.parse_args()

    if args.mode == "server":
        run_https_server(args.server_ip, args.port)
    elif args.mode == "client":
        run_https_client(args.server_ip, args.port, args.bursts, args.requests)
    elif args.mode == "both":
        stop_event = threading.Event()
        server_thread = threading.Thread(
            target=run_https_server,
            args=(args.server_ip, args.port, stop_event),
            daemon=True
        )
        server_thread.start()
        time.sleep(0.5)
        try:
            run_https_client(args.server_ip, args.port, args.bursts, args.requests)
        finally:
            stop_event.set()
            server_thread.join(timeout=1.0)

if __name__ == "__main__":
    main()
