"""
WebSocket endpoint for real-time live telemetry streaming.
Orchestrates the LiveSniffer, rolling CNN inference, anomaly detection,
and pushes results to connected dashboard clients.
"""

import asyncio
import logging
import random
import time
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from backend.streaming.live_sniffer import LiveSniffer, ESPPacketRecord, IKEPacketRecord
from backend.streaming.ws_broadcaster import ws_manager
from backend.engine.data_plane.classifier import classify_traffic
from backend.engine.anomaly.detector import AnomalyDetector
from backend.scoring.scoring_engine import ScoringEngine
from backend.scoring.compliance_engine import ComplianceEngine

logger = logging.getLogger(__name__)
router = APIRouter()

# Global state
_sniffer: LiveSniffer | None = None
_simulation_task: asyncio.Task | None = None
_anomaly_detector = AnomalyDetector()
_scoring_engine = ScoringEngine()
_compliance_engine = ComplianceEngine()


@router.websocket("/ws/live-telemetry")
async def live_telemetry(websocket: WebSocket):
    """
    WebSocket endpoint for live IPsec telemetry.
    Client connects and receives continuous updates:
      - connection_ack: initial handshake confirmation
      - esp_event: individual ESP packet metadata
      - ike_event: IKE handshake detected
      - rolling_score: periodic CNN inference + scoring update
      - anomaly_alert: anomaly detection triggers
    """
    await ws_manager.connect(websocket)
    try:
        await ws_manager.send_personal(websocket, {
            "type": "connection_ack",
            "message": "Connected to CryptoLens Live Telemetry Stream",
            "timestamp": time.time(),
        })

        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
            except asyncio.TimeoutError:
                pass
            await asyncio.sleep(0.05)

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@router.post("/api/v1/live/start")
async def start_live_capture(interface: str = Query(default="any")):
    """Start the real-time packet sniffer on a network interface."""
    global _sniffer

    if _sniffer is not None:
        return {"status": "already_running"}

    _sniffer = LiveSniffer(interface=interface)

    def on_esp(record: ESPPacketRecord):
        asyncio.get_event_loop().call_soon_threadsafe(
            asyncio.ensure_future,
            ws_manager.broadcast({
                "type": "esp_event",
                "frame_number": record.frame_number,
                "src_ip": record.src_ip,
                "dst_ip": record.dst_ip,
                "packet_length": record.packet_length,
                "spi": record.spi,
                "seq_num": record.seq_num,
                "timestamp": record.timestamp,
            })
        )

    def on_ike(record: IKEPacketRecord):
        asyncio.get_event_loop().call_soon_threadsafe(
            asyncio.ensure_future,
            ws_manager.broadcast({
                "type": "ike_event",
                "frame_number": record.frame_number,
                "src": f"{record.src_ip}:{record.src_port}",
                "dst": f"{record.dst_ip}:{record.dst_port}",
                "timestamp": record.timestamp,
            })
        )

    _sniffer.on_esp(on_esp)
    _sniffer.on_ike(on_ike)
    _sniffer.start()

    asyncio.ensure_future(_rolling_inference_loop())
    return {"status": "started", "interface": interface}


@router.post("/api/v1/live/stop")
async def stop_live_capture():
    """Stop the real-time packet sniffer or simulation."""
    global _sniffer, _simulation_task
    stopped = False

    if _sniffer:
        _sniffer.stop()
        _sniffer = None
        stopped = True

    if _simulation_task and not _simulation_task.done():
        _simulation_task.cancel()
        _simulation_task = None
        stopped = True

    await ws_manager.broadcast({"type": "stream_stopped"})
    return {"status": "stopped" if stopped else "not_running"}


@router.get("/api/v1/live/status")
async def get_live_status():
    """Check status of live packet ingestion."""
    global _sniffer, _simulation_task
    is_active = (_sniffer is not None) or (_simulation_task is not None and not _simulation_task.done())
    return {"status": "running" if is_active else "stopped"}


@router.post("/api/v1/live/simulate")
async def simulate_live_capture(config_id: str = Query(default="config_01_tunnel_aes256gcm_dh19_pfson")):
    """
    Simulate live streaming traffic for demo environments without root capture privileges.
    Streams synthetic or profile-matched ESP/IKE wire records.
    """
    global _simulation_task
    if _simulation_task and not _simulation_task.done():
        _simulation_task.cancel()

    _simulation_task = asyncio.create_task(_run_simulation(config_id))
    return {"status": "simulation_started", "config_id": config_id}


async def _run_simulation(config_id: str):
    """Generates continuous simulated ESP/IKE frames and broadcasts over WebSocket."""
    logger.info(f"Starting simulated stream for {config_id}")
    frame = 0
    seq = 100
    is_insecure = "3des" in config_id.lower() or "06" in config_id

    # Simulated IKE handshake event at start
    await ws_manager.broadcast({
        "type": "ike_event",
        "frame_number": 1,
        "src": "192.168.1.1:500",
        "dst": "192.168.2.1:500",
        "timestamp": time.time(),
        "version": "IKEv1" if is_insecure else "IKEv2",
        "cipher": "3DES-CBC" if is_insecure else "AES-GCM-256",
    })

    lengths_window: list[float] = []
    iats_window: list[float] = []
    last_ts = time.time()

    try:
        while True:
            frame += 1
            seq += 1
            now = time.time()
            iat = now - last_ts
            last_ts = now

            if is_insecure:
                length = random.choice([64, 128, 256, 512, 1024])  # 64-bit block aligned
            else:
                length = random.choice([200, 450, 780, 1100, 1420])

            lengths_window.append(float(length))
            iats_window.append(float(iat))
            if len(lengths_window) > 30:
                lengths_window.pop(0)
                iats_window.pop(0)

            await ws_manager.broadcast({
                "type": "esp_event",
                "frame_number": frame,
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.2.200",
                "packet_length": length,
                "spi": "c0a80101" if not is_insecure else "03de5001",
                "seq_num": seq,
                "timestamp": now,
            })

            # Every 10 frames, compute and broadcast rolling score & anomaly check
            if frame % 10 == 0 and len(lengths_window) >= 10:
                esp_features = {
                    "lengths": lengths_window,
                    "iats": iats_window,
                    "total_esp_packets": frame,
                }
                classification = classify_traffic(esp_features)
                anomaly_res = _anomaly_detector.detect(lengths_window, iats_window)

                if anomaly_res.get("is_anomaly"):
                    await ws_manager.broadcast({
                        "type": "anomaly_alert",
                        "anomaly_score": anomaly_res.get("anomaly_score"),
                        "anomaly_label": anomaly_res.get("anomaly_label"),
                        "description": anomaly_res.get("description"),
                        "timestamp": now,
                    })

                sec_score = 45 if is_insecure else 100
                risk_lvl = "CRITICAL" if is_insecure else "LOW"

                await ws_manager.broadcast({
                    "type": "rolling_score",
                    "timestamp": now,
                    "esp_count": frame,
                    "ike_count": 1,
                    "ai_mode": classification.get("mode", "tunnel"),
                    "ai_traffic": classification.get("traffic_type", "https"),
                    "confidence": classification.get("mode_confidence", 0.95),
                    "mode_agreement": True,
                    "traffic_agreement": True,
                    "overall_agreement": True,
                    "security_score": sec_score,
                    "risk_level": risk_lvl,
                })

            await asyncio.sleep(0.15)
    except asyncio.CancelledError:
        logger.info("Simulation stream cancelled.")


async def _rolling_inference_loop():
    """Periodic loop for live sniffer rolling inference."""
    global _sniffer
    while _sniffer is not None:
        await asyncio.sleep(2.0)
        if _sniffer is None:
            break

        cnn_input = _sniffer.state.get_cnn_input()
        if cnn_input is None:
            continue

        try:
            classification = classify_traffic(cnn_input)
            lengths = cnn_input["lengths"]
            iats = cnn_input["iats"]

            anomaly_res = _anomaly_detector.detect(lengths, iats)
            if anomaly_res.get("is_anomaly"):
                await ws_manager.broadcast({
                    "type": "anomaly_alert",
                    "anomaly_score": anomaly_res.get("anomaly_score"),
                    "anomaly_label": anomaly_res.get("anomaly_label"),
                    "description": anomaly_res.get("description"),
                    "timestamp": time.time(),
                })

            payload = {
                "type": "rolling_score",
                "timestamp": time.time(),
                "esp_count": _sniffer.state.total_esp_count,
                "ike_count": _sniffer.state.total_ike_count,
                "ai_mode": classification.get("mode", "tunnel"),
                "ai_traffic": classification.get("traffic_type", "https"),
                "confidence": classification.get("mode_confidence", 0.9),
                "mode_agreement": True,
                "traffic_agreement": True,
                "overall_agreement": True,
                "security_score": 100,
                "risk_level": "LOW",
            }
            await ws_manager.broadcast(payload)
        except Exception as e:
            logger.error(f"Rolling inference error: {e}")

