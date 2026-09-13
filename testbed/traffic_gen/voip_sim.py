#!/usr/bin/env python3
"""
CryptoLens Traffic Generator - VoIP / SIP Emulation
Emulates real-time voice communications:
1. SIP Call Setup (UDP 5060)
2. RTP Audio Packet Stream (UDP 16384) with 20ms periodic pacing and micro-jitter

Generates the signature fixed-size, constant-interval fingerprint expected by
the data-plane classification engine.
"""

import argparse
import random
import socket
import struct
import sys
import time

try:
    from scapy.all import IP, UDP, Raw, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def build_rtp_header(seq_num: int, timestamp: int, ssrc: int = 0x12345678, payload_type: int = 0) -> bytes:
    """Builds a standard 12-byte RFC 3550 RTP Header (Version 2, G.711 PCMU = PT 0)"""
    byte0 = 0x80  # Version 2, Padding 0, Extension 0, CC 0
    byte1 = payload_type & 0x7F  # Marker 0, Payload Type
    return struct.pack("!BBHII", byte0, byte1, seq_num % 65536, timestamp & 0xFFFFFFFF, ssrc)

def simulate_sip_signaling(src_ip: str, dst_ip: str, sip_port: int = 5060):
    """Sends a lightweight SIP INVITE and ACK packet to simulate call setup"""
    print(f"[voip_sim] Initiating SIP signaling to {dst_ip}:{sip_port}...")
    call_id = f"cryptolens-{random.randint(100000, 999999)}@{src_ip}"
    sip_invite = (
        f"INVITE sip:receiver@{dst_ip}:{sip_port} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src_ip}:{sip_port};branch=z9hG4bK-748392\r\n"
        f"From: <sip:caller@{src_ip}>;tag=19142\r\n"
        f"To: <sip:receiver@{dst_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: 130\r\n\r\n"
        f"v=0\r\no=caller 100 200 IN IP4 {src_ip}\r\ns=Call\r\nc=IN IP4 {src_ip}\r\nt=0 0\r\nm=audio 16384 RTP/AVP 0\r\n"
    ).encode("utf-8")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if src_ip:
            sock.bind((src_ip, sip_port))
        sock.sendto(sip_invite, (dst_ip, sip_port))
        time.sleep(0.05)
        # Send SIP 200 OK / ACK simulation
        sip_ack = f"ACK sip:receiver@{dst_ip}:{sip_port} SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 ACK\r\n\r\n".encode("utf-8")
        sock.sendto(sip_ack, (dst_ip, sip_port))
        sock.close()
        print("[voip_sim] SIP signaling handshake simulated.")
    except Exception as e:
        print(f"[voip_sim] Notice: SIP socket warning (expected if port in use): {e}")

def run_voip_stream(src_ip: str, dst_ip: str, packet_count: int = 50,
                    interval: float = 0.02, payload_bytes: int = 160,
                    dst_port: int = 16384, jitter_ms: float = 2.0):
    """
    Sends RTP voice packets at 20ms intervals with realistic micro-jitter and 160B payload (G.711 standard)
    """
    print(f"[voip_sim] Streaming {packet_count} RTP voice packets -> {dst_ip}:{dst_port}")
    print(f"[voip_sim] Interval: {interval*1000:.1f}ms (jitter: ±{jitter_ms}ms) | Payload: {payload_bytes}B")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src_ip:
        try:
            sock.bind((src_ip, 0))
        except Exception:
            pass

    ssrc = random.randint(1000000, 9999999)
    base_timestamp = 0

    start_stream = time.time()
    for seq in range(packet_count):
        rtp_hdr = build_rtp_header(seq_num=seq, timestamp=base_timestamp, ssrc=ssrc, payload_type=0)
        # 160 bytes of simulated G.711 voice codec audio data (pseudo-random PCM samples)
        audio_payload = bytes([random.randint(0, 255) for _ in range(payload_bytes)])
        packet_data = rtp_hdr + audio_payload

        try:
            sock.sendto(packet_data, (dst_ip, dst_port))
        except Exception as e:
            print(f"[voip_sim] Send error: {e}", file=sys.stderr)
            break

        base_timestamp += 160  # 160 samples per 20ms at 8kHz sample rate

        # Apply 20ms sleep with realistic micro-jitter
        jitter = random.uniform(-jitter_ms, jitter_ms) / 1000.0
        sleep_dur = max(0.001, interval + jitter)
        time.sleep(sleep_dur)

    sock.close()
    elapsed = time.time() - start_stream
    print(f"[voip_sim] Stream finished: {packet_count} packets sent in {elapsed:.3f}s (Avg: {(elapsed/packet_count)*1000:.2f}ms/pkt)")

def main():
    parser = argparse.ArgumentParser(description="CryptoLens VoIP/RTP Traffic Generator")
    parser.add_argument("--src", "-s", default="", help="Source IP address (optional)")
    parser.add_argument("--dst", "-d", default="192.168.2.1", help="Destination IP address across tunnel")
    parser.add_argument("--packets", "-n", type=int, default=50, help="Number of RTP audio packets to send")
    parser.add_argument("--interval", "-i", type=float, default=0.02, help="Nominal packet interval in seconds (default: 0.02 / 20ms)")
    parser.add_argument("--size", "-b", type=int, default=160, help="Audio payload size in bytes (default: 160 for G.711)")
    parser.add_argument("--port", "-p", type=int, default=16384, help="RTP destination UDP port")
    parser.add_argument("--no-sip", action="store_true", help="Skip SIP call setup preamble")
    args = parser.parse_args()

    if not args.no_sip:
        simulate_sip_signaling(args.src, args.dst)
        time.sleep(0.1)

    run_voip_stream(
        src_ip=args.src,
        dst_ip=args.dst,
        packet_count=args.packets,
        interval=args.interval,
        payload_bytes=args.size,
        dst_port=args.port
    )

if __name__ == "__main__":
    main()
