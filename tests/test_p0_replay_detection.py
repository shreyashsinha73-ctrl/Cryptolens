import time
import pytest

from backend.streaming.live_sniffer import ESPPacketRecord
from backend.engine.xai.threat_localizer import detect_replay_attacks, AntiReplayWindow


def test_true_replay_triggers_critical():
    """Verify that duplicate sequence on the same interface & SPI triggers CRITICAL alert."""
    records = [
        ESPPacketRecord(
            timestamp=100.0,
            frame_number=1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=1,
            iface="eth0",
        ),
        ESPPacketRecord(
            timestamp=100.1,
            frame_number=2,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=2,
            iface="eth0",
        ),
        # Replayed packet #1
        ESPPacketRecord(
            timestamp=100.2,
            frame_number=3,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=1,
            iface="eth0",
        ),
    ]

    alerts = detect_replay_attacks(records, window_size=64)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "CRITICAL"
    assert alert["spi"] == "0x11223344"
    assert alert["seq_num"] == 1
    assert alert["original_frame"] == 1
    assert alert["duplicate_frame"] == 3


def test_same_packet_seen_on_two_interfaces_no_alert():
    """
    Verify that when iface='any' or both veth ends capture the same packet,
    no replay attack alert is raised.
    """
    records = [
        ESPPacketRecord(
            timestamp=100.0,
            frame_number=1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=1,
            iface="veth0",
        ),
        # Same packet traversed across veth1
        ESPPacketRecord(
            timestamp=100.0001,
            frame_number=2,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=1,
            iface="veth1",
        ),
    ]

    alerts = detect_replay_attacks(records, window_size=64)
    assert len(alerts) == 0, f"Expected 0 alerts for dual-interface capture, got: {alerts}"


def test_out_of_order_within_window_no_alert():
    """
    Verify that out-of-order packets arriving within the sliding window
    (e.g. 1, 2, 5, 3, 4) are accepted without false replay alerts.
    """
    seqs = [1, 2, 5, 3, 4]
    records = [
        ESPPacketRecord(
            timestamp=100.0 + idx * 0.01,
            frame_number=idx + 1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=s,
            iface="eth0",
        )
        for idx, s in enumerate(seqs)
    ]

    alerts = detect_replay_attacks(records, window_size=64)
    assert len(alerts) == 0, f"Out-of-order within window should not alert, got {alerts}"


def test_esn_wrap_no_false_alert():
    """
    Verify that 64-bit Extended Sequence Number (ESN) rollover
    (from 0xFFFFFFFE, 0xFFFFFFFF to 1, 2) is handled cleanly without false replay alerts.
    """
    seqs = [0xFFFFFFFE, 0xFFFFFFFF, 1, 2]
    records = [
        ESPPacketRecord(
            timestamp=100.0 + idx * 0.01,
            frame_number=idx + 1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            packet_length=128,
            spi="0x11223344",
            seq_num=s,
            iface="eth0",
        )
        for idx, s in enumerate(seqs)
    ]

    alerts = detect_replay_attacks(records, window_size=64)
    assert len(alerts) == 0, f"ESN wrap should not trigger false replay alert, got {alerts}"
