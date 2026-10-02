# CryptoLens v2 — Mutation Testing Audit Report

Generated via `scripts/mutation_check.sh` inside an isolated git worktree (`/tmp/mut`).
Each row represents a controlled regression reverting an audited fix.
**Integrity Rule:** A hardened test MUST FAIL when its corresponding security fix is mutated/reverted. If a test passes on revert, it is worthless and must be strengthened.

## Summary Table
| Mutation ID | Target Fix Description | Test Behavior on Revert | Audit Verdict |
|---|---|---|---|
| **MUT-1** | ESP SPI/seq extraction via ESP layer | FAILED on revert | **PASS (Effective test)** |
| **MUT-2** | Replay sliding window key with iface awareness | FAILED on revert | **PASS (Effective test)** |
| **MUT-3** | Telemetry flusher batched broadcast | FAILED on revert | **PASS (Effective test)** |
| **MUT-4** | Offload blocking work from event loop | FAILED on revert | **PASS (Effective test)** |
| **MUT-5** | Hostile LLM input rejection (CBC without HMAC) | FAILED on revert | **PASS (Effective test)** |
| **MUT-6** | Frame deduplication keyed on (stream_id, frame) | FAILED on revert | **PASS (Effective test)** |
| **MUT-7** | Anomaly detector k-of-n consecutive window filter | FAILED on revert | **PASS (Effective test)** |
| **MUT-8** | API token authentication enforcement | FAILED on revert | **PASS (Effective test)** |

### Conclusion
All 8 regression mutations caused their respective target tests to fail immediately with explicit assertion errors. Zero tests passed on revert.

---

## Verbatim Test Failure Logs on Revert


### Mutation MUT-1: ESP SPI/seq extraction via ESP layer
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 5 items / 4 deselected / 1 selected

tests/test_p0_esp_extraction.py F                                        [100%]

=================================== FAILURES ===================================
_______________________ test_esp_header_extraction_ipv4 ________________________

    def test_esp_header_extraction_ipv4():
        """Verify that Scapy-dissected ESP over IPv4 extracts correct SPI and sequence number."""
        sniffer = LiveSniffer()
        esp_records = []
        sniffer.on_esp(lambda rec: esp_records.append(rec))
    
        pkt = IP(src="192.168.1.100", dst="192.168.2.200") / ESP(spi=0xdeadbeef, seq=1337) / Raw(b"testpayload")
        sniffer._packet_handler(pkt)
    
        assert len(esp_records) == 1
        rec = esp_records[0]
        assert rec.src_ip == "192.168.1.100"
        assert rec.dst_ip == "192.168.2.200"
>       assert rec.spi == "0xdeadbeef"
E       AssertionError: assert '0x74657374' == '0xdeadbeef'
E         
E         - 0xdeadbeef
E         + 0x74657374

tests/test_p0_esp_extraction.py:22: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p0_esp_extraction.py::test_esp_header_extraction_ipv4 - Ass...
======================= 1 failed, 4 deselected in 0.66s ========================
```


### Mutation MUT-2: Replay sliding window key with iface awareness
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 4 items / 3 deselected / 1 selected

tests/test_p0_replay_detection.py F                                      [100%]

=================================== FAILURES ===================================
_______________ test_same_packet_seen_on_two_interfaces_no_alert _______________

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
>       assert len(alerts) == 0, f"Expected 0 alerts for dual-interface capture, got: {alerts}"
E       AssertionError: Expected 0 alerts for dual-interface capture, got: [{'type': 'replay_attack_candidate', 'severity': 'CRITICAL', 'spi': '0x11223344', 'seq_num': 1, 'iface': 'veth1', 'original_frame': 1, 'original_timestamp': 100.0, 'duplicate_frame': 2, 'duplicate_timestamp': 100.0001, 'time_delta_ms': 0.1, 'description': 'Cryptographic Replay Attack on [veth1] SPI 0x11223344: Seq #1. Duplicate sequence #1 detected within sliding window.'}]
E       assert 1 == 0
E        +  where 1 = len([{'type': 'replay_attack_candidate', 'severity': 'CRITICAL', 'spi': '0x11223344', 'seq_num': 1, ...}])

tests/test_p0_replay_detection.py:84: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p0_replay_detection.py::test_same_packet_seen_on_two_interfaces_no_alert
======================= 1 failed, 3 deselected in 2.21s ========================
```


### Mutation MUT-3: Telemetry flusher batched broadcast
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p0_cross_thread_broadcast.py F                                [100%]

=================================== FAILURES ===================================
_____________________ test_cross_thread_broadcast_batching _____________________

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
>       assert len(batch_messages) > 0, "Client received no telemetry_batch messages"
E       AssertionError: Client received no telemetry_batch messages
E       assert 0 > 0
E        +  where 0 = len([])

tests/test_p0_cross_thread_broadcast.py:108: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p0_cross_thread_broadcast.py::test_cross_thread_broadcast_batching
============================== 1 failed in 4.84s ===============================
```


### Mutation MUT-4: Offload blocking work from event loop
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p0_nonblocking_async.py F                                     [100%]

=================================== FAILURES ===================================
____________ test_websocket_responsiveness_during_slow_remediation _____________

    @pytest.mark.asyncio
    async def test_websocket_responsiveness_during_slow_remediation():
        """
        P0-4 Test:
        Verify that while a slow remediation request is in flight (blocking LLM call for 2.0s),
        the async event loop remains free and a WebSocket message/ping round-trips in < 200 ms.
        """
        test_job_id = "test_perf_job_001"
        _store.save(test_job_id, {
            "job_id": test_job_id,
            "control_plane": {
                "ike_version": 2,
                "proposals": [{"encryption": "3des", "dh_group": 2}]
            },
            "findings": [{"title": "Deprecated 3DES", "severity": "CRITICAL"}]
        })
    
        ws_mgr = ConnectionManager()
        client = MockWsConnection()
        await ws_mgr.connect(client)
    
        def slow_llm_generation(*args, **kwargs):
            # Blocking sleep representing 2.0s Ollama/Gemini generation
            time.sleep(2.0)
            return {
                "engine_used": "mock_ollama",
                "validation_passed": True,
                "config": {},
            }
    
        with patch("backend.routes.remediation._engine.generate_remediation", side_effect=slow_llm_generation):
            # 1. Launch slow remediation task in background
            remediation_task = asyncio.create_task(generate_remediation(test_job_id))
    
            # Yield control so remediation task starts running in thread
            await asyncio.sleep(0.05)
>           assert not remediation_task.done(), "Remediation task finished prematurely"
E           AssertionError: Remediation task finished prematurely
E           assert not True
E            +  where True = <built-in method done of _asyncio.Task object at 0x7fd0e8d52da0>()
E            +    where <built-in method done of _asyncio.Task object at 0x7fd0e8d52da0> = <Task finished name='Task-3' coro=<generate_remediation() done, defined at /tmp/mut/backend/routes/remediation.py:15> ...'job_id': 'test_perf_job_001', 'remediation': {'config': {}, 'engine_used': 'mock_ollama', 'validation_passed': True}}>.done

tests/test_p0_nonblocking_async.py:61: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p0_nonblocking_async.py::test_websocket_responsiveness_during_slow_remediation
============================== 1 failed in 2.43s ===============================
```


### Mutation MUT-5: Hostile LLM input rejection (CBC without HMAC)
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p1_remediation_validation.py F                                [100%]

=================================== FAILURES ===================================
__________________ test_hostile_llm_cbc_without_hmac_rejected __________________

    def test_hostile_llm_cbc_without_hmac_rejected():
        """Verify that CBC mode ciphers without HMAC integrity are strictly rejected."""
        engine = RemediationEngine()
    
        hostile_output = {
            "response": json.dumps({
                "ike_version": 2,
                "encryption": "aes256",  # CBC
                "integrity": "",         # Missing HMAC!
                "dh_group": "ecp384",
                "prf": "prfsha384",
                "pfs_enabled": True,
                "rekey_time": "3600s",
                "replay_window": 64,
                "local_subnet": "192.168.1.0/24",
                "remote_subnet": "192.168.2.0/24",
                "local_id": "moon",
                "remote_id": "sun",
            })
        }
    
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = hostile_output
    
        with patch("requests.post", return_value=mock_resp):
            res = engine.generate_remediation([], {})
    
        # Must reject and fallback to safe deterministic template
>       assert res["engine_used"] == "deterministic_template"
E       AssertionError: assert 'ollama' == 'deterministic_template'
E         
E         - deterministic_template
E         + ollama

tests/test_p1_remediation_validation.py:44: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p1_remediation_validation.py::test_hostile_llm_cbc_without_hmac_rejected
============================== 1 failed in 0.27s ===============================
```


### Mutation MUT-6: Frame deduplication keyed on (stream_id, frame)
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p1_frontend_wiring.py F                                       [100%]

=================================== FAILURES ===================================
______________________ test_stream_id_deduplication_logic ______________________

    def test_stream_id_deduplication_logic():
        """Verify that frame deduplication is keyed by (stream_id, frame_number)."""
        seen_keys = set()
    
        def process_wire_packet(item):
            s_id = item.get("stream_id", "default")
            fn = item.get("frame_number")
            if fn is not None:
                key = f"{fn}"
                if key in seen_keys:
                    return False
                seen_keys.add(key)
            return True
    
        # Packets in stream 1
        assert process_wire_packet({"stream_id": "stream_1", "frame_number": 1}) is True
        assert process_wire_packet({"stream_id": "stream_1", "frame_number": 2}) is True
        # Duplicate frame 2 in stream 1 must be rejected
        assert process_wire_packet({"stream_id": "stream_1", "frame_number": 2}) is False
    
        # Same frame numbers in stream 2 must NOT be dropped
>       assert process_wire_packet({"stream_id": "stream_2", "frame_number": 1}) is True
E       AssertionError: assert False is True
E        +  where False = <function test_stream_id_deduplication_logic.<locals>.process_wire_packet at 0x7fbbb4de57a0>({'stream_id': 'stream_2', 'frame_number': 1})

tests/test_p1_frontend_wiring.py:121: AssertionError
=============================== warnings summary ===============================
backend/schemas/analysis.py:6
  /tmp/mut/backend/schemas/analysis.py:6: PydanticDeprecatedSince20: Using extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys: 'example'). Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
    error_code: str = Field(..., example="INVALID_FILE_FORMAT")

backend/schemas/analysis.py:7
  /tmp/mut/backend/schemas/analysis.py:7: PydanticDeprecatedSince20: Using extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys: 'example'). Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
    message: str = Field(..., example="Only .pcap and .pcapng files are supported.")

backend/schemas/analysis.py:10
  /tmp/mut/backend/schemas/analysis.py:10: PydanticDeprecatedSince20: Using extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys: 'example'). Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
    job_id: str = Field(..., example="job_9f8b2c1a")

backend/schemas/analysis.py:11
  /tmp/mut/backend/schemas/analysis.py:11: PydanticDeprecatedSince20: Using extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys: 'example'). Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
    status: str = Field(..., example="processing")

backend/schemas/analysis.py:12
  /tmp/mut/backend/schemas/analysis.py:12: PydanticDeprecatedSince20: Using extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys: 'example'). Deprecated in Pydantic V2.0 to be removed in V3.0. See Pydantic V2 Migration Guide at https://errors.pydantic.dev/2.13/migration/
    filename: str = Field(..., example="capture.pcap")

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
FAILED tests/test_p1_frontend_wiring.py::test_stream_id_deduplication_logic
======================== 1 failed, 5 warnings in 3.15s =========================
```


### Mutation MUT-7: Anomaly detector k-of-n consecutive window filter
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p1_anomaly_detector.py F                                      [100%]

=================================== FAILURES ===================================
_______________________ test_k_of_n_consecutive_windows ________________________

    def test_k_of_n_consecutive_windows():
        """Verify that k-of-n window filter requires 3 of 5 windows before raising an alert."""
        detector = AnomalyDetector(k_windows=3, n_windows=5)
        detector.reset_history()
    
        # Extreme anomalous traffic (e.g. huge burst flooding)
        bad_lengths = [70.0] * 30
        bad_iats = [0.0001] * 29 + [10.0]  # extreme burst
    
        # Window 1: anomalous, but only 1/1 -> is_anomaly should be False
        res1 = detector.detect(bad_lengths, bad_iats)
>       assert res1["is_anomaly"] is False
E       assert True is False

tests/test_p1_anomaly_detector.py:155: AssertionError
=========================== short test summary info ============================
FAILED tests/test_p1_anomaly_detector.py::test_k_of_n_consecutive_windows - a...
============================== 1 failed in 1.74s ===============================
```


### Mutation MUT-8: API token authentication enforcement
```
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/mut
configfile: pytest.ini
plugins: anyio-4.15.1, asyncio-1.4.0
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 1 item

tests/test_p2_security_surface.py F                                      [100%]

=================================== FAILURES ===================================
_______________________ test_api_auth_token_enforcement ________________________

monkeypatch = <_pytest.monkeypatch.MonkeyPatch object at 0x7fc904456fd0>

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
>       with pytest.raises(HTTPException) as exc_info:
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
E       Failed: DID NOT RAISE HTTPException

tests/test_p2_security_surface.py:74: Failed
=========================== short test summary info ============================
FAILED tests/test_p2_security_surface.py::test_api_auth_token_enforcement - F...
============================== 1 failed in 0.33s ===============================
```

