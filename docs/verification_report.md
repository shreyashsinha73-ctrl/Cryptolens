# CryptoLens v2 — Independent Verification & Audit Report

## 1. Discarded Work & Transcript Disclosure (Item 1.1)

### 1.1 Incident Analysis
In the previous session, a `git restore .` command was executed after inspecting a dirty working tree that contained unstaged changes across 10 files:
- `.github/workflows/ci.yml`
- `backend/engine/anomaly/detector.py`
- `backend/engine/control_plane/ike_parser.py`
- `scripts/demo_audit.sh`
- `scripts/test_v2_features.py`
- `scripts/train_anomaly.py`
- `tests/test_p0_cross_thread_broadcast.py`
- `tests/test_p1_anomaly_detector.py`
- `tests/test_p1_frontend_wiring.py`
- `tests/test_p1_remediation_validation.py`

### 1.2 Cause of Test Failure Prior to Restore
Before the restore command was run, executing `pytest` produced **1 failure and 71 passes**:
```
backend/scripts/test_control_plane.py:158: AssertionError
AssertionError: Mode mismatch: got Tunnel, expected Transport
assert 'tunnel' == 'transport'
```
**Root Cause:**
The unstaged modifications in the working tree were active regressions/reversions of committed fixes. Specifically, commit `bb0a83e` had introduced detection of IPsec Transport mode via IKEv2 Notify Message Type 16391 (`USE_TRANSPORT_MODE`, RFC 7296 §3.10.1) in both `_parse_with_tshark` and `_parse_native()`. The dirty working tree had reverted `ike_parser.py` to hardcode `"operating_mode": "Tunnel"`, causing Scenario 2 (`legacy_weak_transport_aes128cbc_group2_replayed`) in `test_control_plane_pipeline` to fail.

### 1.3 Transcript-Recovered Diff
Analysis of transcript steps 842 and 844 reveals the exact discarded diff:
```diff
diff --git a/backend/engine/control_plane/ike_parser.py b/backend/engine/control_plane/ike_parser.py
index e7150ed..dae7fe1 100644
--- a/backend/engine/control_plane/ike_parser.py
+++ b/backend/engine/control_plane/ike_parser.py
@@ -127,22 +127,15 @@ class IkeParser:
             "-e", "isakmp.transform.type",
             "-e", "isakmp.transform.id",
             "-e", "isakmp.transform.attr.val",
-            "-e", "isakmp.spis",
-            "-e", "isakmp.notify.msg_type"
+            "-e", "isakmp.spis"
         ]
         proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
         if proc.returncode != 0 or not proc.stdout.strip():
             return None
 
         lines = proc.stdout.strip().splitlines()
-        is_transport = False
         for line in lines:
             parts = line.split("\t")
-            if len(parts) >= 7 and parts[6]:
-                for item in parts[6].split(","):
-                    if item.strip().isdigit() and int(item.strip()) == 16391:
-                        is_transport = True
-
             if len(parts) >= 4:
                 ver_str = parts[0]
                 types_str = parts[2]
@@ -179,7 +172,7 @@ class IkeParser:
                     "engine_used": "tshark",
                     "control_plane": {
                         "ike_version": ike_version,
-                        "operating_mode": "Transport" if is_transport else "Tunnel",
+                        "operating_mode": "Tunnel",
                         "encryption_algorithm": enc,
                         "integrity_algorithm": integ,
                         "dh_group": dh,
@@ -209,8 +202,6 @@ class IkeParser:
         }
 
         proposals_collected = []
-        child_sa_seen = False
-        child_ke_seen = False
 
         for ts, orig_len, pkt_bytes, link_type in reader.iter_packets():
             meta = parse_packet_layers(pkt_bytes, link_type)
@@ -228,8 +219,6 @@ class IkeParser:
 
             major_version = (version_byte >> 4) & 0x0F
             ike_version_str = f"IKEv{major_version}"
-            if major_version == 2 and exchange_type == 36:
-                child_sa_seen = True
 
             # Walk IKE payloads to locate SA (type 33 in IKEv2, type 1 in IKEv1)
             payload_data = ike_payload[28:total_len]
@@ -242,16 +231,6 @@ class IkeParser:
 
                 body = payload_data[4:p_len]
 
-                # Check for Key Exchange in CREATE_CHILD_SA (PFS indicator)
-                if major_version == 2 and exchange_type == 36 and curr_payload_type == 34:
-                    child_ke_seen = True
-
-                # Check for USE_TRANSPORT_MODE Notify (Type 41, Message Type 16391)
-                if curr_payload_type == 41 and len(body) >= 4:
-                    proto_id, spi_sz, msg_type = struct.unpack("!BBH", body[:4])
-                    if msg_type == 16391:
-                        best_control_plane["operating_mode"] = "Transport"
-
                 # IKEv2 SA Payload (Type 33) or IKEv1 SA Payload (Type 1)
                 if (major_version == 2 and curr_payload_type == 33) or (major_version == 1 and curr_payload_type == 1):
                     parsed_sa = self._parse_sa_payload(body, major_version)
@@ -271,9 +250,6 @@ class IkeParser:
                 payload_data = payload_data[p_len:]
                 curr_payload_type = next_p
 
-        if child_sa_seen:
-            best_control_plane["pfs_enabled"] = child_ke_seen
-
         if ike_packets_found == 0:
             return {
                 "parsed_successfully": False,
```

### 1.4 Assessment of Lost Work
Every deleted line in the working copy was an exact rollback of previous commits (`bb0a83e`, `ed473d4`, `3705994`, `3782055`, `23faa5c`, `c8d6bfe`, `e377fcb`). Restoring the working copy to `HEAD` recovered the correct, fully committed codebase. However, invoking `git restore .` without explicit diff disclosure violated auditing rules. Henceforth, all mutation experiments are restricted to isolated external worktrees (`git worktree add /tmp/mut`) without modifying the primary repository tree.

---

## 2. Evidence Integrity & Test Name Verification (Item 1.2)

### 2.1 Audit of Previously Removed Hallucinated Test Names
In earlier summaries and reports from prior passes, 4 test names were cited as "passing evidence" that did not exist in the codebase under those names:

1. **`test_swanctl_netns_load` / "netns container/ns load test"**
   - **Cited for:** P1-2 (Loadable configurations via `swanctl --load-all` in netns)
   - **Actual State:** No netns test existed in `tests/test_p1_remediation_validation.py`. The suite only executed `test_swanctl_syntax_validator`. In Phase A, `test_swanctl_load_execution` was written to honestly check `/var/run/charon.vici` and skip if the charon daemon is inactive.
   - **Status Action:** **Downgraded P1-2 to PARTIAL**. Offline syntax/AST validation passes; live daemon loading requires charon socket access (`sudo systemctl start strongswan`).
2. **`test_websocket_responsive_during_slow_remediation` (5-second mock)**
   - **Cited for:** P0-4 (Non-blocking async handlers under 5s slow LLM call)
   - **Actual State:** The real test in `tests/test_p0_nonblocking_async.py` is `test_websocket_responsiveness_during_slow_remediation`, which uses a 2.0s mock sleep to verify non-blocking threadpool offloading without causing 5s delays in CI.
   - **Status Action:** Verified with `tests/test_p0_nonblocking_async.py::test_websocket_responsiveness_during_slow_remediation` (ping latency < 200ms while slow endpoint executes).
3. **`test_sniffer_batched_broadcast_5000_records`**
   - **Cited for:** P0-1 (Cross-thread broadcast and flusher batching)
   - **Actual State:** The actual test in `tests/test_p0_cross_thread_broadcast.py` is `test_cross_thread_broadcast_batching`. In Phase A, it was strengthened to feed 5,000 synthetic records directly through `_telemetry_queue` and `_telemetry_flusher` into `ws_manager`.
   - **Status Action:** Verified with `tests/test_p0_cross_thread_broadcast.py::test_cross_thread_broadcast_batching`.
4. **`test_rapid_start_stop_idempotency`**
   - **Cited for:** P0-5 (Task lifecycle and idempotent rapid start/stop)
   - **Actual State:** The real test in `tests/test_p0_task_lifecycle.py` is `test_rapid_start_stop_start_lifecycle`.
   - **Status Action:** Verified with `tests/test_p0_task_lifecycle.py::test_rapid_start_stop_start_lifecycle`.

### 2.2 Pytest Collection Verification
Running `./.venv/bin/pytest --collect-only -q tests scripts backend/scripts` collects **exactly 77 tests** (68 in `tests/`, 1 in `scripts/`, 8 in `backend/scripts/`):
- `tests/test_end_to_end_pipeline.py` (1 test)
- `tests/test_p0_cross_thread_broadcast.py` (1 test)
- `tests/test_p0_esp_extraction.py` (5 tests)
- `tests/test_p0_llm_client.py` (8 tests)
- `tests/test_p0_nonblocking_async.py` (1 test)
- `tests/test_p0_pipeline_stages.py` (2 tests)
- `tests/test_p0_replay_detection.py` (4 tests)
- `tests/test_p0_saliency.py` (5 tests)
- `tests/test_p0_task_lifecycle.py` (1 test)
- `tests/test_p0_websocket_heartbeat.py` (2 tests)
- `tests/test_p1_anomaly_detector.py` (8 tests)
- `tests/test_p1_frontend_wiring.py` (6 tests)
- `tests/test_p1_provenance_and_dpi.py` (4 tests)
- `tests/test_p1_remediation_validation.py` (7 tests: 6 passed, 1 skipped)
- `tests/test_p1_sweet32_saliency.py` (4 tests)
- `tests/test_p2_models_cpu.py` (3 tests)
- `tests/test_p2_non_root.py` (1 test)
- `tests/test_p2_security_surface.py` (5 tests)
- `scripts/test_end_to_end.py` (1 test)
- `backend/scripts/test_control_plane.py` (2 tests)
- `backend/scripts/test_part4_integration.py` (6 tests)

Every single cited test name now matches verbatim what pytest collects.

