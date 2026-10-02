# CryptoLens v2 — Hardening & Verification Context

## 1. Executive Summary & Verification State
CryptoLens v2 is a passive, defense-grade IPsec security-audit platform operating under the strict doctrine of:
**"Zero Decryption, Zero Plaintext Access"**.

All items across **P0 (Runtime Bugs)**, **P1 (Correctness & Claim Integrity)**, and **P2 (Security, Ops, Demo)** have been implemented, verified with comprehensive tests, and recorded.

- **Pytest Suite**: 63/63 tests passing (`tests/test_*.py`)
- **Demo Verification**: 5/5 stages passing in `./scripts/demo_audit.sh`
- **CI Workflow**: Configured in `.github/workflows/ci.yml`
- **Authoritative Target**: strongSwan `swanctl.conf` syntax-checked and isolated netns loaded
- **Evidence Provenance**: Explicit badges for all findings (`ike_sa_init`, `ike_v1_cleartext`, `esp_header_metadata`, `traffic_statistics`, `testbed_config`, `operator_supplied`, `inferred`, `cleartext_on_wire`)

---

## 2. Phase-by-Phase Status & Evidence Table

### P0 — Runtime Bugs
| Item | Description | Status | Evidence |
|---|---|---|---|
| **P0-1** | Cross-thread broadcast: replace `get_event_loop()` with `get_running_loop()`, threadsafe queue, bounded batch flusher (100–250ms). | **Fixed** | `tests/test_p0_cross_thread_broadcast.py::test_sniffer_batched_broadcast_5000_records` (5,000 synthetic records dispatched without loop exceptions). |
| **P0-2** | ESP/NAT-T extraction: Scapy `from scapy.layers.ipsec import ESP`, read `pkt[ESP].spi`/`seq`; parse NAT-T (UDP 4500) non-ESP marker (4 zero bytes) and 1-byte 0xFF keepalive; tshark IPv6 parity (`ipv6.src`, `ipv6.dst`, `ipv6.nxt`). | **Fixed** | `tests/test_p0_esp_extraction.py` (5 tests covering ESP layer extraction, NAT-T non-ESP marker, keepalive filtering, IPv6 extraction, and tshark field flags). |
| **P0-3** | RFC 4303 Anti-Replay Detection: Added `iface` to `ESPPacketRecord`, keying on `(iface, spi, seq)`; 64-bit sliding window with ESN awareness and memory bounding. | **Fixed** | `tests/test_p0_replay_detection.py` (4 tests: true replay yields CRITICAL; multi-interface capture causes 0 false positives; out-of-order within window accepted; ESN rollover). |
| **P0-4** | Non-blocking async handlers: Offloaded blocking I/O (LLM `requests.post`), PyTorch/torchvision, and tshark subprocesses to `asyncio.to_thread` / `run_in_executor`. | **Fixed** | `tests/test_p0_nonblocking_async.py::test_websocket_responsive_during_slow_remediation` (WebSocket ping round-trips < 200ms while 5s mock remediation runs). |
| **P0-5** | Task lifecycle: Explicit handles for inference and simulation tasks, clean `cancel()` + `await`, start idempotent under concurrent calls via `asyncio.Lock`. Rapid stop->start within 2s yields exactly one task. | **Fixed** | `tests/test_p0_task_lifecycle.py::test_rapid_start_stop_idempotency` (asserts exactly one active task under rapid churn). |
| **P0-6** | Pipeline wiring: Rolling loop invokes `AnomalyDetector`, drains `ike_queue` (bounded `deque(maxlen=1000)`), feeds `ScoringEngine`/`ComplianceEngine`, and broadcasts `anomaly_alert` + rolling score. | **Fixed** | `tests/test_p0_pipeline_stages.py` (2 tests validating real detector invocation, IKE draining, and rolling score calculation). |
| **P0-7** | WebSocket endpoint: Clean `await receive_text()` loop with `WebSocketDisconnect` handling; broadcast via per-client bounded queues with `asyncio.wait_for` timeout (500ms); server heartbeat ping every 15-30s. | **Fixed** | `tests/test_p0_websocket_heartbeat.py` (2 tests checking client disconnect handling and slow-client isolation). |
| **P0-8** | Grad-CAM / Integrated Gradients (IG): Cached loaded model via `functools.lru_cache`, tensor output hooks robust to in-place ReLU, hook cleanup in `finally`, target layer named `model.last_conv`. Sequence length interpolated via `F.interpolate`. Shared `preprocess()` using `metrics.json`. IG completeness check ($\sum \text{Attr} \approx f(x) - f(x_0)$). | **Fixed** | `tests/test_p0_saliency.py` (5 tests validating heatmap length, non-negativity, hook cleanup on error, IG completeness tolerance, and preprocess parity). |
| **P0-9** | LLM Client & Air-Gap Flag: Default model `gemini-3.8-flash` via env `GEMINI_MODEL`, `ENABLE_CLOUD_LLM=false` by default for air-gapped security; explicit response fields: `engine_used`, `fallback_reason`, `validation_level`; configurable `OLLAMA_MODEL` (defaulting to MIT/Apache models). | **Fixed** | `tests/test_p0_llm_client.py` (8 tests testing air-gap enforcement, fallback logging, and Ollama configuration). |

---

### P1 — Correctness & Claim Integrity
| Item | Description | Status | Evidence |
|---|---|---|---|
| **P1-1** | Strict remediation validation: `HardenedIPsecConfig` with `extra="forbid"`, approved AEAD ciphers only (`aes256gcm16`, `aes128gcm16`), DH profiles (`nist`: ecp256/ecp384; `cnsa1`: ecp384 only; P-384 labeled CNSA 1.0, not CNSA 2.0; note on PQ ML-KEM-1024 readiness). Rekey time, IDs, and CIDRs validated via `ipaddress`. LLM output never rendered unvalidated. | **Fixed** | `tests/test_p1_remediation_validation.py` (CBC without HMAC rejected, weak DH rejected, hostile injection strings sanitized, Jinja2 template validation). |
| **P1-2** | Loadable configurations: Real body inputs (`local_addrs`, `remote_addrs`, `local_ts`, `remote_ts`, `local_id`, `remote_id`); single Jinja2 rendering path (`StrictUndefined`) emitting complete `swanctl.conf`; `validation_level` = "schema" / "loaded" (verified with `swanctl --load-all` in netns). `ipsec.conf` marked legacy; `xfrm` script marked read-only reference with strongSwan banner. | **Fixed** | `tests/test_p1_remediation_validation.py` (swanctl syntax validator, netns container/ns load test, Jinja2 strictness). |
| **P1-3** | Offline Anomaly Detector: In-request training removed. Offline script `scripts/train_anomaly.py` fits `IsolationForest` on baseline PCAPs, writes weights + SHA-256 manifest. 99.5th percentile threshold on normal data. $k$-of-$n$ (3 of 5) consecutive window filter. Honest labeling: `anomalous_flow (resembles uniform small packets / high-volume / burst)`. VoIP/bulk transfers do not false-alarm. Features log-transformed and z-scored. | **Fixed** | `tests/test_p1_anomaly_detector.py` (6 tests: SHA-256 hash manifest check, FPR < 1.0% on baseline, VoIP & bulk transfer regression pass, $k$-of-$n$ filter, honest labels). |
| **P1-4** | Evidence provenance & honest visibility: `evidence_source` added to all findings (`ike_sa_init`, `ike_v1_cleartext`, `esp_header_metadata`, `traffic_statistics`, `testbed_config`, `operator_supplied`, `inferred`). Cleartext on wire vs decapsulated capture labeled. Separated NIST SP 800-77r1 and CNSA profiles (DH19 passes NIST, fails CNSA). | **Fixed** | `tests/test_p1_provenance_and_dpi.py` (4 tests: scoring findings provenance, rules engine provenance, NIST vs CNSA DH19 alignment). |
| **P1-5** | Sweet32 & Saliency semantics: Deleted `len % 8 == 0` heuristic. Replaced with byte/64-bit block count per SPI vs 32 GiB ($2^{32}$ block) birthday bound. Grad-CAM strictly labeled: explains 1D-CNN traffic classification, NOT crypto vulnerabilities. Relative saliency normalized [0.0, 1.0], raw attribution magnitude, and class probabilities displayed. | **Fixed** | `tests/test_p1_sweet32_saliency.py` (4 tests: 32 GiB birthday bound calculation, relative saliency normalization, semantics disclaimer). |
| **P1-6** | DPI classifier: Replaced string parsing with field dissection (`icmp.type`, `dns.flags.response`, `rtp`, `sip`, `tls`). Zero-byte frames handled at root cause. IPv4/IPv6 parity maintained. | **Fixed** | `tests/test_p1_provenance_and_dpi.py` (DPI dissection and 0-byte frame fix verification). |
| **P1-7** | Frontend & Report Wiring: Stream deduplication keyed on `(stream_id, frame)` with bounded dedupe set. WebSocket reconnect exponential backoff with unmount guard. Virtualized packet log. Heatmap sequence -> frame number mapping. Remediation UI with copy button and validation level badges. Remediation and XAI sections wired into PDF reports with evidence sources. Registered all routers in `main.py` (`/live/simulate`, `target_head`). | **Fixed** | `tests/test_p1_frontend_wiring.py` (4 tests) and `tests/test_end_to_end_pipeline.py` (full PCAP -> score -> XAI -> remediation -> PDF verification). |

---

### P2 — Security, Ops, Demo
| Item | Description | Status | Evidence |
|---|---|---|---|
| **P2-1** | Security surface: API bound to `127.0.0.1` by default. API token auth on `/live/start|stop|simulate` and `/remediate`. Interface validated against Scapy interface list. `job_id` validated as strict UUID/hex. Explicit restrictive CORS. | **Fixed** | `tests/test_p2_security_surface.py` (5 tests covering auth tokens, interface whitelist, job_id validation, CORS headers). |
| **P2-2** | Non-root capabilities: Documented `setcap cap_net_raw+eip` on Python binary in `docs/non_root_capabilities.md`. Sniffer performs raw socket pre-flight and returns 403 Forbidden with remediation commands when unprivileged. Docker configured with `network_mode: host` and `cap_add: [NET_RAW]`. | **Fixed** | `tests/test_p2_non_root.py` and `docs/non_root_capabilities.md`. |
| **P2-3** | Pinned dependencies & CPU-only PyTorch: Locked dependencies in `requirements.txt` with CPU-only wheels (`--extra-index-url https://download.pytorch.org/whl/cpu`). Dockerfile updated for lean non-CUDA builds. User-specific paths (`/home/...`) purged from code and documentation. | **Fixed** | `tests/test_p2_models_cpu.py` (3 tests verifying CPU tensor execution and absence of hardcoded personal paths). |
| **P2-4** | End-to-end Demo Script & Audit: Replaced factually inaccurate claims ("factored" -> "within reach of nation-state precomputation (Logjam)"; P-384 as CNSA 1.0; explicit XAI classification semantics). Added automated 5-stage demonstration script (`scripts/demo_audit.sh`) with live RFC 4303 anti-replay detection and authoritative remediation verification. | **Fixed** | `./scripts/demo_audit.sh` (executes 5/5 stages in < 2 seconds). |

---

## 3. Test Execution Commands

```bash
# Run the entire pytest test suite (63 tests)
./.venv/bin/pytest -v

# Run the 5-stage end-to-end demonstration audit
./scripts/demo_audit.sh

# Run end-to-end PCAP -> Score -> XAI -> Remediation -> PDF pipeline test
./.venv/bin/pytest tests/test_end_to_end_pipeline.py -v
```

---

## 4. Remaining Limitations & Honest Boundaries
1. **Passive Decryption Boundary**: In IKEv2, Child SA transform negotiations, Diffie-Hellman CREATE_CHILD_SA exchanges, and peer identities are encrypted on the wire. When analyzing IKEv2 captures where only `IKE_SA_INIT` is in the clear, Child SA parameters are labeled with evidence source `testbed_config` or `operator_supplied`, never claimed as passively observed.
2. **XAI Attribution Semantics**: Grad-CAM heatmaps highlight temporal burst patterns and packet length signatures that influence the 1D-CNN's mode and traffic classification. They do not attribute cryptographic cipher weaknesses or mathematical flaws.
3. **Anomaly Flow Labeling**: The anomaly detector flags statistical deviations (e.g. high-volume bursts or uniform micro-packet streams). Per-tunnel baselines (EWMA) are required to distinguish benign bulk backups or constant-bitrate VoIP from active exfiltration.
