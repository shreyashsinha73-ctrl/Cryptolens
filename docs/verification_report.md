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

---

## 3. Continuous Integration Status (Item 1.4)

### 3.1 Status: UNVERIFIED
Item A6 is marked **UNVERIFIED**. A local workflow configuration exists at `.github/workflows/ci.yml`, but no GitHub Actions execution run has occurred on GitHub infrastructure. Per auditing rules, no claim of passing CI may be made without live GitHub Actions execution evidence.

### 3.2 StrongSwan Daemon Initiation Analysis
In headless CI environments (such as Ubuntu GitHub Actions runners), `systemd` is often inactive as PID 1, meaning `sudo systemctl start strongswan` may fail with init errors. The workflow has been updated to employ a multi-tier fallback:
1. `sudo systemctl start strongswan` / `sudo systemctl start strongswan-starter`
2. `sudo ipsec start`
3. Direct daemon execution: `sudo /usr/lib/strongswan/charon &`
4. Polling loop: Wait up to 10 seconds for `/var/run/charon.vici` socket creation.

### 3.3 What to Push
The local repository branch `main` is currently **43 commits ahead of `origin/main`**.
To trigger the GitHub Actions CI run, the following command must be executed by the operator or upon explicit authorization:
```bash
git push origin main
```
Prior to push confirmation, the repository will remain local.

---

## 4. Anomaly Evaluation & Bound Audit (Item 1.5)

### 4.1 Leave-One-File-Out (LOFO) Cross-Validation
Cross-validation was executed across all six authentic baseline PCAP captures. For each fold, the Isolation Forest was trained on the remaining five baseline captures and evaluated on the held-out capture without window overlap. Upper bounds are calculated at 95% confidence using the exact Clopper-Pearson binomial formula:

| Fold | Held-Out PCAP File | Evaluated Windows ($N$) | False Positives ($K$) | Empirical FPR ($K/N$) | 95% Clopper-Pearson Upper Bound | Calibrated Threshold |
|---|---|---|---|---|---|---|
| **Fold 1** | `config_01_tunnel_aes256gcm_dh19_pfson_all.pcap` | 44 | 0 | 0.00% | **8.04%** | 0.0106 |
| **Fold 2** | `config_02_tunnel_aes128gcm_dh14_pfson_all.pcap` | 42 | 0 | 0.00% | **8.41%** | 0.0107 |
| **Fold 3** | `config_03_tunnel_aes256cbc_sha256_dh14_pfson_all.pcap` | 43 | 0 | 0.00% | **8.22%** | 0.0106 |
| **Fold 4** | `config_04_transport_aes128cbc_sha1_dh5_pfsoff_all.pcap` | 44 | 0 | 0.00% | **8.04%** | 0.0105 |
| **Fold 5** | `config_05_transport_3des_sha1_dh2_pfsoff_all.pcap` | 44 | 0 | 0.00% | **8.04%** | 0.0106 |
| **Fold 6** | `config_06_tunnel_3des_sha1_dh2_pfsoff_all.pcap` | 44 | 0 | 0.00% | **8.04%** | 0.0104 |

**Integrity Clarification (No False Claims):**
Although 0 false alarms were observed in each fold, claiming exact zero false positive rate on finite samples ($N=42\dots44$) is mathematically dishonest. As shown above, the 95% Clopper-Pearson upper confidence bound is **8.04% – 8.41%**.

### 4.2 Labeled Anomaly Injection Recall
Three distinct attack profiles were injected into baseline flow feature windows and evaluated against the calibrated model:

| Anomaly Type | Attack Signature Description | Injected Windows | Detected Windows | Detection Recall |
|---|---|---|---|---|
| **Type 1** | Uniform Small Packets (Covert Beaconing: 64B, low jitter) | 44 | 44 | **100.00%** |
| **Type 2** | Sustained High-Rate Large Packets (Exfiltration: 1480B, IAT=0.0005s) | 44 | 44 | **100.00%** |
| **Type 3** | Burst Flooding (Microbursts / DoS: 70B, burst ratio > 15) | 44 | 44 | **100.00%** |

### 4.3 Missing Baseline Traffic Profiles
Audit of authentic baseline PCAPs reveals that testbed captures consist primarily of IKE negotiations, periodic ICMP echoes (162B ESP payloads), and short HTTP handshakes.
**Explicit Limitations / Missing Profiles:**
1. **Continuous VoIP audio streams** (e.g. constant-bitrate G.711 / Opus RTP sessions) are **not present** in baseline PCAPs.
2. **Sustained multi-megabyte bulk TCP transfers** are **not present** in baseline PCAPs.
Rather than fabricating synthetic data into the training set to mask this absence, these missing distributions are explicitly acknowledged as operational boundaries requiring site-specific baseline profiling.

### 4.4 Shipped Model Manifest & Parity
The shipped production model was retrained across all 6 baseline captures and persisted at `backend/engine/anomaly/weights/`:
- `anomaly_iforest.joblib` SHA-256: `cf51f692969ac92316c0406d9cfd4c659ae30fcb945d44b321802edd0b90b751`
- `anomaly_scaler.joblib` SHA-256: `5d3fc133cadca10a197757b843a002bbd87eb04b813cf440bf0565965d62504b`
- Manifest: `backend/engine/anomaly/weights/anomaly_metadata.json`

---

## 5. demo_audit.sh Stage 5 & Host Daemon Audit (Item 1.6)

### 5.1 Host Daemon & Socket Invocation
In previous audit reports (Phase A, item A5), the 5-stage demonstration script `scripts/demo_audit.sh` (backed by `scripts/test_v2_features.py`) was reported as `VERIFIED` in 0.79s.
Adversarial inspection of Stage 5 reveals:
1. Stage 5 generated remediation using `RemediationEngine` and validated syntax using the AST parser (`validate_swanctl_syntax`).
2. Although `/usr/bin/swanctl` is installed on the host (`strongSwan 6.1.0`), strongSwan's background daemon `charon` is **not running**, and the UNIX control socket `/var/run/charon.vici` does not exist in standard non-root development environments.
3. The previous implementation only invoked `swanctl --version` without attempting to load the generated configuration into the daemon, silently masking the absence of live daemon loading.

### 5.2 Corrected Stage 5 Implementation & `--strict` Flag
Stage 5 in `scripts/test_v2_features.py` was updated to:
1. Write the generated `swanctl.conf` to a temporary file.
2. Invoke `/usr/bin/swanctl --load-all --file <temp_path>`.
3. Capture the exact failure message from `swanctl`:
   ```text
   connecting to 'unix:///var/run/charon.vici' failed: No such file or directory
   error: connecting to 'default' URI failed: No such file or directory
   ```
4. Explicitly print:
   `[-] Stage 5 Daemon Loading: SKIPPED (charon daemon socket /var/run/charon.vici not active)`
5. Add a `--strict` command-line argument to `scripts/test_v2_features.py` and forward it from `scripts/demo_audit.sh "$@"`. In `--strict` mode, any skipped stage raises `RuntimeError("Strict mode failure: swanctl daemon load was SKIPPED because charon is not running")` and immediately halts execution with exit code 1.

### 5.3 Correction of Prior Claim (A5 Downgrade)
- **Prior Claim (A5):** VERIFIED (All 5 stages executed end-to-end in 0.79s).
- **Corrected Status (A5):** **PARTIAL**.
- **Justification:** Stages 1–4 are fully VERIFIED on authentic testbed wire frames and PyTorch models. Stage 5 verified Python AST syntax parsing and cipher policy rules, but host kernel/daemon loading into `charon` was skipped due to the inactive `charon.vici` socket. With `--strict`, the script correctly and transparently fails.

---

## 6. Part 2 — "Unknown Must Not Score As Safe" & Wire Observability Verification

### 6.1 Wire Observability Boundary & Taxonomy (Item 2.1)
Under CryptoLens doctrine (*Zero Decryption, Zero Plaintext Access*), unobserved parameters must never score as safe. The system implements a 4-state observability taxonomy:
- `observed`: Directly extracted from cleartext packets on the wire (e.g. IKEv2 `IKE_SA_INIT` Diffie-Hellman group and IKE version; ESP header sequence number / anti-replay; IKEv1 Phase 1 cleartext proposals).
- `operator_supplied`: Explicitly provided by an administrator or auditor via a strictly validated sidecar configuration (`IPsecSidecarConfig`).
- `inferred`: Deduced through traffic flow statistics or unencrypted protocol notification indicators (e.g. Tunnel vs. Transport mode).
- `not_observable`: Encrypted on the wire and inaccessible without cryptographic keys (e.g. IKEv2 Child SA ESP symmetric ciphers, integrity algorithms, Child SA PFS, and SA lifetime).

The engine computes `coverage` as verified controls over total scored controls ($|V|/|C|$) and assigns a `confidence_label` (`HIGH` for $8/8$, `MEDIUM` for $\ge 4/8$, `LOW` for $< 4/8$).

### 6.2 Three-Score Range Formulation (Item 2.2)
To prevent misleading single scores when evaluating partial wire telemetry:
1. **Worst-Case Score (`score_if_unobserved_fail`):** Sum of points for verified controls; unobserved controls are assumed to have failed ($0$ points). This serves as the primary score.
2. **Best-Case Score (`score_if_unobserved_pass`):** Sum of verified points plus full weight points for all unobserved controls.
3. **Observed-Only Score (`score_observed_only`):** Percentage score normalized strictly across the verified control subset.

**Policy Enforcement:**
- Headline score is presented as a range: `"Score_worst–Score_best, coverage V/8"`, e.g. `"35–100, coverage 3/8"`.
- Risk level is clamped to `UNVERIFIED` whenever unobserved controls exist without sidecar provenance.
- Unqualified "100/100" is strictly prohibited when telemetry coverage is partial.
- Applied across `ScoringEngine`, API payloads, executive/technical PDF reports, and the React `ScoreDial`.

### 6.3 Strict Sidecar Configuration Schema (Item 2.3)
Defined in `backend/schemas/sidecar.py` using Pydantic v2:
- Model: `IPsecSidecarConfig` with `model_config = ConfigDict(extra="forbid")`.
- Rejects unexpected/adversarial fields with validation error.
- Enforces physical sanity constraints (e.g. `key_lifetime_seconds >= 60`).
- Seamlessly accepts upload via `/analyze` (`sidecar: UploadFile` or `sidecar_json: Form`), or auto-loads adjacent `<pcap>.sidecar.json`.
- Stamps ingested parameters with `evidence_source = "operator_supplied"` and `observability = "operator_supplied"`.

### 6.4 Verification Test Suite & Raw Execution Output (Item 2.4)
Implemented in `tests/test_p3_observability_scoring.py`:
- `test_config_01_no_sidecar_partial_coverage`: Verifies raw `config_01` PCAP without sidecar produces `coverage: "3/8"`, `risk_level: "UNVERIFIED"`, `score_headline: "35–100, coverage 3/8"`, and primary score `35.0` (not 100).
- `test_config_01_with_operator_sidecar_higher_coverage`: Verifies same capture with sidecar produces `coverage: "8/8"`, `risk_level: "LOW"`, `score_headline: "100/100, coverage 8/8"`, and labels fields `operator_supplied`.
- `test_ikev1_cleartext_proposals_marked_observed`: Crafts synthetic authentic IKEv1 packet with 3DES/SHA1/DH2 proposal; verifies parser and scoring engine mark proposals as `observed` with `evidence_source: "ike_v1_cleartext"`.
- `test_mutation_forcing_full_coverage_fails`: Mutation check proving that forcing coverage=100% or safe risk level without sidecar strictly fails the test assertion.
- `test_strict_sidecar_schema_rejection`: Verifies schema rejection of injected unknown fields and physically implausible SA lifetimes (< 60s).

```text
============================= test session starts ==============================
platform linux -- Python 3.14.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /home/yugpo/Bauna-Appetite/Cryptolens
configfile: pytest.ini
collected 5 items

tests/test_p3_observability_scoring.py::test_config_01_no_sidecar_partial_coverage PASSED [ 20%]
tests/test_p3_observability_scoring.py::test_config_01_with_operator_sidecar_higher_coverage PASSED [ 40%]
tests/test_p3_observability_scoring.py::test_ikev1_cleartext_proposals_marked_observed PASSED [ 60%]
tests/test_p3_observability_scoring.py::test_mutation_forcing_full_coverage_fails PASSED [ 80%]
tests/test_p3_observability_scoring.py::test_strict_sidecar_schema_rejection PASSED [100%]

======================== 5 passed, 5 warnings in 15.47s ========================
```

### 6.5 Part 2 Status Table

| Item | Requirement Description | Status | Evidence |
|---|---|---|---|
| **2.1** | Add observability taxonomy (`observed`, `inferred`, `operator_supplied`, `not_observable`) to every control & finding; compute coverage & confidence | **VERIFIED** | `backend/scoring/scoring_engine.py:33`, `backend/engine/control_plane/ike_parser.py:192`, `tests/test_p3_observability_scoring.py:53-64` |
| **2.2** | Three-value scoring (`score_observed_only`, `score_if_unobserved_fail`, `score_if_unobserved_pass`), headline range, `UNVERIFIED` risk label on partial coverage | **VERIFIED** | `backend/scoring/scoring_engine.py:317-345`, `backend/reporting/generate_pdf.py:360-377`, `src/components/ScoreDial.jsx:157-170` |
| **2.3** | Strict sidecar configuration schema (`IPsecSidecarConfig`, `extra="forbid"`), upload field and JSON ingestion, provenance tracking | **VERIFIED** | `backend/schemas/sidecar.py:5-23`, `backend/routes/analyze.py:110-140`, `backend/services/analyzer_provider.py:89-109` |
| **2.4** | Tests that must be able to fail: (a) raw PCAP partial coverage; (b) PCAP + sidecar; (c) IKEv1 cleartext proposals; (d) mutation check; (e) strict schema rejection | **VERIFIED** | `tests/test_p3_observability_scoring.py` (5/5 PASSED, 15.47s) |
| **2.5** | Add `docs/observability.md` defining protocol wire visibility boundaries; align dashboard, PDF, and demo scripts | **VERIFIED** | `docs/observability.md` (112 lines), `backend/reporting/generate_pdf.py:518-568`, `npm run build` (built in 876ms) |

## 7. Retired Obsolete Tests & Replacements

With the implementation of the Prompt 05 AI Explainer architecture, the deterministic `RemediationEngine` is established as the sole authority for IPsec configuration parameters (`HardenedIPsecConfig`), while the LLM solely generates human-readable explanations and translation drafts. The obsolete tests that exercised the legacy LLM config-generation path have been retired with `@pytest.mark.skip` and replaced by comprehensive verification in `tests/test_ai_explainer.py`:

| Retired Test Name | Source File | Replacement Test / Coverage |
|---|---|---|
| `test_airgap_disabled_fallback_to_template` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_missing_api_key_falls_back_to_template_with_reason`, `test_config_values_identical_with_explainer_on_or_off` |
| `test_ollama_success_no_fallback` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_mock_http_outbound_body_contains_zero_sensitive_data` |
| `test_gemini_success_when_cloud_enabled` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_mock_http_outbound_body_contains_zero_sensitive_data` |
| `test_bad_api_key_fallback` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_missing_api_key_falls_back_to_template_with_reason` |
| `test_timeout_fallback` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_primary_failover_to_secondary_on_429`, `test_both_providers_fail_falls_back_to_deterministic_template` |
| `test_malformed_json_fallback` | `tests/test_p0_llm_client.py` | `tests/test_ai_explainer.py::test_guard_rejects_extra_unapproved_schema_keys`, `validate_explainer_output` |
| `test_hostile_llm_cbc_without_hmac_rejected` | `tests/test_p1_remediation_validation.py` | `tests/test_ai_explainer.py::test_guard_rejects_unapproved_hostile_ciphers` |
| `test_hostile_llm_weak_dh_group_rejected` | `tests/test_p1_remediation_validation.py` | `tests/test_ai_explainer.py::test_guard_rejects_unapproved_hostile_ciphers` |
| `test_hostile_llm_injection_characters_rejected` | `tests/test_p1_remediation_validation.py` | `tests/test_ai_explainer.py::test_guard_rejects_links_urls_and_html`, `test_guard_rejects_code_fences` |





