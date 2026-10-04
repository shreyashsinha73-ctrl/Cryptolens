# CryptoLens Codebase Context for Claude

This file is the operational handoff for an AI coding agent. Treat the code in
the repository as authoritative when it conflicts with older planning material.
Do not infer plaintext, decrypted payloads, or hidden IKEv2 Child SA values from
a packet capture unless the evidence source explicitly supports that claim.

## 1. Project Identity

CryptoLens is a passive, defense-oriented IPsec security audit platform. Its
central security promise is:

> Zero decryption. Zero plaintext access.

It analyzes `.pcap`, `.pcapng`, and `.cap` captures and produces:

- deterministic IKE/control-plane protocol facts when they are observable;
- metadata-only ESP/data-plane mode and traffic classification;
- security scoring and NIST/CNSA compliance evaluation;
- evidence provenance for every assessed field;
- anomaly and replay findings;
- validated remediation configuration suggestions;
- executive/technical PDF reports;
- an interactive React SOC dashboard and live telemetry WebSocket.

The repository is a combined prototype, testbed, backend service, frontend,
model-training workspace, and demonstration harness. It is not a general VPN
implementation and it must never claim to decrypt IPsec traffic.

## 2. Non-Negotiable Domain Boundaries

### Control plane versus data plane

The pipeline deliberately separates facts from inference:

1. IKE negotiation is parsed deterministically using tshark when available,
   with a native Python binary parser as fallback. IKE version, proposals,
   transforms, DH, and some SA properties are extracted from visible packets.
2. ESP payloads remain encrypted. The data-plane path uses only packet lengths,
   timestamps/inter-arrival times, ESP headers, sequence numbers, and other
   wire metadata. It predicts operating mode and inner traffic class; it does
   not identify plaintext content.
3. If IKEv2 Child SA transforms or peer identities are not visible, label them
   `not_observable`, `testbed_config`, `operator_supplied`, or `inferred` as
   appropriate. Never relabel those values as wire-observed facts.

### Evidence and observability

Finding fields should retain both `observability` and `evidence_source`.
Typical evidence sources are:

- `ike_sa_init`: visible IKEv2 initial exchange;
- `ike_v1_cleartext`: visible IKEv1 proposal data;
- `esp_header_metadata`: ESP SPI/sequence/header metadata;
- `traffic_statistics`: statistical data-plane inference;
- `testbed_config`: known lab ground truth, not passive observation;
- `operator_supplied`: validated sidecar supplied by the operator;
- `inferred`: derived rather than directly observed;
- `cleartext_on_wire`: explicit cleartext-on-wire evidence where applicable.

Grad-CAM and Integrated Gradients explain what the 1D CNN used for traffic
classification. They do not explain cryptographic weaknesses or prove a
cipher has been broken.

## 3. System Architecture

```text
strongSwan testbed / uploaded PCAP
              |
              v
capture validation and IKE/ESP demux
       |                      |
       v                      v
deterministic IKE AST     ESP feature extraction
       |                      |
       +----------+-----------+
                  v
        data-plane classifier/anomaly detector
                  |
                  v
        ScoringEngine + ComplianceEngine
          |          |          |
          v          v          v
       ResultStore  PDF      React dashboard
                         + live WebSocket telemetry
```

### Offline PCAP flow

1. `POST /api/v1/analyze` saves the upload under `backend/uploads/` as a safe
   generated job filename and returns `202` with a `job_id`.
2. A FastAPI background task calls `AnalyzerProvider.get_analysis()` in a
   worker thread. The provider invokes `IkeParser` and
   `analyze_data_plane()`.
3. `ScoringEngine.evaluate()` and `ComplianceEngine.evaluate()` consume the
   normalized analysis object.
4. `RemediationEngine` attempts to create a validated remediation payload.
5. The combined result is persisted as JSON by `ResultStore` under
   `backend/stored_results/`.
6. The frontend polls `GET /api/v1/results/{job_id}` until `completed` or
   `failed`, then renders the dashboard and can request a PDF.

### Live flow

`backend/routes/live.py` owns live capture, simulation, injection, and the
WebSocket. `LiveSniffer` receives packets in a capture thread and places them
on a bounded thread-safe queue. `_telemetry_flusher()` drains and batches the
queue every approximately 150 ms. The rolling inference loop periodically
classifies a 30-packet window, runs anomaly detection, and broadcasts score or
alert events. Lifecycle operations are serialized by an `asyncio.Lock` and
tasks are explicitly cancelled and awaited.

## 4. Repository Map

### Top level

- `README.md`: user-facing overview, setup, architecture, and demo commands.
- `context.md`: this agent handoff.
- `CryptoLens_Project_Breakdown.md`: detailed problem decomposition and
  historical/roadmap planning; useful background, not always the current code.
- `CryptoLens_Testing_and_Demo_Plan.md`: extensive validation and demo plan.
- `package.json`, `package-lock.json`: React/Vite frontend dependencies and
  scripts.
- `requirements.txt`: Python runtime dependencies.
- `docker-compose.yml`: testbed, backend, and frontend development services.
- `vite.config.js`: Vite dev server and `/api` and `/ws` proxy to port 8000.
- `pytest.ini`: pytest discovery/configuration.
- `captures/`: checked-in capture metadata/replay sidecars and manifest. Large
  raw captures may also exist under `data/raw_pcaps/` or be generated.
- `scripts/`: demo, training, evaluation, traffic, and integration scripts.
- `tests/`: regression, security, edge-case, mutation, and end-to-end tests.

### Backend

- `backend/main.py`: FastAPI application, CORS, startup logging, and router
  registration. Default host is `127.0.0.1`, port `8000`.
- `backend/routes/analyze.py`: asynchronous upload and full PCAP pipeline.
- `backend/routes/results.py`: persisted job result lookup.
- `backend/routes/report.py`: executive/technical PDF download.
- `backend/routes/capture.py`: list and ingest testbed captures.
- `backend/routes/live.py`: live REST controls, simulation, injection, rolling
  analysis, and `/ws/live-telemetry`.
- `backend/routes/remediation.py`: validated remediation generation.
- `backend/routes/xai.py`: threat localization and saliency endpoint.
- `backend/schemas/analysis.py`: Pydantic contracts for input/output results.
- `backend/schemas/sidecar.py`: operator-supplied metadata schema.
- `backend/capture/pcap_utils.py`: PCAP reader, link/layer parsing, tshark
  binary discovery, and validation.
- `backend/capture/demux.py`: separates IKE/control and ESP/data tracks.
- `backend/engine/control_plane/ike_parser.py`: tshark-first, native-fallback
  IKEv1/IKEv2 parser and normalized control-plane AST.
- `backend/engine/control_plane/rules_engine.py`: control-plane rule evaluation.
- `backend/engine/data_plane/feature_extract.py`: labels, ESP lengths, timing,
  and fixed-length sequences.
- `backend/engine/data_plane/preprocessing.py`: shared normalization using model
  statistics.
- `backend/engine/data_plane/classifier.py`: public `classify_traffic()`
  interface, CNN path, optional cloud LLM path, confidence calibration, and
  label normalization.
- `backend/engine/data_plane/cnn_model.py`: PyTorch 1D CNN architecture. The
  `last_conv` property is the XAI target layer.
- `backend/engine/data_plane/traffic_analyzer.py`: offline data-plane analysis.
- `backend/engine/data_plane/dataset.py`, `train.py`, `verify.py`,
  `build_hybrid_dataset.py`, `synth_data.py`: dataset/training/verification
  tooling.
- `backend/engine/anomaly/`: IsolationForest/PyOD feature engineering,
  detector, weights, metadata, and integrity checks.
- `backend/engine/xai/`: Grad-CAM, Integrated Gradients, threat localization,
  and RFC 4303 anti-replay window logic.
- `backend/engine/llm_client/`: optional Gemini client and Pydantic response
  schema. Cloud use is disabled by default.
- `backend/engine/inference_pipeline.py`: unified CNN/LLM/fallback interface
  and heuristic agreement reporting.
- `backend/scoring/`: weights, compliance mappings, score calculation,
  standards evaluation, and sidecar consistency checks.
- `backend/remediation/`: strict `HardenedIPsecConfig`, configuration diff,
  provider fallback, and Jinja2 templates for swanctl, Cisco, Fortinet, and
  Palo Alto outputs.
- `backend/reporting/generate_pdf.py`: ReportLab report generation.
- `backend/services/analyzer_provider.py`: real/mock analyzer selection and
  sidecar application.
- `backend/services/result_store.py`: JSON result persistence.
- `backend/services/capture_watcher.py`: capture manifest and ingestion helper.
- `backend/streaming/`: WebSocket broadcaster, Scapy/live sniffer, and packet
  injection profiles.
- `backend/mock_data/`: mock analysis input for explicit mock mode only.
- `backend/data/ai_cache.json`: remediation/explainer cache.
- `backend/generated_reports/`, `backend/stored_results/`, `backend/uploads/`:
  runtime/generated data; do not confuse these with source modules.

### Frontend

- `src/main.jsx`: React bootstrap.
- `src/App.jsx`: application composition, upload/testbed ingestion, result
  polling, remediation/report actions, and dashboard state.
- `src/context/ThemeContext.jsx`: theme provider and light/dark state.
- `src/hooks/useLiveTelemetry.js`: WebSocket/live telemetry integration.
- `src/components/dashboard/`: score, compliance, traffic, AI, telemetry,
  heatmap, remediation, executive, and demo views.
- `src/components/soc/`: SOC shell, navigation, alerts, metrics, trends, and
  design-system view.
- `src/components/common/`: shared cards, badges, buttons, and severity chips.
- `src/components/ScoreDial.jsx`, `PerTunnelBreakdown.jsx`, and
  `ConfidenceBar.jsx`: primary assessment widgets.
- `src/data/`, `src/mock/`: UI demo data and impact data.
- `src/lib/grade.js`: frontend grading helpers.
- `src/App.css`, `src/index.css`: global and application styling. The existing
  UI uses Tailwind CSS v4 plus CSS variables and Nunito Sans.

### Testbed

- `testbed/configs/config_matrix.yaml`: six current strongSwan ground-truth
  configurations.
- `testbed/configs/template.swanctl.conf.j2`: templated configuration.
- `testbed/configs/generate_configs.py`: renders peer A/B configs.
- `testbed/docker/`: strongSwan image and network-namespace setup.
- `testbed/run_capture_session.sh`: capture orchestration.
- `testbed/traffic_gen/`: HTTPS, VoIP, and ICMP traffic generators.
- `testbed/replay_test/inject_duplicate_esp.py`: duplicate ESP replay test.
- `testbed/configs/generated/`: generated configs; regenerate rather than hand
  editing them.

## 5. Current Ground-Truth Configurations

The checked-in matrix and capture naming convention cover:

| Config | Mode | Cipher/integrity | DH | PFS |
|---|---|---|---:|---|
| `config_01` | Tunnel | AES-256-GCM | 19 | on |
| `config_02` | Tunnel | AES-128-GCM | 14 | on |
| `config_03` | Tunnel | AES-256-CBC/SHA-256 | 14 | on |
| `config_04` | Transport | AES-128-CBC/SHA-1 | 5 | off |
| `config_05` | Transport | 3DES/SHA-1 | 2 | off |
| `config_06` | Tunnel | 3DES/SHA-1 | 2 | off |

Use `captures/manifest.json`, replay JSON files, sidecars, and
`testbed/configs/config_matrix.yaml` as the ground-truth sources. Do not infer
that every checked-in `.json` is a final API result; some are replay or capture
metadata.

## 6. API Surface

The backend is normally available at `http://localhost:8000` and the frontend
at `http://localhost:5173`. Vite proxies `/api` and `/ws` during development.

### Offline analysis

- `POST /api/v1/analyze`: multipart upload with required `file`; optional
  `sidecar` file or `sidecar_json`. Accepts `.pcap`, `.pcapng`, `.cap` and
  returns `202 {job_id, status, filename, uploaded_at}`.
- `GET /api/v1/results/{job_id}`: processing, completed, or failed result.
- `GET /api/v1/report/{job_id}/pdf?type=executive|technical`: PDF download.
- `POST /api/v1/remediate/{job_id}`: remediation generation for a completed
  result.
- `GET /api/v1/xai/{job_id}`: XAI/threat localization data.

### Capture ingestion

- `GET /api/v1/capture/testbed`: list available testbed captures.
- `POST /api/v1/capture/ingest`: ingest all captures; supports `force`.
- `POST /api/v1/capture/ingest/{config_id}`: ingest one configuration.
- `GET /api/v1/capture/status`: capture/ingestion status.

### Live and streaming

- `GET /ws/live-telemetry`: WebSocket. Client sends JSON `{"type":"ping"}`
  and receives `pong`; server emits `connection_ack`, `stream_started`, packet
  events or `telemetry_batch`, `rolling_score`, `anomaly_alert`, and
  `stream_completed`.
- `POST /api/v1/live/start?interface=any`: real capture; API auth and raw
  socket/tshark capability checks apply.
- `POST /api/v1/live/stop`: stop and await active tasks.
- `POST /api/v1/live/analyze`: submit the recorded live PCAP to the standard
  async analysis pipeline.
- `GET /api/v1/live/status`: live state.
- `POST /api/v1/live/inject/{profile}`: `hardened`, `vulnerable`, `attack`, or
  `weak` demonstration profiles.
- `POST /api/v1/live/simulate`: stream a real uploaded/testbed capture by
  `job_id` or `config_id`.

Live control routes use `API_AUTH_TOKEN` when configured. The code validates
interfaces against available interfaces and validates job/config identifiers.

## 7. Important Data Contracts

The completed result has this shape, defined by `backend/schemas/analysis.py`:

```json
{
  "job_id": "job_ab12cd34",
  "status": "completed",
  "summary": {
    "overall_security_score": 82.0,
    "risk_level": "MODERATE",
    "score_observed_only": 82.0,
    "score_if_unobserved_fail": 70.0,
    "score_if_unobserved_pass": 90.0,
    "score_headline": "...",
    "coverage": "...",
    "coverage_ratio": 0.8,
    "confidence_label": "...",
    "ai_confidence_score": 0.91,
    "agreement_flag": true,
    "processed_packets": 248
  },
  "control_plane": {
    "ike_version": "IKEv2",
    "operating_mode": "Tunnel",
    "encryption_algorithm": "AES-256-GCM",
    "integrity_algorithm": "NONE",
    "dh_group": 19,
    "pfs_enabled": true,
    "key_lifetime_seconds": 28800,
    "replay_protection_enabled": true,
    "observability": {},
    "evidence_source": {}
  },
  "data_plane": {
    "detected_traffic": [],
    "heuristic_mode_prediction": "tunnel",
    "llm_mode_prediction": "tunnel",
    "ai_confidence_score": 0.91,
    "agreement_flag": true
  },
  "score_breakdown": {},
  "threat_matrix": [],
  "compliance": {},
  "pcap_file": "/absolute/path/to/file.pcap",
  "remediation": {}
}
```

`threat_matrix` items contain `finding_id`, `severity`, `category`, `title`,
`description`, `observed_value`, `source`, `evidence_source`, `observability`,
and `provenance`. Missing data is not automatically treated as a security
pass. Scoring exposes observed-only and possible-range values so the UI can be
honest about coverage.

## 8. Model and Analysis Details

### IKE parser

`IkeParser.parse()` tries tshark first, then native decoding. It handles IKEv1
and IKEv2 headers, SA proposals, transform IDs, DH groups, transport-mode
notifications, PFS indicators, lifetimes, and ESN/replay metadata. A capture
without IKE returns `control_plane: null` with an explicit no-IKE error path;
downstream classification must remain metadata-only.

### CNN classifier

The current normal path is `CLASSIFIER_BACKEND=cnn`. The classifier expects
length and IAT sequences, normalizes them to a fixed length of 30, invokes the
ONNX model, and returns:

- mode: `transport`, `tunnel`, or `unknown`;
- traffic: `https`, `voip`, `icmp`, or `unknown`;
- separate mode and traffic confidence;
- backend identifier.

Confidence is capped by per-class validation F1 values from the model's
`metrics.json` when present. Do not display raw softmax confidence as measured
accuracy. The optional cloud Gemini path requires both explicit
`ENABLE_CLOUD_LLM=true` and a key; it is off by default for air-gapped use.

### Anomaly detection and replay

`AnomalyDetector` uses trained IsolationForest artifacts, a SHA-256 manifest,
log/z-score features, and a 3-of-5 consecutive window rule. It labels
statistical anomalies such as bursts, uniform micro-packets, replay attacks,
or a Sweet32 64-bit block surface. An anomaly is not proof of exfiltration.

`AntiReplayWindow` keys observations by interface/SPI/sequence, uses a bounded
64-bit sliding window, supports ESN rollover, and avoids cross-interface false
positives.

### Scoring and compliance

`ScoringEngine` loads `weights_config.yaml` and `compliance_map.yaml`; weights
must total 100. Categories include encryption, integrity, key exchange, PFS,
replay protection, key lifetime, IKE version, and mode. Risk thresholds are:

- score >= 90: `LOW`;
- score >= 75: `MODERATE`;
- score >= 50: `HIGH`;
- below 50: `CRITICAL`.

`ComplianceEngine` loads standard mappings from `compliance_standards.yaml`.
Keep NIST SP 800-77 Rev. 1 and CNSA profiles distinct. P-384/DH20 is labeled
according to the repository's documented CNSA mapping; do not call it CNSA 2.0
PQC. PQC/ML-KEM readiness is a documented future consideration, not current
passive evidence.

### Remediation

`HardenedIPsecConfig` is strict (`extra="forbid"`) and validates identifiers,
CIDRs, rekey times, approved AEAD ciphers, and approved DH profiles. Rendered
templates use Jinja2 `StrictUndefined` and are syntax checked. Never render raw
unvalidated LLM output. Default remediation is deterministic/offline; Ollama
or Gemini are optional explainers/fallbacks.

## 9. Environment and Runtime Configuration

Important environment variables:

- `HOST` / `PORT`: backend bind address and port; default `127.0.0.1:8000`.
- `FRONTEND_ORIGIN`: allowed frontend origin; default localhost:5173.
- `ALLOW_ALL_ORIGINS`: emergency permissive CORS switch; keep false.
- `ANALYZER_MODE`: `real` (default) or `mock`.
- `CLASSIFIER_BACKEND`: `cnn` (default) or optional `llm` path.
- `ENABLE_CLOUD_LLM`: false by default; must be explicit to send metadata out.
- `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_TIMEOUT_SECONDS`.
- `LLM_PROVIDER`, `LLM_FALLBACK_PROVIDER`, `OLLAMA_MODEL`.
- `API_AUTH_TOKEN`: protects live/remediation control operations when set.
- `CONFIG_ID`, `TRAFFIC`, `REPLAY`: Docker testbed selection variables.

Docker Compose has three development services:

- `testbed`: privileged strongSwan capture generation, mounts `testbed/` and
  `captures/`.
- `backend`: host networking, `NET_RAW`/`NET_ADMIN`, port 8000.
- `frontend`: Node 20, port 5173, installs and runs Vite.

Live capture may require tshark or Linux capabilities. The documented non-root
option is `setcap cap_net_raw,cap_net_admin=eip` on the Python executable;
Docker uses `NET_RAW` and `NET_ADMIN`. Never broaden privileges casually.

## 10. Setup and Verification Commands

### Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm install

# Terminal 1
npm run backend

# Terminal 2
npm run dev
```

Requires Linux, Python 3.10+, Node 18+, npm, and preferably `tshark` 3.6+.
The CPU-only PyTorch wheel is recommended:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

### Common checks

```bash
pytest -v -rs tests scripts backend/scripts
./scripts/demo_audit.sh
npm run lint
npm run build
python scripts/test_end_to_end.py
```

The full suite historically reports 76 passed and 1 skipped locally, with the
live `swanctl --load-all` test skipped when no charon VICI socket is available.
The exact count can change as tests evolve. Run the command rather than relying
on this historical number.

Useful focused checks include:

```bash
pytest -q tests/test_p0_pipeline_stages.py
pytest -q tests/test_p0_esp_extraction.py tests/test_p0_replay_detection.py
pytest -q tests/test_p1_remediation_validation.py
pytest -q tests/test_p2_security_surface.py tests/test_p2_non_root.py
pytest -q tests/test_end_to_end_all_configs.py
```

The five-stage `scripts/demo_audit.sh` exercises capture/demux, control-plane
parsing, CNN/XAI, replay detection, and remediation verification. It should be
treated as a real executable audit, not a screenshot fixture.

## 11. Testing Expectations

Tests are organized around failure modes that matter for a security tool:

- P0 runtime behavior: async non-blocking operation, task lifecycle, WebSocket
  heartbeat/broadcasting, ESP/NAT-T extraction, replay detection, pipeline
  stages, saliency, and LLM air-gap behavior.
- P1 correctness/claim integrity: provenance, DPI dissection, anomaly metrics,
  remediation schema validation, Sweet32 semantics, and frontend wiring.
- P2 security/operations: CORS/auth, interface and job validation, non-root
  behavior, CPU model execution, and documentation claims.
- End-to-end: all capture configurations, pipeline/report integration, and
  expected fixture outcomes.
- Mutation checks: selected tests are intentionally strong enough to fail when
  core behavior is reverted.

When changing a shared contract, add or update a focused test before widening
the test run. For parser/scoring changes, verify evidence provenance and missing
data behavior, not just the happy path. For frontend changes, check polling,
WebSocket reconnect, stale job isolation, and empty/failed/loading states.

## 12. Known Limitations and Honest Status

1. Passive analysis cannot recover encrypted IKEv2 Child SA transforms,
   identities, or plaintext. Sidecars and testbed labels are not wire evidence.
2. Data-plane traffic labels are statistical classifications. Padding, timing
   jitter, NAT, fragmentation, and unseen applications can reduce accuracy.
3. The CNN currently covers HTTPS, VoIP, and ICMP labels. Broader traffic
   classes described in planning documents are roadmap scope unless a model and
   validation data for them exist.
4. `swanctl --load-all` requires a running strongSwan charon daemon and VICI
   socket. Offline syntax validation is still useful and is the expected local
   fallback without root/service access.
5. Cloud LLM use is optional and disabled by policy by default. The application
   must remain useful in an air-gapped environment.
6. The repository includes generated artifacts and historical documents. Do
   not claim a planned file, endpoint, metric, or feature exists until you find
   its implementation and a test or executable verification path.

## 13. Safe Change Rules for Claude

- Read the owning abstraction and its nearest test before editing.
- Prefer existing schemas, route helpers, scoring maps, and frontend patterns.
- Keep the zero-decryption boundary and provenance semantics intact.
- Do not silently turn unknown/unobserved values into secure/pass values.
- Do not add credentials, personal absolute paths, generated model artifacts,
  or large capture files unless explicitly required.
- Do not hand-edit generated strongSwan configs; update the matrix/template and
  regenerate them.
- Keep blocking tshark, model, filesystem, and HTTP work off the async event
  loop using the existing thread/offload patterns.
- Preserve bounded queues, bounded dedupe/history collections, task cleanup,
  and slow-client isolation in live code.
- Keep cloud providers opt-in and redact sensitive inputs before explanation.
- Avoid unrelated refactors and do not revert user changes in a dirty worktree.
- After a substantive edit, run the narrowest executable test that can falsify
  the change, then run broader lint/build/tests when the risk warrants it.

## 14. Practical Starting Points

For a new offline analysis bug, start at:

`backend/routes/analyze.py` -> `backend/services/analyzer_provider.py` ->
`backend/engine/control_plane/ike_parser.py` /
`backend/engine/data_plane/traffic_analyzer.py` ->
`backend/scoring/scoring_engine.py` -> `backend/services/result_store.py`.

For a live telemetry bug, start at:

`backend/routes/live.py` -> `backend/streaming/live_sniffer.py` ->
`backend/streaming/ws_broadcaster.py` and the corresponding P0 live tests.

For a dashboard bug, start at `src/App.jsx` or
`src/hooks/useLiveTelemetry.js`, then follow the specific component and the
backend result/event shape it consumes.

For a model or confidence issue, start at
`backend/engine/data_plane/feature_extract.py`,
`preprocessing.py`, `classifier.py`, and `backend/validation_dataset/` before
changing model code.

For remediation/reporting, start at the route, then the engine/schema/template
or PDF builder, and validate hostile/missing fields with the existing P1 tests.
