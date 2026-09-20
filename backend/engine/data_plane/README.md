# Data-plane engine — how to run

## Pipeline order
```
demux.py (Stage 2, ESP-only pcaps)
        │
        ▼
feature_extract.py   →  per-session .npz  (S_L, S_IAT, mask, labels)
        │
        ▼
dataset.py            →  loads .npz, session-level or cross-config split
        │
        ▼
train.py               →  trains DataPlaneCNN, reports metrics, exports ONNX
```

## 0. Before you have real captures: prove the wiring works
```bash
pip install torch scikit-learn scapy onnxscript --break-system-packages

python synth_data.py /tmp/synth_features --configs 6 --runs-per-combo 15
python dataset.py /tmp/synth_features
python train.py /tmp/synth_features --epochs 25 --out-dir weights
```
This generates fake-but-structurally-realistic sessions (same .npz schema
real data will have) so you can confirm feature_extract → dataset → model →
ONNX export all work before spending testbed time. Traffic-type accuracy
should hit ~100% (the synthetic size/timing profiles are very distinct);
mode accuracy will be noisier since the tunnel-overhead offset (~20-40
bytes) is small relative to synthetic per-packet jitter — that's expected
and doesn't mean the code is broken. See the note at the top of
`synth_data.py` if you want to tune this.

## 1. Once real ESP-only pcaps exist (from capture/demux.py)
Name each session file `<config_id>__<traffic_type>__<mode>__<run_idx>.pcap`,
e.g. `cfg03__https__tunnel__002.pcap` — or edit
`feature_extract.parse_label_from_filename()` to match whatever
`run_capture_session.sh` actually emits.

```bash
python feature_extract.py /path/to/esp_pcaps /path/to/features
python dataset.py /path/to/features
python train.py /path/to/features --epochs 30 --out-dir weights
```

## 2. Cross-config generalization check (per the doc's validation methodology)
```bash
python train.py /path/to/features --held-out-config cfg06 --out-dir weights_xconfig
```

## Outputs
- `weights/cnn_mode_traffic.onnx` — matches the path expected in the repo tree
- `weights/cnn_mode_traffic.pt` — raw PyTorch weights, for resuming/debugging
- `metrics.json` — full confusion matrices + per-class precision/recall/F1
  for both heads, written inside `--out-dir` alongside the weights

## Wiring into inference_pipeline.py
`inference_pipeline.py` should load `cnn_mode_traffic.onnx` via `onnxruntime`,
feed it a `(1, 2, 30)` tensor built the same way `feature_extract.py` builds
one (z-scored using the `normalization_mean`/`normalization_std` saved in
`metrics.json` — reuse the *training* stats, don't refit at inference time),
and read off `mode_logits`/`traffic_logits` by argmax. Also surface the
softmax max-probability as the "uncalibrated confidence" your demo script
(Section 7, step 5) displays — the doc is explicit that this confidence
should be labeled uncalibrated, not treated as a true probability.
