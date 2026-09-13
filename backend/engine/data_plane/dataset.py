"""
dataset.py
----------
Stage: engine/data_plane

Loads the .npz files produced by feature_extract.py into arrays the model
can train on, and implements the two splitting strategies the project doc
calls for:

1. `session_level_split`  - standard train/val/test, split by whole session
   (never by packet), so no session leaks across the boundary.
2. `cross_config_split`   - train on N-1 configs, test on the held-out one,
   to check the model learns the general Tunnel/Transport size signature
   rather than memorizing per-config fingerprints.

Both return the same tuple shape so train.py can use either interchangeably.
"""

import argparse
import random
from pathlib import Path

import numpy as np

from feature_extract import MODE_CLASSES, TRAFFIC_CLASSES


def load_sessions(feature_dir: str):
    """Loads every .npz in feature_dir into a list of dicts."""
    sessions = []
    for npz_path in sorted(Path(feature_dir).glob("*.npz")):
        data = np.load(npz_path, allow_pickle=True)
        sessions.append(
            {
                "session_id": str(data["session_id"]),
                "config_id": str(data["config_id"]),
                "S_L": data["S_L"].astype(np.float32),
                "S_IAT": data["S_IAT"].astype(np.float32),
                "mask": data["mask"].astype(np.float32),
                "mode": str(data["mode"]),
                "traffic_type": str(data["traffic_type"]),
            }
        )
    if not sessions:
        raise SystemExit(f"No .npz feature files found in {feature_dir}")
    return sessions


def to_arrays(sessions):
    """Stacks a list of session dicts into model-ready numpy arrays."""
    X_len = np.stack([s["S_L"] for s in sessions])
    X_iat = np.stack([s["S_IAT"] for s in sessions])
    y_mode = np.array([MODE_CLASSES.index(s["mode"]) for s in sessions], dtype=np.int64)
    y_traffic = np.array(
        [TRAFFIC_CLASSES.index(s["traffic_type"]) for s in sessions], dtype=np.int64
    )
    # 2-channel input: (N, 2, seq_len)
    X = np.stack([X_len, X_iat], axis=1)
    return X, y_mode, y_traffic


def normalize(X_train, *others):
    """
    Z-score normalization fit on train only (leakage-safe), applied to
    train + any other splits passed in. Channel-wise (length vs IAT have
    very different scales).
    """
    mean = X_train.mean(axis=(0, 2), keepdims=True)
    std = X_train.std(axis=(0, 2), keepdims=True) + 1e-6

    def apply(X):
        return (X - mean) / std

    return (apply(X_train),) + tuple(apply(X) for X in others), (mean, std)


def session_level_split(sessions, val_frac=0.15, test_frac=0.15, seed=42):
    """
    Shuffles whole sessions, then splits. Since one .npz == one session,
    this is automatically session-level (no packet ever crosses a split).
    """
    rng = random.Random(seed)
    sessions = sessions[:]
    rng.shuffle(sessions)

    n = len(sessions)
    n_test = max(1, int(n * test_frac))
    n_val = max(1, int(n * val_frac))

    test = sessions[:n_test]
    val = sessions[n_test : n_test + n_val]
    train = sessions[n_test + n_val :]

    if not train:
        raise SystemExit(
            f"Only {n} sessions total - not enough to hold out val/test. "
            "Collect more sessions or lower val_frac/test_frac."
        )
    return train, val, test


def cross_config_split(sessions, held_out_config: str):
    """
    Train on every config except `held_out_config`; test on that config
    alone. No val split here on purpose - this check exists purely to
    answer "did it memorize per-config fingerprints", not for tuning.
    """
    train = [s for s in sessions if s["config_id"] != held_out_config]
    test = [s for s in sessions if s["config_id"] == held_out_config]
    if not test:
        available = sorted({s["config_id"] for s in sessions})
        raise SystemExit(
            f"No sessions found for config_id='{held_out_config}'. "
            f"Available config_ids: {available}"
        )
    if not train:
        raise SystemExit("Held-out config left nothing to train on.")
    return train, [], test


def main():
    ap = argparse.ArgumentParser(description="Inspect the assembled dataset.")
    ap.add_argument("feature_dir")
    ap.add_argument("--held-out-config", default=None)
    args = ap.parse_args()

    sessions = load_sessions(args.feature_dir)
    configs = sorted({s["config_id"] for s in sessions})
    modes = {m: sum(s["mode"] == m for s in sessions) for m in MODE_CLASSES}
    traffic = {t: sum(s["traffic_type"] == t for s in sessions) for t in TRAFFIC_CLASSES}

    print(f"Total sessions: {len(sessions)}")
    print(f"Configs found ({len(configs)}): {configs}")
    print(f"Mode label counts: {modes}")
    print(f"Traffic label counts: {traffic}")

    if args.held_out_config:
        train, _, test = cross_config_split(sessions, args.held_out_config)
        print(f"\nCross-config split: train={len(train)}, held-out test={len(test)}")
    else:
        train, val, test = session_level_split(sessions)
        print(f"\nSession-level split: train={len(train)}, val={len(val)}, test={len(test)}")


if __name__ == "__main__":
    main()
