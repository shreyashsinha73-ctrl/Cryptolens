#!/usr/bin/env python3
"""
verify.py
---------
End-to-end verification script for the IPsec data-plane ML pipeline.

Workflow:
1. Creates a fresh isolated virtual environment.
2. Installs requirements.txt.
3. Runs synth_data.py to generate temporary synthetic session features.
4. Runs dataset.py to validate data loading, parsing, and splitting.
5. Runs train.py for a small number of epochs (default: 10) to verify training loop & ONNX export.
6. Verifies that cnn_mode_traffic.onnx, cnn_mode_traffic.pt, and metrics.json exist and are non-empty.
7. Automatically cleans up all temporary generated directories (synthetic data, weights, venv).

Exits 0 on success, non-zero on failure. Suitable for pre-commit checks and CI.
"""

import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def log_step(step: int, total: int, message: str):
    print(f"\n[{step}/{total}] ===> {message}", flush=True)


def log_ok(message: str):
    print(f"  [OK] {message}", flush=True)


def log_error(message: str):
    print(f"\n[ERROR] {message}", file=sys.stderr, flush=True)


def remove_tree_robust(path: Path, max_retries: int = 5, delay: float = 0.5):
    """Robustly deletes a directory tree, handling Windows read-only and lock quirks."""
    if not path.exists():
        return

    def _handle_remove_readonly(func, p, _):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    for attempt in range(max_retries):
        try:
            shutil.rmtree(path, onerror=_handle_remove_readonly)
            return
        except Exception:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                try:
                    shutil.rmtree(path, ignore_errors=True)
                except Exception:
                    pass


def run_command(cmd: list[str], cwd: Path, env: dict[str, str], step_desc: str):
    print(f"  Running: {' '.join(str(c) for c in cmd)}", flush=True)
    res = subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=False)
    if res.returncode != 0:
        log_error(f"{step_desc} failed with exit code {res.returncode}")
        sys.exit(res.returncode)


def main():
    parser = argparse.ArgumentParser(
        description="Verify engine/data_plane ML pipeline end-to-end."
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=10,
        help="Number of epochs to train for verification (default: 10)",
    )
    parser.add_argument(
        "--configs",
        type=int,
        default=2,
        help="Number of synthetic configs to generate (default: 2)",
    )
    parser.add_argument(
        "--runs-per-combo",
        type=int,
        default=5,
        help="Runs per mode/traffic combo (default: 5)",
    )
    parser.add_argument(
        "--skip-venv",
        action="store_true",
        help="Skip creating a new venv and use current python environment instead",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Do not clean up temporary directories on exit (for debugging)",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    requirements_file = script_dir / "requirements.txt"
    synth_data_script = script_dir / "synth_data.py"
    dataset_script = script_dir / "dataset.py"
    train_script = script_dir / "train.py"

    # Ensure required pipeline files exist
    for f in [requirements_file, synth_data_script, dataset_script, train_script]:
        if not f.is_file():
            log_error(f"Missing required pipeline file: {f}")
            sys.exit(1)

    # Subprocess environment with UTF-8 support (vital on Windows to avoid charmap codec errors)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"

    total_steps = 6 if not args.skip_venv else 5
    current_step = 1

    temp_venv_dir = None
    temp_work_dir = None

    try:
        if args.skip_venv:
            py_exec = Path(sys.executable)
            print(f"Skipping venv creation; using active Python: {py_exec}")
        else:
            log_step(current_step, total_steps, "Creating fresh isolated virtual environment")
            current_step += 1
            temp_venv_dir = Path(tempfile.mkdtemp(prefix="cryptolens_venv_"))
            run_command(
                [sys.executable, "-m", "venv", str(temp_venv_dir)],
                cwd=script_dir,
                env=env,
                step_desc="Virtual environment creation",
            )

            # Locate venv python executable
            if os.name == "nt":
                py_exec = temp_venv_dir / "Scripts" / "python.exe"
            else:
                py_exec = temp_venv_dir / "bin" / "python"

            if not py_exec.exists():
                # Fallback check
                alt_exec = temp_venv_dir / "bin" / "python" if os.name == "nt" else temp_venv_dir / "Scripts" / "python.exe"
                if alt_exec.exists():
                    py_exec = alt_exec
                else:
                    log_error(f"Cannot find python executable in created venv at {py_exec}")
                    sys.exit(1)

            log_ok(f"Virtual environment created at {temp_venv_dir}")

            log_step(current_step, total_steps, "Installing requirements.txt into venv")
            current_step += 1
            run_command(
                [str(py_exec), "-m", "pip", "install", "--no-warn-script-location", "-r", str(requirements_file)],
                cwd=script_dir,
                env=env,
                step_desc="Pip dependency installation",
            )
            log_ok("Requirements installed successfully")

        # Create temporary workspace for synthetic dataset & weights
        temp_work_dir = Path(tempfile.mkdtemp(prefix="cryptolens_work_"))
        synth_data_dir = temp_work_dir / "synth_features"
        weights_dir = temp_work_dir / "weights"

        log_step(current_step, total_steps, f"Generating synthetic dataset via synth_data.py ({args.configs} configs, {args.runs_per_combo} runs/combo)")
        current_step += 1
        run_command(
            [
                str(py_exec),
                str(synth_data_script),
                str(synth_data_dir),
                "--configs",
                str(args.configs),
                "--runs-per-combo",
                str(args.runs_per_combo),
            ],
            cwd=script_dir,
            env=env,
            step_desc="Synthetic data generation",
        )
        log_ok(f"Synthetic dataset generated in {synth_data_dir}")

        log_step(current_step, total_steps, "Validating dataset loading and splits via dataset.py")
        current_step += 1
        run_command(
            [str(py_exec), str(dataset_script), str(synth_data_dir)],
            cwd=script_dir,
            env=env,
            step_desc="Dataset validation",
        )
        log_ok("Dataset inspection and splitting verified")

        log_step(current_step, total_steps, f"Running training loop for {args.epochs} epochs via train.py")
        current_step += 1
        run_command(
            [
                str(py_exec),
                str(train_script),
                str(synth_data_dir),
                "--epochs",
                str(args.epochs),
                "--out-dir",
                str(weights_dir),
            ],
            cwd=script_dir,
            env=env,
            step_desc="Training loop and ONNX export",
        )
        log_ok("Model training and export finished")

        log_step(current_step, total_steps, "Verifying output artifacts existence and integrity")
        metrics_candidate = weights_dir / "metrics.json"
        if not metrics_candidate.exists():
            metrics_candidate = temp_work_dir / "metrics.json"

        expected_artifacts = [
            weights_dir / "cnn_mode_traffic.onnx",
            weights_dir / "cnn_mode_traffic.pt",
            metrics_candidate,
        ]

        missing_or_empty = []
        for art in expected_artifacts:
            if not art.exists():
                missing_or_empty.append(f"{art.name} (DOES NOT EXIST at {art})")
            elif art.stat().st_size == 0:
                missing_or_empty.append(f"{art.name} (FILE IS EMPTY at {art})")
            else:
                log_ok(f"Verified {art.name}: {art.stat().st_size:,} bytes")

        if missing_or_empty:
            log_error("Artifact verification failed:\n  " + "\n  ".join(missing_or_empty))
            sys.exit(1)

        print("\n" + "=" * 70)
        print("  ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
        print("=" * 70)

    finally:
        if not args.keep_temp:
            print("\nCleaning up temporary files...")
            if temp_work_dir and temp_work_dir.exists():
                remove_tree_robust(temp_work_dir)
                print(f"  Removed temporary workspace: {temp_work_dir}")
            if temp_venv_dir and temp_venv_dir.exists():
                remove_tree_robust(temp_venv_dir)
                print(f"  Removed temporary virtual environment: {temp_venv_dir}")
            print("Working tree is clean.")
        else:
            print(f"\n[DEBUG] Kept temporary files:\n  Work: {temp_work_dir}\n  Venv: {temp_venv_dir}")


if __name__ == "__main__":
    main()
