"""
capture_watcher.py — Testbed Capture Auto-Ingest Service

Bridges Stage 1 (testbed) → Stages 2-4 (backend) by:
  1. Scanning the captures/ directory for PCAP files listed in manifest.json
  2. Ingesting them through the same analysis pipeline as manual uploads
  3. Tracking which captures have already been ingested to avoid duplicates
  4. Optionally watching for new captures via periodic polling

This module is imported lazily to avoid crashing the backend if the
captures/ directory doesn't exist yet (e.g., testbed hasn't been run).
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cryptolens.capture_watcher")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAPTURES_DIR = PROJECT_ROOT / "captures"
MANIFEST_FILENAME = "manifest.json"


class CaptureWatcher:
    """Manages automatic ingest of testbed-generated PCAP captures."""

    def __init__(self, captures_dir: Optional[Path] = None):
        self.captures_dir = captures_dir or DEFAULT_CAPTURES_DIR
        self._ingested_registry: Dict[str, str] = {}  # pcap_file -> job_id

    # ──────────────────────────────────────────────────────────────
    # Manifest access
    # ──────────────────────────────────────────────────────────────

    def _manifest_path(self) -> Path:
        return self.captures_dir / MANIFEST_FILENAME

    def load_manifest(self) -> Dict[str, Any]:
        """Load the testbed ground-truth manifest. Returns empty dict on failure."""
        mpath = self._manifest_path()
        if not mpath.exists():
            logger.warning("Manifest not found at %s", mpath)
            return {}
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Failed to parse manifest: %s", exc)
            return {}

    def list_available_captures(self) -> List[Dict[str, Any]]:
        """
        List all captures from the manifest along with their ingest status.
        Returns a list of dicts suitable for the API response.
        """
        manifest = self.load_manifest()
        captures = manifest.get("captures", [])
        result = []

        for entry in captures:
            pcap_file = entry.get("pcap_file", "")
            pcap_path = self.captures_dir / pcap_file
            already_ingested = pcap_file in self._ingested_registry

            result.append({
                "config_id": entry.get("config_id", "unknown"),
                "pcap_file": pcap_file,
                "exists_on_disk": pcap_path.is_file(),
                "size_bytes": entry.get("size_bytes", 0),
                "packet_count": entry.get("packet_count", 0),
                "ground_truth": entry.get("ground_truth", {}),
                "ingested": already_ingested,
                "job_id": self._ingested_registry.get(pcap_file),
            })

        return result

    # ──────────────────────────────────────────────────────────────
    # Single capture ingest
    # ──────────────────────────────────────────────────────────────

    def ingest_single(
        self, pcap_file: str, pipeline_fn, force: bool = False
    ) -> Dict[str, Any]:
        """
        Ingest a single PCAP from the captures directory.

        Args:
            pcap_file: filename (not full path) of the PCAP inside captures/
            pipeline_fn: callable(job_id, file_path) that runs the analysis pipeline
            force: if True, re-ingest even if already processed

        Returns:
            dict with job_id, status, pcap_file, etc.
        """
        # Generate a testbed-specific job ID for traceability
        config_id = pcap_file.replace(".pcap", "").replace(".pcapng", "")
        job_id = f"testbed_{config_id}"

        from backend.services.result_store import ResultStore
        store = ResultStore()
        if not force and (pcap_file in self._ingested_registry or store.exists(job_id)):
            self._ingested_registry[pcap_file] = job_id
            return {
                "pcap_file": pcap_file,
                "status": "already_ingested",
                "job_id": job_id,
            }

        pcap_path = self.captures_dir / pcap_file
        if not pcap_path.is_file():
            return {
                "pcap_file": pcap_file,
                "status": "file_not_found",
                "error": f"PCAP file not found: {pcap_path}",
            }

        try:
            # Run the analysis pipeline synchronously (same as manual upload).
            # The pipeline_fn is process_pcap_pipeline from routes/analyze.py.
            pipeline_fn(job_id, pcap_path)

            self._ingested_registry[pcap_file] = job_id
            return {
                "pcap_file": pcap_file,
                "status": "completed",
                "job_id": job_id,
            }

        except Exception as exc:
            logger.error("Ingest failed for %s: %s", pcap_file, exc)
            return {
                "pcap_file": pcap_file,
                "status": "failed",
                "error": str(exc),
            }

    # ──────────────────────────────────────────────────────────────
    # Batch ingest
    # ──────────────────────────────────────────────────────────────

    def ingest_all(
        self, pipeline_fn, force: bool = False
    ) -> Dict[str, Any]:
        """
        Ingest ALL captures listed in the manifest.

        Returns a summary dict with per-capture results.
        """
        manifest = self.load_manifest()
        captures = manifest.get("captures", [])

        if not captures:
            return {
                "status": "no_captures",
                "message": "No captures found in manifest.json. Run the testbed first.",
                "results": [],
            }

        results = []
        succeeded = 0
        skipped = 0
        failed = 0

        for entry in captures:
            pcap_file = entry.get("pcap_file", "")
            if not pcap_file:
                continue

            result = self.ingest_single(pcap_file, pipeline_fn, force=force)
            results.append(result)

            if result["status"] == "completed":
                succeeded += 1
            elif result["status"] == "already_ingested":
                skipped += 1
            else:
                failed += 1

        return {
            "status": "completed",
            "total": len(results),
            "succeeded": succeeded,
            "skipped": skipped,
            "failed": failed,
            "results": results,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

    # ──────────────────────────────────────────────────────────────
    # Scan for un-manifested PCAPs (bonus: catches any .pcap files
    # dropped into captures/ outside of run_capture_session.sh)
    # ──────────────────────────────────────────────────────────────

    def scan_untracked_pcaps(self) -> List[str]:
        """Find .pcap files in captures/ that aren't in the manifest."""
        if not self.captures_dir.is_dir():
            return []

        manifest = self.load_manifest()
        known_files = {
            entry.get("pcap_file", "")
            for entry in manifest.get("captures", [])
        }

        untracked = []
        for fpath in self.captures_dir.glob("*.pcap"):
            if fpath.name not in known_files:
                untracked.append(fpath.name)
        for fpath in self.captures_dir.glob("*.pcapng"):
            if fpath.name not in known_files:
                untracked.append(fpath.name)

        return sorted(untracked)

    def get_ingest_status(self) -> Dict[str, Any]:
        """Return current ingest status for all captures."""
        return {
            "captures_dir": str(self.captures_dir),
            "manifest_exists": self._manifest_path().exists(),
            "total_ingested": len(self._ingested_registry),
            "ingested_jobs": dict(self._ingested_registry),
        }
