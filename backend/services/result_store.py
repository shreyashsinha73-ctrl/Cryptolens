import json
import logging
from pathlib import Path
from typing import Any, Dict
from backend.services.neon_db import (
    save_analysis_result_to_neon,
    get_analysis_result_from_neon,
    exists_in_neon,
)

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "stored_results"


class ResultStore:
    def __init__(self, results_dir: Path = RESULTS_DIR):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, job_id: str) -> Path:
        if not job_id or ".." in job_id or "/" in job_id or "\\" in job_id or "\0" in job_id:
            raise ValueError(f"Invalid job_id '{job_id}': path traversal or illegal characters detected")
        return self.results_dir / f"{job_id}.json"

    def save(self, job_id: str, result: Dict[str, Any]) -> None:
        result_path = self._get_path(job_id)

        try:
            with result_path.open("w", encoding="utf-8") as file:
                json.dump(result, file, indent=2)
        except Exception as e:
            logger.warning(f"Error saving result to disk for {job_id}: {e}")

        # Cloud persistence (survives Render restarts)
        status = result.get("status", "completed")
        save_analysis_result_to_neon(job_id, result, status)

    def load(self, job_id: str) -> Dict[str, Any]:
        result_path = self._get_path(job_id)

        # 1. Try local filesystem cache
        if result_path.exists():
            try:
                with result_path.open("r", encoding="utf-8") as file:
                    return json.load(file)
            except Exception as e:
                logger.warning(f"Local result file unreadable for {job_id}: {e}")

        # 2. Try persistent cloud storage (Neon DB)
        neon_data = get_analysis_result_from_neon(job_id)
        if neon_data:
            # Rehydrate local cache
            try:
                with result_path.open("w", encoding="utf-8") as file:
                    json.dump(neon_data, file, indent=2)
            except Exception:
                pass
            return neon_data

        raise FileNotFoundError(
            f"No analysis result found for job_id: {job_id}"
        )

    def exists(self, job_id: str) -> bool:
        if self._get_path(job_id).exists():
            return True
        return exists_in_neon(job_id)

    def delete(self, job_id: str) -> None:
        result_path = self._get_path(job_id)

        if result_path.exists():
            result_path.unlink()