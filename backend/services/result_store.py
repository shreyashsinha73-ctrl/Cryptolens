import json
from pathlib import Path
from typing import Any, Dict


BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "stored_results"


class ResultStore:
    def __init__(self, results_dir: Path = RESULTS_DIR):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, job_id: str) -> Path:
        return self.results_dir / f"{job_id}.json"

    def save(self, job_id: str, result: Dict[str, Any]) -> None:
        result_path = self._get_path(job_id)

        with result_path.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=2)

    def load(self, job_id: str) -> Dict[str, Any]:
        result_path = self._get_path(job_id)

        if not result_path.exists():
            raise FileNotFoundError(
                f"No analysis result found for job_id: {job_id}"
            )

        with result_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    def exists(self, job_id: str) -> bool:
        return self._get_path(job_id).exists()

    def delete(self, job_id: str) -> None:
        result_path = self._get_path(job_id)

        if result_path.exists():
            result_path.unlink()