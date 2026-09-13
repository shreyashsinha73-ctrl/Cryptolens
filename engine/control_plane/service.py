"""
Control-Plane Service Orchestrator (engine/control_plane/service.py)
Orchestrates demuxing, parsing, and rule evaluation for uploaded captures.
Saves processed job state for the backend API.
"""

import json
import os
from typing import Dict, Any, Optional

from capture.demux import demux_pcap
from engine.control_plane.ike_parser import IkeParser
from engine.control_plane.rules_engine import RulesEngine


JOBS_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".tmp", "jobs")


def run_control_plane_pipeline(
    pcap_path: str,
    job_id: str,
    save_job_cache: bool = True
) -> Dict[str, Any]:
    """
    Executes the full Control-Plane Lead pipeline on an input PCAP.

    1. Demuxes stream into control vs data plane.
    2. Parses IKE control packets into an AST.
    3. Evaluates cryptographic rules and threat matrix.
    4. Caches job record for instant API retrieval.
    """
    # 1. Demux
    demux_res = demux_pcap(pcap_path, save_splits=False)

    # 2. Parse IKE
    parser = IkeParser(pcap_path)
    ast = parser.parse()
    cp_data = ast.get("control_plane")

    # 3. Evaluate Compliance
    rules_engine = RulesEngine(target_standard="nist")
    evaluation = rules_engine.evaluate(cp_data)

    mode_pred = cp_data.get("operating_mode", "Unknown") if cp_data else "Unknown"

    # 4. Construct API-ready response matching AnalysisResultResponse schema
    result: Dict[str, Any] = {
        "job_id": job_id,
        "status": "completed",
        "summary": evaluation["summary"],
        "control_plane": evaluation["control_plane"],
        "data_plane": {
            "detected_traffic": [
                {
                    "traffic_type": "Encrypted ESP",
                    "percentage": 100.0 if demux_res["data_plane"]["packet_count"] > 0 else 0.0,
                    "packet_count": demux_res["data_plane"]["packet_count"],
                    "avg_packet_size_bytes": (
                        int(demux_res["data_plane"]["byte_count"] / demux_res["data_plane"]["packet_count"])
                        if demux_res["data_plane"]["packet_count"] > 0 else 0
                    )
                }
            ],
            "heuristic_mode_prediction": mode_pred,
            "llm_mode_prediction": mode_pred
        },
        "threat_matrix": evaluation["threat_matrix"],
        "demux_telemetry": demux_res
    }


    # 5. Persist job cache
    if save_job_cache:
        os.makedirs(JOBS_CACHE_DIR, exist_ok=True)
        job_file = os.path.join(JOBS_CACHE_DIR, f"{job_id}.json")
        with open(job_file, "w") as f:
            json.dump(result, f, indent=2)

    return result


def get_job_result(job_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves cached job result if available."""
    job_file = os.path.join(JOBS_CACHE_DIR, f"{job_id}.json")
    if os.path.exists(job_file):
        try:
            with open(job_file, "r") as f:
                return json.load(f)
        except Exception:
            return None
    return None

