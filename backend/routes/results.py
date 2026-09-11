import json
import aiofiles
from pathlib import Path
from fastapi import APIRouter, HTTPException, status
from backend.schemas.analysis import AnalysisResultResponse, ErrorResponse

router = APIRouter()

STORED_RESULTS_DIR = Path("backend/stored_results")

@router.get(
    "/results/{job_id}",
    response_model=AnalysisResultResponse,
    responses={404: {"model": ErrorResponse}}
)
async def get_results(job_id: str):
    result_file = STORED_RESULTS_DIR / f"{job_id}.json"
    
    # TEMPORARY FALLBACK for the UI demo or when processing is still incomplete
    if job_id == "job_demo" or not result_file.exists():
        from backend.services.analyzer_provider import AnalyzerProvider
        from backend.scoring.scoring_engine import ScoringEngine
        
        scorer = ScoringEngine()
        provider = AnalyzerProvider()
        
        # Load the mock data directly from the JSON file
        mock_file = Path("backend/mock_data/analysis_input.json")
        if mock_file.exists():
            with open(mock_file, "r") as f:
                analysis_input = json.load(f)
        else:
            raise HTTPException(status_code=500, detail="Mock data file missing.")
        evaluation = scorer.evaluate(analysis_input)
        
        # Calculate total processed packets from data_plane
        processed_packets = sum(item.get("packet_count", 0) for item in analysis_input.get("data_plane", {}).get("detected_traffic", []))
        
        return AnalysisResultResponse(
            job_id=job_id,
            status="completed",
            summary={
                "overall_risk_score": evaluation["score"],
                "risk_level": evaluation["risk_level"],
                "ai_confidence_score": evaluation["ai_confidence"],
                "agreement_flag": evaluation["agreement_flag"],
                "processed_packets": processed_packets
            },
            control_plane=analysis_input["control_plane"],
            data_plane=analysis_input["data_plane"],
            threat_matrix=evaluation["findings"]
        )

    if not result_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "JOB_NOT_FOUND", "message": f"Job ID '{job_id}' does not exist or is still processing."}
        )

    async with aiofiles.open(result_file, "r") as f:
        content = await f.read()
        
    data = json.loads(content)
    return AnalysisResultResponse(**data)