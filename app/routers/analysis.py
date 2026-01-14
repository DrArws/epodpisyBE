from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import google.generativeai as genai

from app.analysis import get_error_logs, analyze_log_entries, get_generative_model
from app.auth import get_current_user

router = APIRouter()

class AnalysisRequest(BaseModel):
    project_id: str
    service_name: str
    hours: int = 1

class AnalysisResponse(BaseModel):
    suggestion: str

@router.post("/analyze-errors", response_model=AnalysisResponse)
async def analyze_errors(
    request: AnalysisRequest,
    current_user: dict = Depends(get_current_user),
    model: genai.GenerativeModel = Depends(get_generative_model)
):
    """
    Analyzes error logs for a given Cloud Run service and suggests a fix.
    """
    try:
        logs = get_error_logs(
            project_id=request.project_id,
            service_name=request.service_name,
            hours=request.hours,
        )
        if not logs:
            return {"suggestion": "No error logs found for the specified service and time period."}

        suggestion = analyze_log_entries(logs, model)
        return {"suggestion": suggestion}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
