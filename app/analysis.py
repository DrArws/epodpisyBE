from google.cloud import logging_v2
import google.generativeai as genai
from fastapi import HTTPException, Depends

from app.config import get_settings, Settings


def get_generative_model(settings: Settings = Depends(get_settings)) -> genai.GenerativeModel:
    """
    Configures and returns a Gemini generative model.
    """
    api_key = settings.gemini_api_key
    if not api_key:
        raise HTTPException(status_code=500, detail="GEMINI_API_KEY is not configured.")

    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-pro')


def analyze_log_entries(log_entries: list[str], model: genai.GenerativeModel) -> str:
    """
    Analyzes a list of log entries and suggests a fix.
    """
    if not log_entries:
        raise HTTPException(status_code=400, detail="No log entries provided.")

    prompt = f"""The following are log entries from a Cloud Run service.
    Please analyze them and suggest a fix for any errors found.

    Log entries:
    {"".join(log_entries)}
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze logs: {e}")

def get_error_logs(project_id: str, service_name: str, hours: int = 1) -> list[str]:
    """
    Retrieves error logs for a given Cloud Run service.
    """
    client = logging_v2.LoggingServiceV2Client()

    filter_ = f"""
    resource.type="cloud_run_revision"
    resource.labels.service_name="{service_name}"
    severity>=ERROR
    timestamp>="{get_timestamp_for_hours_ago(hours)}"
    """

    try:
        entries = client.list_log_entries(
            resource_names=[f"projects/{project_id}"],
            filter_=filter_,
            page_size=100,  # Adjust as needed
        )
        return [entry.text_payload for entry in entries]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {e}")

def get_timestamp_for_hours_ago(hours: int) -> str:
    """
    Returns a timestamp string for a given number of hours ago.
    """
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    n_hours_ago = now - timedelta(hours=hours)
    return n_hours_ago.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
