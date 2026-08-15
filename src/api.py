from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from src.ai_analyst import finding_to_ai_input
from src.ai_client import analyze_finding
from src.ai_schema import AIAnalysis


app = FastAPI(title="AI Security Analyst API")


class SecurityFindingRequest(BaseModel):
    ip_address: str
    attack_type: str
    severity: str
    failed_attempts: int
    max_failures_in_window: int
    window_minutes: int
    targeted_users: list[str]
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]


@app.post("/analyze", response_model=AIAnalysis)
def analyze_security_finding(finding: SecurityFindingRequest):
    try:
        ai_input = finding_to_ai_input(finding)
        analysis = analyze_finding(ai_input)

        return analysis

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="AI analysis service is currently unavailable."
        ) from exc