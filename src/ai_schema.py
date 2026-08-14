from pydantic import BaseModel
from typing import List


class MitreAttack(BaseModel):
    tactic: str
    technique_id: str
    technique: str


class AIAnalysis(BaseModel):
    incident_summary: str
    why_suspicious: List[str]
    mitre_attack: MitreAttack
    evidence: List[str]
    confidence: str
    recommended_actions: List[str]