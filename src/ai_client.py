import json
import os

from dotenv import load_dotenv
from google import genai

from src.ai_schema import AIAnalysis

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def analyze_finding(finding):
    prompt = f"""
You are an AI cybersecurity analyst.

Analyze the structured security finding below.

STRICT RULES:
- Use ONLY the information provided in the security finding.
- Do not invent facts, evidence, users, IP addresses, or events.
- Do not claim an attack succeeded unless the finding provides evidence.
- Do not guess a MITRE ATT&CK mapping when evidence is insufficient.
- If the MITRE mapping is uncertain, clearly state that in the fields.
- Base confidence on the available evidence.
- Recommendations must be defensive and practical.

Return ONLY valid JSON matching the required schema.

Security Finding:
{json.dumps(finding, indent=2, default=str)}
"""

    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=prompt,
        config={
            "response_mime_type": "application/json",
            "response_schema": AIAnalysis,
        },
    )

    return AIAnalysis.model_validate_json(response.text)