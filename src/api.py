from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.ai_analyst import finding_to_ai_input
from src.ai_client import analyze_finding
from src.ai_schema import AIAnalysis
from src.detector import detect, detect_success_after_failures
from src.parser import parse_log_line
from src.schema import SecurityFinding


app = FastAPI(title="AI Security Analyst API")


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "security.log"


# =========================================================
# REQUEST SCHEMA
# =========================================================

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


# =========================================================
# HELPERS
# =========================================================

def load_security_events():
    """
    Read security.log and convert each valid line
    into a structured event using the existing parser.
    """

    if not LOG_FILE.exists():
        raise FileNotFoundError(
            f"Security log not found: {LOG_FILE}"
        )

    events = []

    with LOG_FILE.open(
        "r",
        encoding="utf-8"
    ) as log_file:

        for line in log_file:
            event = parse_log_line(line)

            if event is not None:
                events.append(event)

    return events


def severity_status(severity: str) -> str:
    """
    Convert detector severity into a dashboard-friendly
    status.
    """

    if severity == "High":
        return "Needs Review"

    if severity == "Medium":
        return "Investigating"

    return "Monitoring"


def analyze_security_finding(
    finding: SecurityFinding,
):
    """
    Send an existing SecurityFinding through the
    existing AI Analyst / Gemini pipeline.
    """

    ai_input = finding_to_ai_input(finding)

    return analyze_finding(ai_input)


def build_normal_incident(
    finding: SecurityFinding,
):
    """
    Convert a SecurityFinding + AIAnalysis into the
    structure expected by the React dashboard.
    """

    ai_analysis = None

    try:
        ai_analysis = analyze_security_finding(
            finding
        )

    except Exception:
        # Keep the detector result available even if
        # the AI service temporarily fails.
        ai_analysis = None

    return {
        "id": str(uuid4()),

        "securityFinding": {
            "ip_address": finding.ip_address,
            "attack_type": finding.attack_type,
            "severity": finding.severity,
            "failed_attempts": finding.failed_attempts,
            "max_failures_in_window": (
                finding.max_failures_in_window
            ),
            "window_minutes": finding.window_minutes,
            "targeted_users": finding.targeted_users,
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
            "evidence": finding.evidence,
        },

        "aiAnalysis": (
            ai_analysis.model_dump()
            if isinstance(
                ai_analysis,
                AIAnalysis
            )
            else None
        ),

        "status": severity_status(
            finding.severity
        ),
    }


def build_compromise_incident(
    compromise: dict,
):
    """
    Convert the detector's possible-compromise
    result into the same dashboard structure.

    The detector logic itself is NOT modified.
    """

    successful_login = compromise[
        "successful_login"
    ]

    failed_attempts = compromise[
        "failed_attempts_before_success"
    ]

    ip_address = compromise["ip"]
    user = compromise["user"]

    # Create a SecurityFinding representation so that
    # the existing AI Analyst can analyze it too.
    finding = SecurityFinding(
        ip_address=ip_address,
        attack_type="Possible account compromise",
        severity=compromise["severity"],
        failed_attempts=failed_attempts,
        max_failures_in_window=failed_attempts,
        window_minutes=10,
        targeted_users=[user],
        first_seen=successful_login,
        last_seen=successful_login,
        evidence=[
            (
                f"{failed_attempts} failed login attempts "
                f"from {ip_address} for user {user}"
            ),
            (
                "A successful login occurred after "
                "multiple failed attempts"
            ),
        ],
    )

    ai_analysis = None

    try:
        ai_analysis = analyze_security_finding(
            finding
        )

    except Exception:
        ai_analysis = None

    return {
        "id": str(uuid4()),

        "securityFinding": {
            "ip_address": ip_address,
            "attack_type": (
                "Possible Account Compromise"
            ),
            "severity": compromise["severity"],
            "failed_attempts": failed_attempts,
            "max_failures_in_window": failed_attempts,
            "window_minutes": 10,
            "targeted_users": [user],
            "first_seen": successful_login.isoformat(),
            "last_seen": successful_login.isoformat(),
            "evidence": finding.evidence,
        },

        "aiAnalysis": (
            ai_analysis.model_dump()
            if isinstance(
                ai_analysis,
                AIAnalysis
            )
            else None
        ),

        "status": "Needs Review",

        "possible_compromise": {
            "user": user,
            "source_ip": ip_address,
            "failed_attempts_before_success": (
                failed_attempts
            ),
            "successful_login_time": (
                successful_login.isoformat()
            ),
        },
    }


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AI Security Analyst API",
    }


# =========================================================
# GET SECURITY FINDINGS
# =========================================================

@app.get("/findings")
def get_security_findings():
    """
    Run the existing security pipeline against
    security.log and return dashboard-ready incidents.

    Parser and detector logic are reused as-is.
    """

    try:
        events = load_security_events()

        if not events:
            return []

        # Existing detector logic.
        findings = detect(events)

        # Existing possible-compromise detector.
        compromises = detect_success_after_failures(
            events
        )

        incidents = []

        # Convert normal SecurityFinding results.
        for finding in findings:
            incidents.append(
                build_normal_incident(finding)
            )

        # Convert possible compromise results.
        for compromise in compromises:
            incidents.append(
                build_compromise_incident(
                    compromise
                )
            )

        # Newest incidents first.
        incidents.sort(
            key=lambda incident: (
                incident["securityFinding"][
                    "last_seen"
                ]
            ),
            reverse=True,
        )

        return incidents

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=500,
            detail="Security log file is unavailable.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to load security findings.",
        ) from exc


# =========================================================
# EXISTING AI ANALYSIS ENDPOINT
# =========================================================

@app.post(
    "/analyze",
    response_model=AIAnalysis
)
def analyze_security_finding_endpoint(
    finding: SecurityFindingRequest,
):
    """
    Analyze one SecurityFinding using the existing
    Gemini / AI Analyst pipeline.
    """

    try:
        ai_input = finding_to_ai_input(
            finding
        )

        analysis = analyze_finding(
            ai_input
        )

        return analysis

    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "AI analysis service is currently "
                "unavailable."
            ),
        ) from exc