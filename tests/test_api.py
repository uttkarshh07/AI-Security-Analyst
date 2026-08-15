from fastapi.testclient import TestClient

from src.api import app
from src.ai_schema import AIAnalysis, MitreAttack


client = TestClient(app)


def mock_ai_analysis():
    return AIAnalysis(
        incident_summary="Password spraying activity detected.",
        why_suspicious=[
            "Multiple user accounts were targeted from a single IP address."
        ],
        mitre_attack=MitreAttack(
            tactic="Credential Access",
            technique_id="T1110.003",
            technique="Password Spraying",
        ),
        evidence=[
            "7 failed login attempts from 203.0.113.5",
            "6 unique users targeted",
        ],
        confidence="High",
        recommended_actions=[
            "Review authentication logs.",
            "Investigate the source IP.",
        ],
    )


def test_analyze_valid_finding(monkeypatch):
    monkeypatch.setattr(
        "src.api.analyze_finding",
        lambda finding: mock_ai_analysis(),
    )

    finding = {
        "ip_address": "203.0.113.5",
        "attack_type": "Password spraying",
        "severity": "Medium",
        "failed_attempts": 7,
        "max_failures_in_window": 7,
        "window_minutes": 10,
        "targeted_users": [
            "alice",
            "bob",
            "carol",
            "dave",
            "eve",
            "frank",
        ],
        "first_seen": "2026-08-13T10:00:01",
        "last_seen": "2026-08-13T10:02:00",
        "evidence": [
            "7 failed login attempts from 203.0.113.5",
            "6 unique users targeted",
        ],
    }

    response = client.post("/analyze", json=finding)

    assert response.status_code == 200

    data = response.json()

    assert "incident_summary" in data
    assert "why_suspicious" in data
    assert "mitre_attack" in data
    assert "evidence" in data
    assert "confidence" in data
    assert "recommended_actions" in data

    assert data["mitre_attack"]["technique_id"] == "T1110.003"


def test_analyze_invalid_finding():
    finding = {
        "ip_address": "203.0.113.5",
        "attack_type": "Password spraying",
        "severity": "Medium",
        "failed_attempts": "seven",
        "max_failures_in_window": 7,
        "window_minutes": 10,
        "targeted_users": ["alice"],
        "first_seen": "2026-08-13T10:00:01",
        "last_seen": "2026-08-13T10:02:00",
        "evidence": [
            "7 failed login attempts",
        ],
    }

    response = client.post("/analyze", json=finding)

    assert response.status_code == 422


def test_analyze_ai_failure(monkeypatch):
    def mock_ai_failure(finding):
        raise Exception("Gemini unavailable")

    monkeypatch.setattr(
        "src.api.analyze_finding",
        mock_ai_failure,
    )

    finding = {
        "ip_address": "203.0.113.5",
        "attack_type": "Password spraying",
        "severity": "Medium",
        "failed_attempts": 7,
        "max_failures_in_window": 7,
        "window_minutes": 10,
        "targeted_users": ["alice", "bob"],
        "first_seen": "2026-08-13T10:00:01",
        "last_seen": "2026-08-13T10:02:00",
        "evidence": [
            "7 failed login attempts from 203.0.113.5",
            "2 unique users targeted",
        ],
    }

    response = client.post("/analyze", json=finding)

    assert response.status_code == 503
    assert response.json() == {
        "detail": "AI analysis service is currently unavailable."
    }