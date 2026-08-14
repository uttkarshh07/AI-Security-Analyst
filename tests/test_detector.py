from datetime import datetime, timedelta

from src.detector import detect, detect_success_after_failures


def test_password_spraying_detection():
    start_time = datetime(2026, 8, 13, 10, 0, 0)

    events = []

    users = ["alice", "bob", "carol", "dave", "eve"]

    for i, user in enumerate(users):
        events.append({
            "ts": start_time + timedelta(seconds=i * 20),
            "status": "LOGIN_FAILED",
            "user": user,
            "ip": "203.0.113.5",
        })

    findings = detect(events)

    assert findings[0].attack_type == "Password spraying"
    assert findings[0].severity == "Medium"
    assert findings[0].max_failures_in_window == 5
    assert len(findings[0].targeted_users) == 5


def test_password_spraying_not_triggered_below_threshold():
    start_time = datetime(2026, 8, 13, 10, 0, 0)

    events = []

    users = ["alice", "bob", "carol", "dave"]

    for i, user in enumerate(users):
        events.append({
            "ts": start_time + timedelta(seconds=i * 20),
            "status": "LOGIN_FAILED",
            "user": user,
            "ip": "203.0.113.5",
        })

    findings = detect(events)

    assert len(findings) == 1
    assert findings[0].attack_type != "Password spraying"


def test_success_after_multiple_failures():
    start_time = datetime(2026, 8, 13, 10, 0, 0)

    events = [
        {
            "ts": start_time,
            "status": "LOGIN_FAILED",
            "user": "alice",
            "ip": "203.0.113.5",
        },
        {
            "ts": start_time + timedelta(seconds=20),
            "status": "LOGIN_FAILED",
            "user": "alice",
            "ip": "203.0.113.5",
        },
        {
            "ts": start_time + timedelta(seconds=40),
            "status": "LOGIN_FAILED",
            "user": "alice",
            "ip": "203.0.113.5",
        },
        {
            "ts": start_time + timedelta(seconds=60),
            "status": "LOGIN_SUCCESS",
            "user": "alice",
            "ip": "203.0.113.5",
        },
    ]

    findings = detect_success_after_failures(events)

    assert len(findings) == 1
    assert findings[0]["attack_type"] == "Possible account compromise"
    assert findings[0]["severity"] == "High"
    assert findings[0]["user"] == "alice"
    assert findings[0]["ip"] == "203.0.113.5"
    assert findings[0]["failed_attempts_before_success"] == 3


def test_success_after_two_failures_not_detected():
    start_time = datetime(2026, 8, 13, 10, 0, 0)

    events = [
        {
            "ts": start_time,
            "status": "LOGIN_FAILED",
            "user": "alice",
            "ip": "203.0.113.5",
        },
        {
            "ts": start_time + timedelta(seconds=20),
            "status": "LOGIN_FAILED",
            "user": "alice",
            "ip": "203.0.113.5",
        },
        {
            "ts": start_time + timedelta(seconds=40),
            "status": "LOGIN_SUCCESS",
            "user": "alice",
            "ip": "203.0.113.5",
        },
    ]

    findings = detect_success_after_failures(events)

    assert len(findings) == 0