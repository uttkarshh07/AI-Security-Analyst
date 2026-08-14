def finding_to_ai_input(finding):
    return {
        "ip_address": finding.ip_address,
        "attack_type": finding.attack_type,
        "severity": finding.severity,
        "failed_attempts": finding.failed_attempts,
        "targeted_users": finding.targeted_users,
        "time_span": f"{finding.window_minutes} minutes",
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "evidence": finding.evidence,
    }