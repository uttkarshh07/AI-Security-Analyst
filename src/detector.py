from collections import defaultdict
from src.schema import SecurityFinding

WINDOW_MINUTES = 10
MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 10
PASSWORD_SPRAY_USERS = 5
SUCCESS_AFTER_FAILURES = 3


def classify_severity(failure_count: int) -> str:
    if failure_count >= HIGH_THRESHOLD:
        return "High"
    elif failure_count >= MEDIUM_THRESHOLD:
        return "Medium"
    else:
        return "Low"


def detect(events):
    """
    Detect brute-force, password spraying,
    and repeated failed logins.
    """

    failures_by_ip = defaultdict(list)

    for event in events:
        if event["status"] == "LOGIN_FAILED":
            failures_by_ip[event["ip"]].append(event)

    results = []

    for ip, fails in failures_by_ip.items():
        fails.sort(key=lambda event: event["ts"])

        max_in_window = 1
        start = 0

        for end in range(len(fails)):
            while (
                fails[end]["ts"] - fails[start]["ts"]
            ).total_seconds() > WINDOW_MINUTES * 60:
                start += 1

            max_in_window = max(
                max_in_window,
                end - start + 1
            )

        if max_in_window == 1:
            continue

        severity = classify_severity(max_in_window)

        unique_users = len({event["user"] for event in fails})

        if unique_users >= PASSWORD_SPRAY_USERS:
            attack_type = "Password spraying"
        elif max_in_window >= MEDIUM_THRESHOLD:
            attack_type = "Brute-force login attempt"
        else:
            attack_type = "Repeated failed logins"

        results.append(
    SecurityFinding(
        ip_address=ip,
        attack_type=attack_type,
        severity=severity,
        failed_attempts=len(fails),
        max_failures_in_window=max_in_window,
        window_minutes=WINDOW_MINUTES,
        targeted_users=sorted(
            {event["user"] for event in fails}
        ),
        first_seen=fails[0]["ts"],
        last_seen=fails[-1]["ts"],
        evidence=[
            f"{len(fails)} failed login attempts from {ip}",
            f"{len({event['user'] for event in fails})} unique users targeted",
        ],
    )
)

    return sorted(
        results,
        key=lambda result: result.max_failures_in_window,
        reverse=True
    )


def detect_success_after_failures(events):
    """
    Detect a successful login after several failed
    attempts from the same IP and user.
    """

    failures_by_user_ip = defaultdict(list)
    successes = []

    for event in events:
        key = (event["ip"], event["user"])

        if event["status"] == "LOGIN_FAILED":
            failures_by_user_ip[key].append(event)

        elif event["status"] == "LOGIN_SUCCESS":
            successes.append(event)

    findings = []

    for success in successes:
        key = (success["ip"], success["user"])

        previous_failures = [
            failure
            for failure in failures_by_user_ip[key]
            if 0 <= (
                success["ts"] - failure["ts"]
            ).total_seconds() <= WINDOW_MINUTES * 60
        ]

        if len(previous_failures) >= SUCCESS_AFTER_FAILURES:
            findings.append({
                "ip": success["ip"],
                "user": success["user"],
                "attack_type": "Possible account compromise",
                "severity": "High",
                "failed_attempts_before_success": len(previous_failures),
                "successful_login": success["ts"],
            })

    return findings
