import re
from datetime import datetime


LOG_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<status>LOGIN_FAILED|LOGIN_SUCCESS)\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
)


def parse_log_line(line: str):
    """Convert one raw log line into a structured event."""
    match = LOG_PATTERN.search(line)

    if not match:
        return None

    return {
        "ts": datetime.strptime(
            match.group("ts"),
            "%Y-%m-%d %H:%M:%S"
        ),
        "status": match.group("status"),
        "user": match.group("user"),
        "ip": match.group("ip"),
    }
    