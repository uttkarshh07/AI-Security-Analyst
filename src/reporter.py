def print_report(findings):
    if not findings:
        print("No suspicious activity detected.")
        return

    print("=" * 60)
    print("SUSPICIOUS ACTIVITY REPORT")
    print("=" * 60)

    for finding in findings:
        print(f"\nIP: {finding.ip_address}")
        print(f"  Attack type       : {finding.attack_type}")
        print(f"  Severity          : {finding.severity}")
        print(
            f"  Failures in window: "
            f"{finding.max_failures_in_window} "
            f"(within {finding.window_minutes} min)"
        )
        print(f"  Total failures    : {finding.failed_attempts}")
        print(
            f"  Targeted users    : "
            f"{', '.join(finding.targeted_users)}"
        )
        print(
            f"  Time span         : "
            f"{finding.first_seen} -> {finding.last_seen}"
        )
        print(
            f"  Evidence          : "
            f"{'; '.join(finding.evidence)}"
        )
def print_compromise_report(findings):
    if not findings:
        print("\nNo possible account compromise detected.")
        return

    print("\n" + "=" * 60)
    print("POSSIBLE ACCOUNT COMPROMISE REPORT")
    print("=" * 60)

    for finding in findings:
        print(f"\nIP: {finding['ip']}")
        print(f"  User              : {finding['user']}")
        print(f"  Attack type       : {finding['attack_type']}")
        print(f"  Severity          : {finding['severity']}")
        print(
            f"  Failed attempts  : "
            f"{finding['failed_attempts_before_success']}"
        )
        print(
            f"  Successful login : "
            f"{finding['successful_login']}"
        )