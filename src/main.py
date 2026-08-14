from src.parser import parse_log_line
from src.detector import detect, detect_success_after_failures
from src.reporter import print_report, print_compromise_report
from src.ai_analyst import finding_to_ai_input
from src.ai_client import analyze_finding


if __name__ == "__main__":
    with open("security.log", "r") as file:
        lines = file.readlines()

    events = [
        event
        for line in lines
        if (event := parse_log_line(line))
    ]

    findings = detect(events)
    print_report(findings)

    # AI analysis
    for finding in findings:
        ai_input = finding_to_ai_input(finding)
        analysis = analyze_finding(ai_input)

        print("\n" + "=" * 60)
        print("AI SECURITY ANALYSIS")
        print("=" * 60)

        print(f"\nIncident Summary:\n{analysis.incident_summary}")

        print("\nWhy Suspicious:")
        for reason in analysis.why_suspicious:
            print(f"- {reason}")

        print("\nMITRE ATT&CK:")
        print(f"  Tactic: {analysis.mitre_attack.tactic}")
        print(f"  Technique ID: {analysis.mitre_attack.technique_id}")
        print(f"  Technique: {analysis.mitre_attack.technique}")

        print("\nEvidence:")
        for evidence in analysis.evidence:
            print(f"- {evidence}")

        print(f"\nConfidence: {analysis.confidence}")

        print("\nRecommended Actions:")
        for action in analysis.recommended_actions:
            print(f"- {action}")

    correlation_findings = detect_success_after_failures(events)
    print_compromise_report(correlation_findings)