# AI Security Analyst

AI Security Analyst is a security-focused project designed to analyze authentication logs and identify suspicious login activity.

The system parses raw security logs into structured events and analyzes authentication failures to detect common attack patterns such as **repeated failed logins, brute-force login attempts, and password spraying**. It also correlates failed and successful login attempts to identify potential **account compromise** scenarios.

## What It Currently Does

* Parses raw authentication log entries
* Tracks failed login attempts by IP address
* Detects repeated failed logins
* Detects brute-force login attempts
* Detects password spraying across multiple users
* Classifies findings into Low, Medium, and High severity
* Identifies successful logins following multiple failures
* Flags possible account compromise
* Generates structured security findings and reports

## How It Works

```text
Security Logs
      ↓
    Parser
      ↓
Structured Security Events
      ↓
   Detector
      ↓
Threat Detection & Severity Classification
      ↓
 Security Findings / Reports
```

The detection engine currently analyzes authentication activity within a configurable time window and uses thresholds to classify suspicious behavior.

## Project Goal

The long-term goal is to evolve this project into an **AI-powered Security Analyst** that can not only detect suspicious activity, but also explain why an event is suspicious, assess its risk, summarize the incident, and recommend appropriate security actions.

## Current Detection Capabilities

The system can identify:

* Repeated failed logins
* Brute-force login attempts
* Password spraying
* Possible account compromise after repeated authentication failures

## Tech Stack

* Python
* Regular Expressions
* Datetime-based log analysis
* Rule-based security detection
* Structured security findings

## Future Development

The next stage of the project will introduce an AI analysis layer on top of the existing detection engine.

Planned capabilities include:

* AI-generated incident explanations
* Risk and threat summaries
* Recommended response actions
* Security-event prioritization
* Natural-language security reports
* Integration with an LLM
* More advanced attack-pattern detection

## Project Status

🚧 **Currently under active development**

The core log parsing and security detection pipeline is functional. The AI analyst layer is the next major development stage.
