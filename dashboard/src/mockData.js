export const incidents = [
  {
    id: "INC-001",

    securityFinding: {
      ip_address: "203.0.113.5",
      attack_type: "Password Spraying",
      severity: "Medium",

      failed_attempts: 7,
      max_failures_in_window: 7,
      window_minutes: 10,

      targeted_users: [
        "alice",
        "bob",
        "carol",
        "dave",
        "eve",
        "frank",
      ],

      first_seen: "2026-08-13T10:00:01",
      last_seen: "2026-08-13T10:02:00",

      evidence: [
        "7 failed login attempts from 203.0.113.5",
        "6 unique users targeted",
      ],
    },

    aiAnalysis: {
      incident_summary:
        "A single IP address attempted to authenticate against multiple user accounts within a short period. This pattern is consistent with password spraying.",

      why_suspicious: [
        "A single source IP targeted multiple distinct accounts.",
        "7 authentication failures occurred across 6 users in a short timeframe.",
      ],

      mitre_attack: {
        tactic: "Credential Access",
        technique_id: "T1110.003",
        technique: "Password Spraying",
      },

      evidence: [
        "7 failed login attempts from 203.0.113.5",
        "6 unique users targeted",
      ],

      confidence: "High",

      recommended_actions: [
        "Review authentication attempts from the source IP.",
        "Check whether any login succeeded from this IP.",
        "Monitor the targeted accounts.",
        "Verify MFA is enabled for the targeted users.",
      ],
    },

    status: "Investigating",

    possible_compromise: null,
  },

  {
    id: "INC-002",

    securityFinding: {
      ip_address: "10.10.10.5",
      attack_type: "Password Spraying",
      severity: "Medium",

      failed_attempts: 5,
      max_failures_in_window: 5,
      window_minutes: 10,

      targeted_users: [
        "alice",
        "bob",
        "carol",
        "dave",
        "eric",
      ],

      first_seen: "2026-08-13T14:00:00",
      last_seen: "2026-08-13T14:01:20",

      evidence: [
        "5 failed login attempts from 10.10.10.5",
        "5 unique users targeted",
      ],
    },

    aiAnalysis: {
      incident_summary:
        "The source IP generated failed authentication attempts against five different user accounts in a short period, matching a password spraying pattern.",

      why_suspicious: [
        "Every failed attempt targeted a different user.",
        "The failures were concentrated within a short time window.",
      ],

      mitre_attack: {
        tactic: "Credential Access",
        technique_id: "T1110.003",
        technique: "Password Spraying",
      },

      evidence: [
        "5 failed login attempts from 10.10.10.5",
        "5 unique users targeted",
      ],

      confidence: "High",

      recommended_actions: [
        "Review authentication logs for this source IP.",
        "Check for any successful login from 10.10.10.5.",
        "Monitor the targeted accounts.",
        "Confirm MFA is enabled for the affected users.",
      ],
    },

    status: "Investigating",

    possible_compromise: null,
  },

  {
    id: "INC-003",

    securityFinding: {
      ip_address: "198.51.100.9",
      attack_type: "Repeated Failed Logins",
      severity: "Low",

      failed_attempts: 2,
      max_failures_in_window: 2,
      window_minutes: 10,

      targeted_users: ["grace"],

      first_seen: "2026-08-13T09:00:00",
      last_seen: "2026-08-13T09:00:30",

      evidence: [
        "2 failed login attempts from 198.51.100.9",
        "1 user targeted",
      ],
    },

    aiAnalysis: {
      incident_summary:
        "Two failed login attempts were recorded from the same IP against one user. This is worth monitoring but does not by itself strongly indicate an attack.",

      why_suspicious: [
        "Two failures came from the same source IP within 30 seconds.",
        "The activity targeted the same account.",
      ],

      mitre_attack: {
        tactic: "Credential Access",
        technique_id: "T1110",
        technique: "Brute Force",
      },

      evidence: [
        "2 failed login attempts from 198.51.100.9",
        "1 unique user targeted",
      ],

      confidence: "Low",

      recommended_actions: [
        "Verify whether the failed attempts were expected user activity.",
        "Monitor the source IP for additional failures.",
        "Escalate if the number or frequency of failures increases.",
      ],
    },

    status: "Monitoring",

    possible_compromise: null,
  },

  {
    id: "INC-004",

    securityFinding: {
      ip_address: "192.0.2.44",
      attack_type: "Possible Account Compromise",
      severity: "High",

      failed_attempts: 8,
      max_failures_in_window: 8,
      window_minutes: 10,

      targeted_users: ["alice"],

      first_seen: "2026-08-13T14:05:10",
      last_seen: "2026-08-13T14:08:32",

      evidence: [
        "8 failed login attempts from 192.0.2.44",
        "A successful login followed the failed attempts",
        "The successful login targeted user alice",
      ],
    },

    aiAnalysis: {
      incident_summary:
        "A successful login occurred after multiple failed authentication attempts from the same source IP. This may indicate that an account password was eventually guessed or obtained.",

      why_suspicious: [
        "Multiple authentication failures were followed by a successful login.",
        "The same source IP was associated with both failed and successful authentication activity.",
      ],

      mitre_attack: {
        tactic: "Credential Access",
        technique_id: "T1110",
        technique: "Brute Force",
      },

      evidence: [
        "8 failed login attempts from 192.0.2.44",
        "Successful login recorded at 2026-08-13 14:08:32",
        "Affected user: alice",
      ],

      confidence: "High",

      recommended_actions: [
        "Review the successful login and confirm whether alice initiated it.",
        "Review authentication and activity logs for the affected account.",
        "Protect or reset the account if the login was not expected.",
        "Verify MFA and review other sessions for the account.",
      ],
    },

    status: "Needs Review",

    possible_compromise: {
      user: "alice",
      source_ip: "192.0.2.44",
      failed_attempts: 8,
      successful_login_time: "2026-08-13T14:08:32",
    },
  },
];