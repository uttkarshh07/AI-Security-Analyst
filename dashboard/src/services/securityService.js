const API_BASE_URL = "http://127.0.0.1:8000";

export async function getSecurityFindings() {
  const response = await fetch(`${API_BASE_URL}/findings`);

  if (!response.ok) {
    throw new Error(
      `Failed to load security findings (${response.status})`
    );
  }

  const data = await response.json();

  if (!Array.isArray(data)) {
    throw new Error("Invalid response from security API.");
  }

  return data.map((incident) => {
    const finding = incident.securityFinding || {};
    const aiAnalysis =
      incident.aiAnalysis || incident.ai_analysis || null;

    return {
      id: incident.id,

      // SecurityFinding fields
      ip_address: finding.ip_address || "",
      attack_type: finding.attack_type || "Unknown",
      severity: finding.severity || "Low",
      failed_attempts: finding.failed_attempts ?? 0,
      max_failures_in_window:
        finding.max_failures_in_window ?? 0,
      window_minutes: finding.window_minutes ?? 0,
      targeted_users: finding.targeted_users || [],
      first_seen: finding.first_seen || null,
      last_seen: finding.last_seen || null,
      evidence: finding.evidence || [],

      // AIAnalysis
      aiAnalysis,

      // API-level status
      status: incident.status || "Investigating",

      // Keep this compatible with the existing UI.
      // The current /findings endpoint may not provide
      // possible_compromise yet.
      possible_compromise:
        incident.possible_compromise || null,
    };
  });
}