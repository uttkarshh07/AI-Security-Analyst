import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bell,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Crosshair,
  FileSearch,
  LayoutDashboard,
  Search,
  Settings,
  Shield,
  UserRound,
} from "lucide-react";

import { getSecurityFindings } from "./services/securityService";
import "./App.css";

/*
=========================================================
DATA LAYER
=========================================================



/* =========================================================
   REUSABLE COMPONENTS
========================================================= */

function SeverityBadge({ severity }) {
  const value = severity?.toLowerCase() || "low";

  return (
    <span className={`severity-badge ${value}`}>
      <span className="severity-dot" />
      {severity || "Low"}
    </span>
  );
}

function StatusBadge({ status }) {
  const normalized =
    status?.toLowerCase().replace(/\s+/g, "-") || "";

  return (
    <span className={`status-badge ${normalized}`}>
      {status || "Monitoring"}
    </span>
  );
}

function SummaryCard({
  label,
  value,
  description,
  type = "",
  icon: Icon,
}) {
  return (
    <div className={`summary-card ${type}`}>
      <div className={`summary-icon ${type}`}>
        <Icon size={20} strokeWidth={1.8} />
      </div>

      <div className="summary-content">
        <div className={`summary-label ${type}`}>
          {label}
        </div>

        <div className="summary-value">
          {value}
        </div>

        <div className="summary-description">
          {description}
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   SIDEBAR
========================================================= */

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-logo">
          <Shield size={21} strokeWidth={1.8} />
        </div>

        <div>
          <h1>AI Security Analyst</h1>
          <span>Security Operations</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">
          OVERVIEW
        </div>

        <button
          type="button"
          className="nav-item active"
        >
          <LayoutDashboard size={17} />
          <span>Dashboard</span>
        </button>

        <div className="nav-section-label">
          MONITORING
        </div>

        <button
          type="button"
          className="nav-item"
        >
          <FileSearch size={17} />
          <span>Security Findings</span>
        </button>

        <button
          type="button"
          className="nav-item"
        >
          <AlertTriangle size={17} />
          <span>Incidents</span>
        </button>

        <button
          type="button"
          className="nav-item"
        >
          <Crosshair size={17} />
          <span>MITRE ATT&amp;CK</span>
        </button>

        <button
          type="button"
          className="nav-item"
        >
          <Settings size={17} />
          <span>Settings</span>
        </button>
      </nav>

      <div className="sidebar-footer">
        <span className="sidebar-online-dot" />
        <span>Detection engine online</span>
      </div>
    </aside>
  );
}

/* =========================================================
   SEARCH & FILTERS
========================================================= */

function SearchFilters({
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  attackFilter,
  setAttackFilter,
  statusFilter,
  setStatusFilter,
  sortBy,
  setSortBy,
}) {
  return (
    <div className="filters">

      <div className="search-control">
        <Search size={16} />

        <input
          type="text"
          placeholder="Search IP, attack type, or user"
          value={search}
          onChange={(event) =>
            setSearch(event.target.value)
          }
        />

        {search && (
          <button
            type="button"
            className="clear-search"
            onClick={() => setSearch("")}
            aria-label="Clear search"
          >
            ×
          </button>
        )}
      </div>

      <div className="filter-control">
        <span>Severity</span>

        <div className="select-wrap">
          <select
            value={severityFilter}
            onChange={(event) =>
              setSeverityFilter(event.target.value)
            }
          >
            <option value="all">
              All severities
            </option>

            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <ChevronDown size={14} />
        </div>
      </div>

      <div className="filter-control">
        <span>Attack Type</span>

        <div className="select-wrap">
          <select
            value={attackFilter}
            onChange={(event) =>
              setAttackFilter(event.target.value)
            }
          >
            <option value="all">
              All attack types
            </option>

            <option value="Password Spraying">
              Password Spraying
            </option>

            <option value="Brute-force login attempt">
              Brute-force Login
            </option>

            <option value="Repeated Failed Logins">
              Repeated Failed Logins
            </option>

            <option value="Possible Account Compromise">
              Possible Account Compromise
            </option>
          </select>

          <ChevronDown size={14} />
        </div>
      </div>

      <div className="filter-control">
        <span>Status</span>

        <div className="select-wrap">
          <select
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(event.target.value)
            }
          >
            <option value="all">
              All statuses
            </option>

            <option value="Needs Review">
              Needs Review
            </option>

            <option value="Investigating">
              Investigating
            </option>

            <option value="Monitoring">
              Monitoring
            </option>
          </select>

          <ChevronDown size={14} />
        </div>
      </div>

      <div className="filter-control sort-control">
        <span>Sort by</span>

        <div className="select-wrap">
          <select
            value={sortBy}
            onChange={(event) =>
              setSortBy(event.target.value)
            }
          >
            <option value="newest">
              Newest
            </option>

            <option value="severity">
              Severity
            </option>

            <option value="failures">
              Most failed attempts
            </option>
          </select>

          <ChevronDown size={14} />
        </div>
      </div>

    </div>
  );
}

/* =========================================================
   DATA HELPERS
========================================================= */

function getSourceIP(finding) {
  return (
    finding.ip_address ||
    finding.source_ip ||
    finding.sourceIp ||
    "—"
  );
}

function getTargetedUsers(finding) {
  if (Array.isArray(finding.targeted_users)) {
    return finding.targeted_users;
  }

  if (Array.isArray(finding.targetedUsers)) {
    return finding.targetedUsers;
  }

  if (typeof finding.targeted_users === "string") {
    return [finding.targeted_users];
  }

  if (Array.isArray(finding.users)) {
    return finding.users;
  }

  if (finding.user) {
    return [finding.user];
  }

  return [];
}

function getFailedAttempts(finding) {
  return (
    finding.failed_attempts ??
    finding.failedAttempts ??
    finding.failures ??
    0
  );
}

/* =========================================================
   FINDINGS TABLE
========================================================= */

function FindingTable({
  findings,
  selectedId,
  onSelect,
}) {
  if (!findings.length) {
    return (
      <div className="empty-state">
        <ClipboardList size={28} />

        <h3>
          No suspicious activity detected.
        </h3>

        <p>
          Your system currently has no security
          findings to review.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="findings-table">

        <thead>
          <tr>
            <th>Severity</th>
            <th>Attack Type</th>
            <th>Source IP</th>
            <th>Targeted Users</th>
            <th>Failures</th>
            <th>First Seen</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>

        <tbody>
          {findings.map((finding) => {
            const isSelected =
              selectedId === finding.id;

            const users =
              getTargetedUsers(finding);

            return (
              <tr
                key={finding.id}
                className={
                  isSelected
                    ? "selected-row"
                    : ""
                }
                onClick={() =>
                  onSelect(finding)
                }
              >

                <td>
                  <SeverityBadge
                    severity={finding.severity}
                  />
                </td>

                <td className="attack-cell">
                  <strong>
                    {finding.attack_type ||
                      finding.attack ||
                      "Unknown activity"}
                  </strong>

                  {finding.attack_description && (
                    <span className="row-subtle">
                      {finding.attack_description}
                    </span>
                  )}
                </td>

                <td>
                  <span className="source-ip">
                    {getSourceIP(finding)}
                  </span>
                </td>

                <td>
                  {users.length}{" "}
                  {users.length === 1
                    ? "user"
                    : "users"}
                </td>

                <td>
                  {getFailedAttempts(finding)}
                </td>

                <td>
                  {formatTime(
                    finding.first_seen ||
                    finding.firstSeen
                  )}
                </td>

                <td>
                  <StatusBadge
                    status={finding.status}
                  />
                </td>

                <td className="arrow-cell">
                  <ChevronRight size={17} />
                </td>

              </tr>
            );
          })}
        </tbody>

      </table>
    </div>
  );
}

/* =========================================================
   FINDING DETAILS
========================================================= */

function FindingDetails({ finding }) {
  if (!finding) {
    return (
      <div className="details-placeholder">
        <ClipboardList size={30} />

        <h3>
          Select a security finding
        </h3>

        <p>
          Select a finding above to review
          its complete security analysis.
        </p>
      </div>
    );
  }

  const ai =
    finding.aiAnalysis ||
    finding.ai_analysis ||
    finding.ai_analysis_result;

  const users = getTargetedUsers(finding);

  return (
    <section className="incident-section">

      <div className="details-heading">

        <div>
          <div className="eyebrow">
            SECURITY FINDING
          </div>

          <h2>
            {finding.attack_type ||
              finding.attack ||
              "Security Finding"}
          </h2>

          <p className="details-source">
            Source IP{" "}
            <span className="source-ip">
              {getSourceIP(finding)}
            </span>
          </p>
        </div>

        <SeverityBadge
          severity={finding.severity}
        />

      </div>

      <div className="details">

        {/* OVERVIEW */}

        <div className="detail-section">

          <div className="section-title">
            <h3>Finding Overview</h3>
          </div>

          <div className="detail-grid">

            <div className="detail-item">
              <span>Attack Type</span>

              <strong>
                {finding.attack_type ||
                  finding.attack ||
                  "Unknown"}
              </strong>
            </div>

            <div className="detail-item">
              <span>Severity</span>

              <strong>
                {finding.severity || "Low"}
              </strong>
            </div>

            <div className="detail-item">
              <span>Source IP</span>

              <strong className="detail-value-ip">
                {getSourceIP(finding)}
              </strong>
            </div>

            <div className="detail-item">
              <span>Failed Attempts</span>

              <strong>
                {getFailedAttempts(finding)}
              </strong>
            </div>

            <div className="detail-item">
              <span>Time Window</span>

              <strong>
                {finding.window_minutes ??
                finding.windowMinutes
                  ? `${
                      finding.window_minutes ??
                      finding.windowMinutes
                    } minutes`
                  : "—"}
              </strong>
            </div>

            <div className="detail-item">
              <span>First Seen</span>

              <strong>
                {formatDateTime(
                  finding.first_seen ||
                  finding.firstSeen
                )}
              </strong>
            </div>

            <div className="detail-item">
              <span>Last Seen</span>

              <strong>
                {formatDateTime(
                  finding.last_seen ||
                  finding.lastSeen
                )}
              </strong>
            </div>

          </div>
        </div>

        {/* TARGETED USERS */}

        <div className="detail-section">

          <div className="section-title">
            <h3>Targeted Users</h3>
          </div>

          <div className="user-tags">

            {users.length ? (
              users.map((user) => (
                <span key={user}>
                  <UserRound size={13} />
                  {user}
                </span>
              ))
            ) : (
              <span className="no-users">
                No user information available
              </span>
            )}

          </div>

        </div>

        {/* POSSIBLE COMPROMISE */}

        {finding.possible_compromise && (
          <div className="compromise-alert">

            <div className="compromise-icon">
              <Shield size={20} />
            </div>

            <div>
              <strong>
                Possible Account Compromise
              </strong>

              <p>
                A successful login occurred
                after multiple failed attempts.
              </p>

              <div className="compromise-grid">

                <div>
                  <span>Affected user</span>

                  <strong>
                    {finding.possible_compromise.user}
                  </strong>
                </div>

                <div>
                  <span>Source IP</span>

                  <strong className="detail-value-ip">
                    {finding.possible_compromise.source_ip}
                  </strong>
                </div>

                <div>
                  <span>Failed attempts</span>

                  <strong>
                    {getFailedAttempts(finding)}
                  </strong>
                </div>

                <div>
                  <span>Successful login</span>

                  <strong>
                    {formatDateTime(
                      finding.possible_compromise
                        .successful_login_time
                    )}
                  </strong>
                </div>

              </div>
            </div>

          </div>
        )}

        {/* AI ANALYSIS */}

        {ai && (
          <>

            {/* WHY SUSPICIOUS */}

            <div className="detail-section">

              <div className="section-title">
                <h3>
                  Why is this suspicious?
                </h3>
              </div>

              <div className="plain-language-box">
                <p>
                  {ai.incident_summary}
                </p>
              </div>

              {ai.why_suspicious?.length > 0 && (
                <ul className="explanation-list">
                  {ai.why_suspicious.map(
                    (reason, index) => (
                      <li key={index}>
                        {reason}
                      </li>
                    )
                  )}
                </ul>
              )}

            </div>

            {/* EVIDENCE */}

            <div className="detail-section">

              <div className="section-title">
                <h3>Evidence</h3>
              </div>

              <ul className="evidence-list">

                {ai.evidence?.map(
                  (item, index) => (
                    <li key={index}>
                      <span className="evidence-bullet">
                        •
                      </span>

                      {item}
                    </li>
                  )
                )}

              </ul>

            </div>

            {/* MITRE */}

            <div className="detail-section">

              <div className="section-title">
                <h3>MITRE ATT&amp;CK</h3>
              </div>

              <div className="mitre-card">

                <div>
                  <span>Technique</span>

                  <strong>
                    {ai.mitre_attack?.technique ||
                      "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>Technique ID</span>

                  <strong>
                    {ai.mitre_attack?.technique_id ||
                      "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>Tactic</span>

                  <strong>
                    {ai.mitre_attack?.tactic ||
                      "Unknown"}
                  </strong>
                </div>

              </div>

              <p className="helper-text">
                MITRE ATT&amp;CK is a framework
                used to describe common attacker
                techniques.
              </p>

            </div>

            {/* CONFIDENCE */}

            <div className="detail-section">

              <div className="confidence-row">

                <div className="section-title">
                  <h3>AI Confidence</h3>
                </div>

                <span className="confidence-badge">
                  {ai.confidence || "Unknown"}
                </span>

              </div>

              <p className="helper-text">
                Confidence indicates how strongly
                the available evidence supports
                the analysis.
              </p>

            </div>

            {/* ACTIONS */}

            <div className="detail-section last-section">

              <div className="section-title">
                <h3>Recommended Actions</h3>
              </div>

              <ol className="actions-list">

                {ai.recommended_actions?.map(
                  (action, index) => (
                    <li key={index}>

                      <span>
                        {index + 1}
                      </span>

                      <p>
                        {action}
                      </p>

                    </li>
                  )
                )}

              </ol>

            </div>

          </>
        )}

      </div>
    </section>
  );
}

/* =========================================================
   DATE / TIME HELPERS
========================================================= */

function formatTime(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDateTime(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/* =========================================================
   MAIN APP
========================================================= */

function App() {
  // =====================================================
  // API DATA
  // =====================================================

  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  // =====================================================
  // FILTERS
  // =====================================================

  const [search, setSearch] = useState("");

  const [severityFilter, setSeverityFilter] =
    useState("all");

  const [attackFilter, setAttackFilter] =
    useState("all");

  const [statusFilter, setStatusFilter] =
    useState("all");

  const [sortBy, setSortBy] =
    useState("newest");

  // =====================================================
  // SELECTED FINDING
  // =====================================================

  const [selectedId, setSelectedId] =
    useState(null);

  // =====================================================
  // API LOAD
  // =====================================================

  const loadFindings = async () => {
    try {
      setLoading(true);
      setError(false);

      const data = await getSecurityFindings();

      setFindings(data);

      // Select the first finding automatically
      setSelectedId((currentId) => {
        if (
          currentId &&
          data.some(
            (finding) => finding.id === currentId
          )
        ) {
          return currentId;
        }

        return data[0]?.id || null;
      });
    } catch (err) {
      console.error(
        "Failed to load security findings:",
        err
      );

      setError(true);
      setFindings([]);
      setSelectedId(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);

  // =====================================================
  // DATA USED BY THE UI
  // =====================================================

  const dashboardIncidents = findings;

  /* =====================================================
     FILTERING
  ===================================================== */

  const filteredFindings = useMemo(() => {
    let result = [...dashboardIncidents];

    const query =
      search.toLowerCase().trim();

    if (query) {
      result = result.filter((finding) => {
        const users = getTargetedUsers(finding)
          .join(" ")
          .toLowerCase();

        const ip = getSourceIP(finding)
          .toLowerCase();

        const attack =
          finding.attack_type ||
          finding.attack ||
          "";

        return (
          ip.includes(query) ||
          attack.toLowerCase().includes(query) ||
          users.includes(query)
        );
      });
    }

    if (severityFilter !== "all") {
      result = result.filter(
        (finding) =>
          finding.severity ===
          severityFilter
      );
    }

    if (attackFilter !== "all") {
  result = result.filter((finding) => {
    const attackType =
      finding.attack_type ||
      finding.attack ||
      "";

    return (
      attackType.toLowerCase() ===
      attackFilter.toLowerCase()
    );
  });
}

    if (statusFilter !== "all") {
  result = result.filter((finding) => {
    const status =
      finding.status || "";

    return (
      status.toLowerCase() ===
      statusFilter.toLowerCase()
    );
  });
}

    if (sortBy === "failures") {
      result.sort(
        (a, b) =>
          getFailedAttempts(b) -
          getFailedAttempts(a)
      );
    }

    if (sortBy === "severity") {
      const order = {
        High: 3,
        Medium: 2,
        Low: 1,
      };

      result.sort(
        (a, b) =>
          (order[b.severity] || 0) -
          (order[a.severity] || 0)
      );
    }

    if (sortBy === "newest") {
      result.sort(
        (a, b) =>
          new Date(
            b.first_seen ||
            b.firstSeen ||
            0
          ) -
          new Date(
            a.first_seen ||
            a.firstSeen ||
            0
          )
      );
    }

    return result;
  }, [
    findings,
    search,
    severityFilter,
    attackFilter,
    statusFilter,
    sortBy,
  ]);

  const selectedFinding =
  filteredFindings.find(
    (finding) =>
      finding.id === selectedId
  ) ||
  dashboardIncidents.find(
    (finding) =>
      finding.id === selectedId
  ) ||
  filteredFindings[0] ||
  null;

  /* =====================================================
     SUMMARY
  ===================================================== */

  const totalFindings =
    dashboardIncidents.length;

  const highSeverity =
    dashboardIncidents.filter(
      (finding) =>
        finding.severity === "High"
    ).length;

  const mediumSeverity =
    dashboardIncidents.filter(
      (finding) =>
        finding.severity === "Medium"
    ).length;

  const possibleCompromises =
    dashboardIncidents.filter(
      (finding) =>
        finding.possible_compromise
    ).length;

  /* =====================================================
     UI
  ===================================================== */

  return (
    <div className="app-shell">

      {/* SIDEBAR */}

      <Sidebar />

      {/* MAIN APPLICATION */}

      <div className="main-area">

        {/* TOP BAR */}

        <header className="topbar">

          <div className="brand">

            <div className="brand-mark">
              <Shield size={20} />
            </div>

            <div className="brand-content">

              <h1>
                AI Security Analyst
              </h1>

              <p>
                Security monitoring and
                incident review
              </p>

            </div>

          </div>

          <div className="topbar-right">

            <div className="monitoring-status">
              <span className="status-dot" />
              Monitoring
            </div>

            <span className="last-updated">
              Last updated:{" "}
              {new Date().toLocaleTimeString(
                [],
                {
                  hour: "2-digit",
                  minute: "2-digit",
                  second: "2-digit",
                }
              )}
            </span>

            <button
              className="icon-button"
              type="button"
              aria-label="Notifications"
            >
              <Bell size={17} />
            </button>

          </div>

        </header>

        {/* PAGE */}

        <main className="page">

          {/* PAGE HEADING */}

          <section className="page-heading">

            <div className="breadcrumb">
              SECURITY OPERATIONS
            </div>

            <h2>
              Dashboard
            </h2>

            <p>
              Review suspicious authentication
              activity and understand what needs
              attention.
            </p>

          </section>

          {/* SUMMARY CARDS */}

          <section className="summary-grid">

            <SummaryCard
              label="Total Findings"
              value={totalFindings}
              description="Security findings detected"
              type="total"
              icon={ClipboardList}
            />

            <SummaryCard
              label="High Severity"
              value={highSeverity}
              description="Requires immediate review"
              type="high"
              icon={Shield}
            />

            <SummaryCard
              label="Medium Severity"
              value={mediumSeverity}
              description="Requires investigation"
              type="medium"
              icon={Search}
            />

            <SummaryCard
              label="Possible Compromises"
              value={possibleCompromises}
              description="Successful login after failures"
              type="compromise"
              icon={UserRound}
            />

          </section>

          {/* FINDINGS */}

          <section className="findings-section">

            <div className="section-header">

              <div>
                <h2>
                  Recent Security Findings
                </h2>

                <p>
                  Select a finding to review
                  the full analysis.
                </p>
              </div>

              <span className="finding-count">
                {filteredFindings.length} of{" "}
                {dashboardIncidents.length}
              </span>

            </div>

            <SearchFilters
              search={search}
              setSearch={setSearch}
              severityFilter={severityFilter}
              setSeverityFilter={
                setSeverityFilter
              }
              attackFilter={attackFilter}
              setAttackFilter={
                setAttackFilter
              }
              statusFilter={statusFilter}
              setStatusFilter={
                setStatusFilter
              }
              sortBy={sortBy}
              setSortBy={setSortBy}
            />

            {loading ? (
               <div className="state-card">
    <ClipboardList size={28} />

    <h3>Loading security findings...</h3>

    <p>
      Fetching the latest findings from the
      security monitoring service.
    </p>
  </div>
      ) : error ? (
  <div className="state-card error-state">
    <AlertTriangle size={28} />

    <h3>Unable to load security findings.</h3>

    <p>
      Check the backend connection and try again.
    </p>

    <button
      type="button"
      className="retry-button"
      onClick={loadFindings}
    >
      Try Again
    </button>
  </div>
) : (
  <FindingTable
    findings={filteredFindings}
    selectedId={
      selectedFinding?.id
    }
    onSelect={(finding) =>
      setSelectedId(finding.id)
    }
  />
)}

          </section>

          {/* INCIDENT DETAILS */}

          <FindingDetails
            finding={selectedFinding}
          />

        </main>

      </div>

    </div>
  );
}

export default App;