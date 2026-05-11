import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const fallbackAlerts = [
  {
    threat: "Ransomware Activity",
    severity: "Critical",
    priority: "P1",
    entity: "system_blr",
    pair: "43.252.176.8 -> 142.250.240.4",
    score: 91,
    status: "Contain now",
    source: "Endpoint EDR",
    signal: "Mass file rename, encryption behavior, shadow copy delete command",
    firstSeen: "20:38:06",
  },
  {
    threat: "Credential Abuse",
    severity: "High",
    priority: "P2",
    entity: "raj.k",
    pair: "112.133.201.5 -> 142.250.176.90",
    score: 78,
    status: "Block session",
    source: "Identity Logs",
    signal: "Impossible travel login and repeated MFA challenge failures",
    firstSeen: "20:38:02",
  },
  {
    threat: "Suspicious Login Attempt",
    severity: "Medium",
    priority: "P3",
    entity: "priya.s",
    pair: "103.1.1.45 -> 142.250.227.246",
    score: 52,
    status: "Verify user",
    source: "SIEM Correlation",
    signal: "New device fingerprint with unusual access time",
    firstSeen: "20:37:59",
  },
  {
    threat: "Phishing Email Attack",
    severity: "Medium",
    priority: "P3",
    entity: "ashok.v",
    pair: "43.252.176.8 -> 142.250.216.83",
    score: 58,
    status: "Quarantine mail",
    source: "Email Gateway",
    signal: "Suspicious attachment hash and spoofed sender domain",
    firstSeen: "20:37:55",
  },
  {
    threat: "Unauthorized Access Attempt",
    severity: "High",
    priority: "P2",
    entity: "mumbai-fw",
    pair: "18.139.22.45 -> 10.20.4.18",
    score: 83,
    status: "Deny route",
    source: "Firewall / VPC Flow",
    signal: "Blocked admin port scan from untrusted regional IP",
    firstSeen: "20:37:52",
  },
  {
    threat: "Malware Detected",
    severity: "High",
    priority: "P2",
    entity: "finance-laptop-07",
    pair: "10.20.3.18 -> 185.199.108.153",
    score: 74,
    status: "Scan host",
    source: "Endpoint EDR",
    signal: "Unsigned executable, persistence registry key, and suspicious outbound beacon",
    firstSeen: "20:37:48",
  },
];

const fallbackVulnerabilities = [
  { issue: "Weak Password Policy", risk: "Critical", owner: "Identity", sla: "4h" },
  { issue: "Outdated Apache Server", risk: "High", owner: "Web Tier", sla: "12h" },
  { issue: "Open SSH Port", risk: "Medium", owner: "Network", sla: "24h" },
];

const detectionSources = [
  {
    key: "Endpoint EDR",
    name: "Endpoint EDR",
    feed: "Device behavior",
    value: "18 events",
    detail: "Process chains, suspicious scripts, encryption patterns",
  },
  {
    key: "Identity Logs",
    name: "Identity Logs",
    feed: "Azure AD / IAM",
    value: "9 events",
    detail: "Impossible travel, failed MFA, privilege escalation",
  },
  {
    key: "Firewall / VPC Flow",
    name: "Firewall / VPC Flow",
    feed: "Firewall + VPC",
    value: "26 flows",
    detail: "Port scans, risky destinations, unusual egress volume",
  },
  {
    key: "Email Gateway",
    name: "Email Gateway",
    feed: "Mail security",
    value: "7 messages",
    detail: "Spoofed domains, malicious hashes, link detonation",
  },
];

const playbooks = {
  ransomware:
    "Critical ransomware pattern. Isolate the host, disable the affected account, preserve disk evidence, block command-and-control traffic, and restore only from clean backups.",
  credential:
    "Credential abuse suspected. Revoke active sessions, reset the password, enforce MFA, review login geography, and check recent privilege changes.",
  login:
    "Suspicious login. Verify the user, compare device fingerprint, check IP reputation, and require step-up authentication.",
  phishing:
    "Phishing signal. Quarantine the email, remove matching messages, scan clicked endpoints, and block the sender domain and attachment hash.",
  unauthorized:
    "Unauthorized access attempt. Keep deny rule active, block the source IP, check lateral movement, and review exposed admin services.",
  default:
    "Investigate by source, score, affected entity, and evidence. Contain high-score alerts first, then close the vulnerable path.",
};

function enrichAlert(alert, index) {
  const template =
    fallbackAlerts.find((item) => item.threat.toLowerCase() === alert.threat?.toLowerCase()) ||
    fallbackAlerts[index % fallbackAlerts.length];

  return {
    ...template,
    ...alert,
    source: template.source,
    signal: template.signal,
    score: template.score,
    status: template.status,
    firstSeen: template.firstSeen,
  };
}

function severityClass(value = "") {
  return value.toLowerCase();
}

function getPlaybook(text) {
  const value = text.toLowerCase();
  if (value.includes("ransomware")) return playbooks.ransomware;
  if (value.includes("credential")) return playbooks.credential;
  if (value.includes("login")) return playbooks.login;
  if (value.includes("phishing")) return playbooks.phishing;
  if (value.includes("unauthorized") || value.includes("access")) return playbooks.unauthorized;
  return playbooks.default;
}

function findMatchingAlert(question, alerts, selectedAlert) {
  const query = question.toLowerCase();
  return (
    alerts.find((alert) =>
      alert.threat
        .toLowerCase()
        .split(" ")
        .some((word) => word.length > 4 && query.includes(word))
    ) ||
    selectedAlert ||
    alerts[0]
  );
}

function AssistantChat({ alerts, selectedAlert, onSelectAlert }) {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Ask about any alert. I can explain where it was detected, how dangerous it is, and what action to take.",
    },
  ]);

  const replyFor = (alert, userText) => {
    const response = `${getPlaybook(`${userText} ${alert.threat}`)} Detected from ${alert.source}. Evidence: ${alert.signal}. Threat score: ${alert.score}/100.`;
    setMessages((current) => [...current, { role: "user", text: userText }, { role: "assistant", text: response }]);
  };

  const askAbout = (alert) => {
    onSelectAlert(alert);
    replyFor(alert, `What should I do for ${alert.threat}?`);
  };

  const submitQuestion = (event) => {
    event.preventDefault();
    const value = question.trim();
    if (!value) return;
    const alert = findMatchingAlert(value, alerts, selectedAlert);
    onSelectAlert(alert);
    replyFor(alert, value);
    setQuestion("");
  };

  return (
    <section className="assistant-panel">
      <div className="section-heading">
        <div>
          <p className="section-kicker">Response Assistant</p>
          <h2>Ask what to do next</h2>
        </div>
        <span className="priority-pill">{selectedAlert.priority}</span>
      </div>
      <div className="quick-prompts">
        {[...new Map(alerts.map((alert) => [alert.threat, alert])).values()].slice(0, 4).map((alert) => (
          <button key={alert.threat} type="button" onClick={() => askAbout(alert)}>
            {alert.threat}
          </button>
        ))}
      </div>
      <div className="chat-window">
        {messages.map((message, index) => (
          <div key={`${message.role}-${index}`} className={`message ${message.role}`}>
            {message.text}
          </div>
        ))}
      </div>
      <form className="chat-form" onSubmit={submitQuestion}>
        <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask: how dangerous is ransomware?"
        />
        <button type="submit">Send</button>
      </form>
    </section>
  );
}

function LiveLineGraph({ title, values, color = "#48ffd2" }) {
  const max = Math.max(...values, 100);
  const points = values
    .map((value, index) => {
      const x = (index / Math.max(values.length - 1, 1)) * 100;
      const y = 100 - (value / max) * 86 - 7;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <section className="live-graph-card">
      <div className="section-heading">
        <div>
          <p className="section-kicker">Live Graph</p>
          <h2>{title}</h2>
        </div>
        <span>{values[values.length - 1]}</span>
      </div>
      <svg className="live-graph" viewBox="0 0 100 100" preserveAspectRatio="none">
        <polyline points={points} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </section>
  );
}

function MiniSparkline({ values, color = "#48ffd2" }) {
  const max = Math.max(...values, 100);
  const min = Math.min(...values, 0);
  const range = Math.max(max - min, 1);
  const points = values
    .map((value, index) => {
      const x = (index / Math.max(values.length - 1, 1)) * 100;
      const y = 44 - ((value - min) / range) * 34;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg className="mini-sparkline" viewBox="0 0 100 48" preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MetricGraphCards({ threatTrend, flowTrend, alerts }) {
  const latestThreat = threatTrend[threatTrend.length - 1];
  const latestFlow = flowTrend[flowTrend.length - 1];
  const containment = Math.max(82, 100 - alerts.filter((alert) => alert.severity === "Critical").length * 4);
  const modelActivity = alerts.length + 7;

  return (
    <section className="metric-graph-grid">
      <article className="metric-graph-card">
        <div>
          <span>Anomaly Threshold</span>
          <strong>{latestThreat}%</strong>
        </div>
        <small>+8.2</small>
        <MiniSparkline values={threatTrend} color="#6f72ff" />
      </article>
      <article className="metric-graph-card">
        <div>
          <span>Containment Rate</span>
          <strong>{containment}%</strong>
        </div>
        <small>Stable</small>
        <MiniSparkline values={[86, 88, 87, 91, 89, 93, containment]} color="#12d6a0" />
      </article>
      <article className="metric-graph-card">
        <div>
          <span>Network Entropy</span>
          <strong>{(latestFlow / 100).toFixed(2)}</strong>
        </div>
        <small>-0.03</small>
        <MiniSparkline values={flowTrend} color="#f2a51f" />
      </article>
      <article className="metric-graph-card">
        <div>
          <span>Active Models</span>
          <strong>{modelActivity}</strong>
        </div>
        <small>Optimized</small>
        <MiniSparkline values={[8, 10, 9, 12, 8, 11, modelActivity]} color="#ff5fb7" />
      </article>
    </section>
  );
}

function LiveGraphs({ threatTrend, flowTrend }) {
  return (
    <section className="live-graphs">
      <LiveLineGraph title="Threat score trend" values={threatTrend} color="#48ffd2" />
      <LiveLineGraph title="Network flow volume" values={flowTrend} color="#ffba4a" />
    </section>
  );
}

function SourceBoard({ selectedSource, onSelectSource }) {
  return (
    <section className="source-board">
      <div className="section-heading">
        <div>
          <p className="section-kicker">Detection Sources</p>
          <h2>Where threats are detected from</h2>
        </div>
        <button type="button" className="ghost-button" onClick={() => onSelectSource("All")}>
          Show all
        </button>
      </div>
      <div className="source-grid">
        {detectionSources.map((source) => (
          <button
            key={source.key}
            type="button"
            className={`source-card ${selectedSource === source.key ? "selected" : ""}`}
            onClick={() => onSelectSource(source.key)}
          >
            <span>{source.feed}</span>
            <strong>{source.name}</strong>
            <b>{source.value}</b>
            <p>{source.detail}</p>
          </button>
        ))}
      </div>
    </section>
  );
}

function RiskBrief({ alerts, vulnerabilities, onRefresh, onOpenAssistant, onExportReport }) {
  const averageScore = Math.round(alerts.reduce((total, alert) => total + alert.score, 0) / alerts.length);
  const highImpact = alerts.filter((alert) => alert.severity === "Critical" || alert.severity === "High").length;

  return (
    <section className="risk-brief">
      <div className="risk-copy">
        <p className="section-kicker">Current Security Posture</p>
        <h2>{averageScore >= 80 ? "High risk activity in progress" : "Active threats under monitoring"}</h2>
        <p>
          Threats are detected by combining endpoint behavior, identity sign-ins, firewall/VPC flow logs, email security,
          and SIEM correlation rules. Backend agents classify each alert, assign priority, and attach response guidance.
        </p>
      </div>
      <div className="risk-meter" style={{ "--score": `${averageScore}%` }}>
        <strong>{averageScore}</strong>
        <span>Threat score</span>
      </div>
      <div className="risk-stats">
        <div>
          <b>{alerts.length}</b>
          <span>Active alerts</span>
        </div>
        <div>
          <b>{highImpact}</b>
          <span>High impact</span>
        </div>
        <div>
          <b>{vulnerabilities.length}</b>
          <span>Open exposures</span>
        </div>
        <button type="button" onClick={onRefresh}>Refresh telemetry</button>
        <button type="button" onClick={onOpenAssistant}>Ask assistant</button>
        <button type="button" onClick={onExportReport}>Export report</button>
      </div>
    </section>
  );
}

function IncidentWorkbench({ alerts, selectedAlert, onSelectAlert, onAsk }) {
  return (
    <section className="workbench">
      <div className="section-heading">
        <div>
          <p className="section-kicker">Incident Workbench</p>
          <h2>Prioritized threat queue</h2>
        </div>
      </div>
      <div className="incident-list">
        {alerts.map((alert) => (
          <article key={`${alert.threat}-${alert.entity}`} className={`incident-card ${selectedAlert.threat === alert.threat ? "selected" : ""}`}>
            <button type="button" className="incident-main" onClick={() => onSelectAlert(alert)}>
              <span className={`severity ${severityClass(alert.severity)}`}>{alert.severity}</span>
              <h3>{alert.threat}</h3>
              <p>{alert.signal}</p>
              <dl>
                <div>
                  <dt>Detected from</dt>
                  <dd>{alert.source}</dd>
                </div>
                <div>
                  <dt>Affected entity</dt>
                  <dd>{alert.entity}</dd>
                </div>
                <div>
                  <dt>Traffic pair</dt>
                  <dd>{alert.pair}</dd>
                </div>
              </dl>
            </button>
            <div className="incident-side">
              <strong>{alert.score}</strong>
              <span>Threat level</span>
              <b>{alert.status}</b>
              <button type="button" onClick={() => onAsk(alert)}>
                Ask assistant
              </button>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

function TopologyView() {
  const flowText = {
    Email: "Email Gateway detects spoofed domains, malicious attachments, unsafe links, and phishing campaigns.",
    Identity: "Identity Logs detect impossible travel, password spray, MFA fatigue, and suspicious user sessions.",
    Cloud: "Cloud telemetry detects risky API calls, unusual storage access, and abnormal VPC flows.",
    Endpoint: "Endpoint EDR detects malware, ransomware behavior, suspicious scripts, and persistence.",
    Firewall: "Firewall / VPC Flow detects port scans, blocked admin access, and risky outbound destinations.",
  };
  const [selectedFlow, setSelectedFlow] = useState(flowText.Email);

  return (
    <section className="network-page">
      <div className="flow-map">
        <div className="flow-center">Secure Core</div>
        {["Email", "Identity", "Cloud", "Endpoint", "Firewall"].map((item, index) => (
          <button key={item} type="button" className={`flow-node flow-${index + 1}`} onClick={() => setSelectedFlow(flowText[item])}>
            {item}
          </button>
        ))}
      </div>
      <div className="network-notes">
        <p className="section-kicker">Network Detection</p>
        <h2>Flow evidence</h2>
        <p>Click a node to see what telemetry is used for detection.</p>
        <strong className="selected-flow">{selectedFlow}</strong>
        {["13.233.124.12 - trusted cloud volume", "18.139.22.45 - unusual session burst", "20.42.161.124 - blocked scan"].map((item) => (
          <span key={item}>{item}</span>
        ))}
      </div>
    </section>
  );
}

function ExposureView({ vulnerabilities, selectedPlan, onCreatePlan }) {
  return (
    <section className="exposure-page">
      <div className="section-heading">
        <div>
          <p className="section-kicker">Exposure Management</p>
          <h2>Vulnerabilities that increase threat impact</h2>
        </div>
      </div>
      <div className="exposure-list">
        {vulnerabilities.map((item) => (
          <article key={item.issue}>
            <span className={`severity ${severityClass(item.risk)}`}>{item.risk}</span>
            <h3>{item.issue}</h3>
            <p>Owner: {item.owner} / SLA: {item.sla}</p>
            <button type="button" onClick={() => onCreatePlan(item)}>Create fix plan</button>
          </article>
        ))}
      </div>
      {selectedPlan && (
        <section className="fix-plan-panel">
          <p className="section-kicker">Generated Fix Plan</p>
          <h2>{selectedPlan.issue}</h2>
          <ol>
            <li>Assign owner: {selectedPlan.owner}</li>
            <li>Target remediation SLA: {selectedPlan.sla}</li>
            <li>Validate affected assets and confirm business owner approval.</li>
            <li>Apply remediation, retest exposure, and close the finding.</li>
          </ol>
        </section>
      )}
    </section>
  );
}

export default function App() {
  const [alerts, setAlerts] = useState(fallbackAlerts);
  const [vulnerabilities, setVulnerabilities] = useState(fallbackVulnerabilities);
  const [breach, setBreach] = useState({});
  const [activePage, setActivePage] = useState("dashboard");
  const [selectedAlert, setSelectedAlert] = useState(fallbackAlerts[0]);
  const [selectedSource, setSelectedSource] = useState("All");
  const [lastSync, setLastSync] = useState("Demo data");
  const [notice, setNotice] = useState("System ready. Select an alert, source, or assistant prompt to begin.");
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [threatTrend, setThreatTrend] = useState([68, 72, 75, 71, 78, 74, 82, 76, 79, 75]);
  const [flowTrend, setFlowTrend] = useState([42, 48, 45, 56, 62, 58, 66, 71, 69, 74]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsResponse, vulnerabilitiesResponse, breachResponse] = await Promise.all([
          axios.get("http://127.0.0.1:8000/alerts"),
          axios.get("http://127.0.0.1:8000/vulnerabilities"),
          axios.get("http://127.0.0.1:8000/breach-analysis"),
        ]);

        const nextAlerts = alertsResponse.data.map((alert, index) => enrichAlert(alert, index));
        setAlerts(nextAlerts);
        setSelectedAlert(nextAlerts[0]);
        setVulnerabilities(
          vulnerabilitiesResponse.data.map((item, index) => ({
            ...fallbackVulnerabilities[index % fallbackVulnerabilities.length],
            ...item,
          }))
        );
        setBreach(breachResponse.data);
        setLastSync(new Date().toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }));
      } catch {
        setLastSync("Demo data");
      }
    };

    fetchData();
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setThreatTrend((current) => [...current.slice(1), Math.max(45, Math.min(96, current[current.length - 1] + Math.round(Math.random() * 12 - 5)))]);
      setFlowTrend((current) => [...current.slice(1), Math.max(30, Math.min(96, current[current.length - 1] + Math.round(Math.random() * 14 - 6)))]);
    }, 1800);

    return () => window.clearInterval(timer);
  }, []);

  const visibleAlerts = useMemo(
    () => (selectedSource === "All" ? alerts : alerts.filter((alert) => alert.source === selectedSource)),
    [alerts, selectedSource]
  );

  const nextAction = useMemo(() => getPlaybook(selectedAlert.threat).split(".")[0], [selectedAlert]);

  const selectSource = (source) => {
    setSelectedSource(source);
    setNotice(source === "All" ? "Showing alerts from all detection sources." : `Filtered incidents detected from ${source}.`);
  };

  const refreshTelemetry = () => {
    setAlerts((current) =>
      current.map((alert, index) => ({
        ...alert,
        score: Math.max(38, Math.min(96, alert.score + (index % 2 === 0 ? 2 : -3))),
      }))
    );
    setLastSync(new Date().toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }));
    setNotice("Telemetry refreshed. Scores were recalculated from latest simulated agent signals.");
  };

  const exportReport = () => {
    const report = [
      "Security Copilot AI Agents Platform Report",
      `Generated: ${new Date().toLocaleString("en-IN")}`,
      "",
      ...alerts.map((alert) => `- ${alert.threat} | ${alert.severity} | ${alert.source} | Score ${alert.score}`),
    ].join("\n");
    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "security-copilot-report.txt";
    link.click();
    URL.revokeObjectURL(url);
    setNotice("Report exported as security-copilot-report.txt.");
  };

  const askAssistant = (alert) => {
    setSelectedAlert(alert);
    setNotice(`Assistant opened for ${alert.threat}.`);
    setActivePage("assistant");
  };

  return (
    <div className="app-shell">
      <aside className="side-nav">
        <div className="brand-block">
          <span>SC</span>
          <b>Copilot</b>
        </div>
        <nav>
          {[
            ["dashboard", "Mission"],
            ["topology", "Network"],
            ["assistant", "Assistant"],
            ["exposure", "Exposure"],
          ].map(([id, label]) => (
            <button key={id} type="button" className={activePage === id ? "active" : ""} onClick={() => setActivePage(id)}>
              {label}
            </button>
          ))}
        </nav>
      </aside>

      <main className="workspace">
        <header className="hero-bar">
          <div>
            <p className="section-kicker">Autonomous AI Security Agents</p>
            <h1>Security operations mission control</h1>
            <p>Live threat detection, source evidence, response recommendations, and analyst chat in one workspace.</p>
          </div>
          <div className="status-strip">
            <span>{lastSync} sync</span>
            <span>Backend: FastAPI agents</span>
            <span>Recommendation: {nextAction}</span>
          </div>
        </header>

        <div className="notice-bar">{notice}</div>

        {activePage === "dashboard" && (
          <>
            <RiskBrief
              alerts={alerts}
              vulnerabilities={vulnerabilities}
              onRefresh={refreshTelemetry}
              onOpenAssistant={() => setActivePage("assistant")}
              onExportReport={exportReport}
            />
            <MetricGraphCards threatTrend={threatTrend} flowTrend={flowTrend} alerts={alerts} />
            <LiveGraphs threatTrend={threatTrend} flowTrend={flowTrend} />
            <SourceBoard selectedSource={selectedSource} onSelectSource={selectSource} />
            <div className="dashboard-layout">
              <IncidentWorkbench
                alerts={visibleAlerts}
                selectedAlert={selectedAlert}
                onSelectAlert={(alert) => {
                  setSelectedAlert(alert);
                  setNotice(`${alert.threat} selected. Detected from ${alert.source}.`);
                }}
                onAsk={askAssistant}
              />
              <section className="breach-summary">
                <p className="section-kicker">Breach Agent</p>
                <h2>Current breach analysis</h2>
                <dl>
                  <div>
                    <dt>Entry point</dt>
                    <dd>{breach.entry_point ?? "Phishing Email"}</dd>
                  </div>
                  <div>
                    <dt>Affected systems</dt>
                    <dd>{breach.affected_systems ?? 4}</dd>
                  </div>
                  <div>
                    <dt>Severity</dt>
                    <dd>{breach.severity ?? "High"}</dd>
                  </div>
                  <div>
                    <dt>Recommended action</dt>
                    <dd>{breach.recommended_action ?? "Isolate infected endpoints immediately."}</dd>
                  </div>
                </dl>
              </section>
            </div>
          </>
        )}

        {activePage === "topology" && <TopologyView />}
        {activePage === "assistant" && <AssistantChat alerts={alerts} selectedAlert={selectedAlert} onSelectAlert={setSelectedAlert} />}
        {activePage === "exposure" && (
          <ExposureView
            vulnerabilities={vulnerabilities}
            selectedPlan={selectedPlan}
            onCreatePlan={(item) => {
              setSelectedPlan(item);
              setNotice(`Fix plan created for ${item.issue}: owner ${item.owner}, target SLA ${item.sla}.`);
            }}
          />
        )}
      </main>
    </div>
  );
}
