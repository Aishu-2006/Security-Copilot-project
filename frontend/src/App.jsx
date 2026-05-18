import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const fallbackAlerts = [
  { threat: "Ransomware Activity", severity: "Critical", priority: "P1", entity: "system_blr", pair: "43.252.176.8 -> 142.250.240.4", score: 77.6, status: "High Risk", source: "Endpoint EDR", time: "8:38:06 PM" },
  { threat: "Credential Abuse", severity: "High", priority: "P2", entity: "system_blr", pair: "43.252.176.8 -> 142.250.31.25", score: 81.9, status: "High Risk", source: "Identity Logs", time: "8:38:04 PM" },
  { threat: "Suspicious Login Attempt", severity: "Medium", priority: "P3", entity: "system_blr", pair: "43.252.176.8 -> 142.250.216.83", score: 42.9, status: "Normal", source: "SIEM Correlation", time: "8:38:02 PM" },
  { threat: "Unauthorized Access Attempt", severity: "High", priority: "P2", entity: "raj.k", pair: "112.133.201.5 -> 142.250.176.90", score: 13.5, status: "Normal", source: "Firewall / VPC Flow", time: "8:38:00 PM" },
  { threat: "Phishing Email Attack", severity: "Medium", priority: "P3", entity: "priya.s", pair: "103.1.1.45 -> 142.250.227.246", score: 1.4, status: "Normal", source: "Email Gateway", time: "8:37:59 PM" },
  { threat: "Malware Detected", severity: "High", priority: "P2", entity: "system_blr", pair: "103.1.1.45 -> 142.250.168.172", score: 27.4, status: "Normal", source: "Endpoint EDR", time: "8:37:57 PM" },
];

const fallbackVulnerabilities = [
  { issue: "Weak Password Policy", risk: "Critical", owner: "Identity", sla: "4h" },
  { issue: "Outdated Apache Server", risk: "High", owner: "Web Tier", sla: "12h" },
  { issue: "Open SSH Port", risk: "Medium", owner: "Network", sla: "24h" },
];

const destinations = [
  { country: "IND", ip: "13.233.124.12", volume: "4.2 GB total volume", score: 12 },
  { country: "SGP", ip: "18.139.22.45", volume: "2.1 GB total volume", score: 8 },
  { country: "JPN", ip: "52.193.18.2", volume: "850 MB total volume", score: 45 },
  { country: "IND", ip: "43.252.176.8", volume: "600 MB total volume", score: 22 },
  { country: "CHN", ip: "20.42.161.124", volume: "320 MB total volume", score: 78 },
];

const icons = {
  shield: "M12 3l7 3v5c0 5-3.4 9.4-7 10-3.6-.6-7-5-7-10V6l7-3z",
  pulse: "M4 12h4l2-6 4 12 2-6h4",
  nodes: "M5 6h4v4H5zM15 6h4v4h-4zM10 16h4v4h-4zM9 8h6M7 10v3l5 3 5-3v-3",
  screen: "M4 5h16v11H4zM9 20h6",
  db: "M5 7c0-2 14-2 14 0v10c0 2-14 2-14 0V7zm0 5c0 2 14 2 14 0",
  bars: "M5 19V9M12 19V5M19 19v-7",
  lock: "M7 11h10v9H7zM9 11V8a3 3 0 116 0v3",
  search: "M10.5 18a7.5 7.5 0 110-15 7.5 7.5 0 010 15zm5.5-2l5 5",
  refresh: "M20 7v5h-5M4 17v-5h5M18 12a6 6 0 00-10-4M6 12a6 6 0 0010 4",
  cloud: "M7 18h10a4 4 0 00.8-7.9A6 6 0 006.4 8.7 4.5 4.5 0 007 18z",
};

function Icon({ name }) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none">
      <path d={icons[name]} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Sparkline({ color = "#6f72ff", values = [18, 16, 17, 15, 28, 13, 17, 22, 19] }) {
  const points = values.map((value, index) => `${index * 12},${42 - value}`).join(" ");
  return (
    <svg className="sparkline" viewBox="0 0 96 48" preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MetricCard({ icon, label, value, delta, color, values }) {
  return (
    <section className="metric-card">
      <div className="metric-top">
        <span className="metric-icon"><Icon name={icon} /></span>
        <span className="metric-delta" style={{ color }}>{delta}</span>
      </div>
      <p>{label}</p>
      <div className="metric-bottom">
        <strong>{value}</strong>
        <Sparkline color={color} values={values} />
      </div>
    </section>
  );
}

function TelemetryTable({ alerts }) {
  return (
    <section className="panel telemetry-panel">
      <div className="panel-heading">
        <h2><Icon name="pulse" /> Live Telemetry Ingestion</h2>
        <div className="legend"><span className="critical-dot" /> Critical <span className="verified-dot" /> Verified</div>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Entity</th>
              <th>Traffic Pair</th>
              <th>Score</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert, index) => (
              <tr key={`${alert.threat}-${index}`}>
                <td>{alert.time}</td>
                <td className="entity">{alert.entity}</td>
                <td>{alert.pair}</td>
                <td>
                  <span className="score-bar"><span style={{ width: `${Math.min(alert.score, 100)}%` }} /></span>
                  <b>{alert.score.toFixed(1)}</b>
                </td>
                <td><span className={`status-pill ${alert.score > 70 ? "risk" : "normal"}`}>{alert.score > 70 ? "High Risk" : "Normal"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CopilotRail({ breach, vulnerabilities }) {
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Ask about an alert, threat level, detection source, or recommended response.",
    },
  ]);

  const answerQuestion = (event) => {
    event.preventDefault();
    const value = question.trim();
    if (!value) return;

    const lower = value.toLowerCase();
    let response = "Review the alert source, score, affected entity, and evidence. Contain high-risk threats first, then validate and remediate the root cause.";

    if (lower.includes("ransomware")) {
      response = "Ransomware is critical. Isolate the endpoint, disable the account, block command-and-control traffic, preserve evidence, and restore only from clean backups.";
    } else if (lower.includes("phishing")) {
      response = "Phishing is usually detected from Email Gateway telemetry. Quarantine the message, remove matching emails, block the sender/domain, and scan clicked endpoints.";
    } else if (lower.includes("credential") || lower.includes("login")) {
      response = "Credential or login threats come from Identity Logs and SIEM correlation. Revoke sessions, reset the password, enforce MFA, and review sign-in geography.";
    } else if (lower.includes("firewall") || lower.includes("network") || lower.includes("access")) {
      response = "Network threats come from Firewall / VPC Flow logs. Block the source IP, keep deny rules active, check exposed ports, and review lateral movement.";
    } else if (lower.includes("source") || lower.includes("detect")) {
      response = "Threats are detected from Endpoint EDR, Identity Logs, Firewall / VPC Flow, Email Gateway, and SIEM Correlation rules.";
    }

    setMessages((current) => [...current, { role: "user", text: value }, { role: "assistant", text: response }]);
    setQuestion("");
  };

  return (
    <aside className="right-rail">
      <section className="panel chat-panel">
        <div className="panel-heading">
          <h2><Icon name="pulse" /> AI Chat Assistant</h2>
        </div>
        <div className="chat-messages">
          {messages.map((message, index) => (
            <div key={`${message.role}-${index}`} className={`chat-message ${message.role}`}>
              {message.text}
            </div>
          ))}
        </div>
        <form className="chat-form" onSubmit={answerQuestion}>
          <input
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="Ask what to do..."
          />
          <button type="submit">Send</button>
        </form>
      </section>
      <section className="panel health-card">
        <div className="panel-heading">
          <h2><Icon name="shield" /> System Health</h2>
          <span className="health">Healthy</span>
        </div>
        <dl>
          <div><dt>Ingestion Engine</dt><dd>Operational</dd></div>
          <div><dt>Entry Point</dt><dd>{breach.entry_point ?? "Phishing Email"}</dd></div>
          <div><dt>Affected Systems</dt><dd>{breach.affected_systems ?? 4}</dd></div>
          <div><dt>Recommended Action</dt><dd>{breach.recommended_action ?? "Isolate infected endpoints immediately."}</dd></div>
        </dl>
      </section>
      <section className="panel health-card">
        <h2>Exposure Queue</h2>
        <div className="queue">
          {vulnerabilities.map((item) => (
            <div key={item.issue}>
              <span className={`risk-dot ${item.risk.toLowerCase()}`} />
              <strong>{item.issue}</strong>
              <small>{item.owner} - SLA {item.sla}</small>
            </div>
          ))}
        </div>
      </section>
    </aside>
  );
}

function Dashboard({ alerts, breach, vulnerabilities }) {
  const metrics = [
    { icon: "pulse", label: "Anomaly Threshold", value: "92.4%", delta: "+8.2", color: "#6f72ff", values: [18, 16, 17, 15, 30, 14, 18, 23, 19] },
    { icon: "lock", label: "Containment Rate", value: "100%", delta: "Stable", color: "#12b98f", values: [24, 23, 24, 22, 31, 20, 23, 30, 28] },
    { icon: "pulse", label: "Network Entropy", value: "0.45", delta: "-0.03", color: "#f2a51f", values: [25, 24, 18, 20, 14, 16, 19, 20, 18] },
    { icon: "db", label: "Active Models", value: "12", delta: "Optimized", color: "#f15398", values: [12, 20, 14, 13, 18, 15, 21, 24, 28] },
  ];

  return (
    <>
      <section className="metric-grid">
        {metrics.map((metric) => <MetricCard key={metric.label} {...metric} />)}
      </section>
      <div className="dashboard-grid">
        <TelemetryTable alerts={alerts} />
        <CopilotRail breach={breach} vulnerabilities={vulnerabilities} />
      </div>
    </>
  );
}

function TopologyView() {
  return (
    <section className="topology-page">
      <div className="topology-title">
        <h2><Icon name="nodes" /> Network Topology & Flow Analysis</h2>
        <div>
          <button type="button">Show Flow Table</button>
          <button type="button" className="primary-button">Export Flows</button>
        </div>
      </div>
      <div className="topology-layout">
        <section className="topology-map">
          <div className="map-chip"><Icon name="nodes" /> Global Origin Analysis</div>
          <div className="node hub" />
          {[1, 2, 3, 4, 5].map((item) => <span key={item} className={`node node-${item}`} />)}
          {[1, 2, 3, 4, 5].map((item) => <span key={item} className={`link link-${item}`} />)}
          <div className="topology-stats">
            <div><span>Total Inbound</span><strong>4.2 GB</strong></div>
            <div><span>Peak Throughput</span><strong>850 Mbps</strong></div>
            <div><span>Active Streams</span><strong>1,240</strong></div>
          </div>
        </section>
        <aside className="topology-side">
          <section className="panel">
            <h2>Top Regional Destinations (Asia)</h2>
            <div className="destination-list">
              {destinations.map((destination) => (
                <div key={destination.ip} className="destination">
                  <span>{destination.country}</span>
                  <div><strong>{destination.ip}</strong><small>{destination.volume}</small></div>
                  <b className={destination.score > 70 ? "hot" : ""}>{destination.score}</b>
                </div>
              ))}
            </div>
          </section>
          <section className="panel sync-panel">
            <h2><Icon name="cloud" /> Cloud Sync Status</h2>
            <p>Real-time synchronization with AWS CloudTrail and Azure Sentinel is currently operational. VPC Flow logs are being ingested with 42ms median latency.</p>
          </section>
        </aside>
      </div>
    </section>
  );
}

function SourcesView({ alerts }) {
  const sources = ["Endpoint EDR", "Identity Logs", "Firewall / VPC Flow", "Email Gateway", "SIEM Correlation"];

  return (
    <section className="panel page-panel">
      <h2><Icon name="nodes" /> Detection Sources</h2>
      <div className="source-list">
        {sources.map((source) => (
          <article key={source}>
            <strong>{source}</strong>
            <span>{alerts.filter((alert) => alert.source === source).length} active signals</span>
            <p>
              {source === "Endpoint EDR" && "Detects ransomware, malware, suspicious scripts, and endpoint behavior."}
              {source === "Identity Logs" && "Detects credential abuse, suspicious sign-ins, MFA failures, and impossible travel."}
              {source === "Firewall / VPC Flow" && "Detects unauthorized access, port scans, denied routes, and risky traffic."}
              {source === "Email Gateway" && "Detects phishing, spoofed domains, unsafe links, and malicious attachments."}
              {source === "SIEM Correlation" && "Combines endpoint, identity, network, and email events into correlated incidents."}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}

function AssetsView({ alerts }) {
  return (
    <section className="panel page-panel">
      <h2><Icon name="screen" /> Protected Assets</h2>
      <div className="asset-grid">
        {[...new Map(alerts.map((alert) => [alert.entity, alert])).values()].map((alert) => (
          <article key={alert.entity}>
            <strong>{alert.entity}</strong>
            <span>{alert.source}</span>
            <p>{alert.threat}</p>
            <b className={alert.score > 70 ? "asset-risk" : ""}>{alert.score.toFixed(1)}</b>
          </article>
        ))}
      </div>
    </section>
  );
}

function DataView({ vulnerabilities }) {
  return (
    <section className="panel page-panel">
      <h2><Icon name="db" /> Exposure Data</h2>
      <div className="source-list">
        {vulnerabilities.map((item) => (
          <article key={item.issue}>
            <strong>{item.issue}</strong>
            <span>{item.risk} risk</span>
            <p>Owner: {item.owner}. Remediation SLA: {item.sla}.</p>
          </article>
        ))}
      </div>
    </section>
  );
}

function ReportsView({ alerts, vulnerabilities }) {
  const highRisk = alerts.filter((alert) => alert.score > 70).length;

  return (
    <section className="panel page-panel">
      <h2><Icon name="bars" /> Security Reports</h2>
      <div className="report-grid">
        <article><span>Total Alerts</span><strong>{alerts.length}</strong></article>
        <article><span>High Risk Alerts</span><strong>{highRisk}</strong></article>
        <article><span>Open Exposures</span><strong>{vulnerabilities.length}</strong></article>
        <article><span>Containment</span><strong>100%</strong></article>
      </div>
      <p className="report-note">Report summary is generated from live telemetry, vulnerability data, and breach analysis.</p>
    </section>
  );
}

function enrichAlert(alert, index) {
  return { ...fallbackAlerts[index % fallbackAlerts.length], ...alert };
}

export default function App() {
  const [activePage, setActivePage] = useState("dashboard");
  const [alerts, setAlerts] = useState(fallbackAlerts);
  const [vulnerabilities, setVulnerabilities] = useState(fallbackVulnerabilities);
  const [breach, setBreach] = useState({});
  const [lastSync, setLastSync] = useState("Simulation Mode");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsResponse, vulnerabilitiesResponse, breachResponse] = await Promise.all([
          axios.get("http://127.0.0.1:8000/alerts"),
          axios.get("http://127.0.0.1:8000/vulnerabilities"),
          axios.get("http://127.0.0.1:8000/breach-analysis"),
        ]);
        setAlerts(alertsResponse.data.map((alert, index) => enrichAlert(alert, index)));
        setVulnerabilities(vulnerabilitiesResponse.data.map((item, index) => ({ ...fallbackVulnerabilities[index % fallbackVulnerabilities.length], ...item })));
        setBreach(breachResponse.data);
        setLastSync(new Date().toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" }));
      } catch {
        setLastSync("Simulation Mode");
      }
    };
    fetchData();
  }, []);

  const navItems = useMemo(() => [
    ["dashboard", "shield"],
    ["topology", "pulse"],
    ["sources", "nodes"],
    ["assets", "screen"],
    ["data", "db"],
    ["reports", "bars"],
  ], []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-mark"><Icon name="shield" /></div>
        <nav>
          {navItems.map(([id, icon]) => (
            <button key={id} className={activePage === id ? "active" : ""} type="button" onClick={() => setActivePage(id)} title={id}>
              <Icon name={icon} />
            </button>
          ))}
        </nav>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <p className="eyebrow">Security Co-pilot Platform</p>
          </div>
          <div className="topbar-actions">
            <span className="mode-pill">{lastSync}</span>
            <label className="search-box"><Icon name="search" /><input placeholder="Search Indian infrastructure..." /></label>
            <button className="icon-button" type="button" title="Refresh telemetry"><Icon name="refresh" /></button>
            <button className="profile-button" type="button">A</button>
          </div>
        </header>
        {activePage === "topology" ? (
          <TopologyView />
        ) : activePage === "sources" ? (
          <SourcesView alerts={alerts} />
        ) : activePage === "assets" ? (
          <AssetsView alerts={alerts} />
        ) : activePage === "data" ? (
          <DataView vulnerabilities={vulnerabilities} />
        ) : activePage === "reports" ? (
          <ReportsView alerts={alerts} vulnerabilities={vulnerabilities} />
        ) : (
          <Dashboard alerts={alerts} breach={breach} vulnerabilities={vulnerabilities} />
        )}
      </main>
    </div>
  );
}
