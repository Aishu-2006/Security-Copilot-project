# Security Copilot AI Agents Platform

React + Vite frontend for an autonomous security operations dashboard. The interface presents live telemetry, AI agent triage, incident priority, vulnerability exposure, breach summary, and network topology analysis.

## Run The Frontend

```bash
npm install
npm run dev
```

Open the Vite URL shown in the terminal, usually:

```text
http://localhost:5173
```

## Optional Backend

The frontend reads from these FastAPI endpoints when the backend is running:

```text
GET http://127.0.0.1:8000/alerts
GET http://127.0.0.1:8000/vulnerabilities
GET http://127.0.0.1:8000/breach-analysis
```

If the backend is not running, the dashboard automatically uses demo telemetry so the presentation still works.

## Implemented Views

- Command dashboard with anomaly threshold, containment rate, entropy, and active model metrics.
- Live telemetry ingestion table with risk scoring and status badges.
- AI Copilot rail with incident summary and recommended containment action.
- Agent summaries for triage, priority routing, and breach response.
- Network topology and flow analysis with regional destinations and cloud sync status.

## Validation

```bash
npm run lint
npm run build
```
