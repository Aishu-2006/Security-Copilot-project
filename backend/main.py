from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import random

from triage_agent import classify_alert
from priority_agent import assign_priority
from vulnerability_agent import scan_vulnerabilities
from breach_agent import analyze_breach

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

threat_samples = [
    "Ransomware Activity",
    "Credential Abuse",
    "Suspicious Login Attempt",
    "Malware Detected",
    "Phishing Email Attack",
    "Unauthorized Access Attempt"
]


@app.get("/")
def home():
    return {"message": "Microsoft Security Copilot Backend Running"}


@app.get("/alerts")
def get_alerts():

    alerts = []

    for i in range(5):

        threat = random.choice(threat_samples)

        severity = classify_alert(threat)

        priority = assign_priority(severity)

        alerts.append({
            "threat": threat,
            "severity": severity,
            "priority": priority
        })

    return alerts


@app.get("/vulnerabilities")
def vulnerabilities():

    return scan_vulnerabilities()


@app.get("/breach-analysis")
def breach_analysis():

    return analyze_breach()