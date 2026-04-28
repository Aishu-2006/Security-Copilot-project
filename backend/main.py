from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message":"Security Copilot Running"}

@app.get("/alerts")
def alerts():
    return [
        {
            "threat":"Ransomware",
            "priority":"P1"
        },
        {
            "threat":"Credential Abuse",
            "priority":"P2"
        }
    ]