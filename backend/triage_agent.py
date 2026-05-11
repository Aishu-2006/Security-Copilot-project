def classify_alert(alert):

    alert = alert.lower()

    if "ransomware" in alert:
        return "Critical"

    elif "unauthorized" in alert:
        return "High"

    elif "malware" in alert:
        return "High"

    elif "phishing" in alert:
        return "Medium"

    elif "login" in alert:
        return "Medium"

    return "Low"