import requests


def scan(url: str):
    """Check permissive CORS by sending an Origin and inspecting ACAO/ACAC headers."""
    try:
        origin = "https://evil.example"
        r = requests.get(url, headers={"Origin": origin}, timeout=3)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")

        issues = []
        if acao == "*":
            issues.append({"issue": "ACAO wildcard", "header": acao})
        if acao == origin and acac.lower() == "true":
            issues.append({"issue": "ACAO reflects arbitrary origin with credentials", "header": acao})

        return {"vulnerable": bool(issues), "details": issues}
    except Exception as e:
        return {"error": str(e)}




