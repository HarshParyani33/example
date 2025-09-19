import requests
from urllib.parse import urlparse, parse_qs, urlencode

# Basic error-based SQLi indicators
SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query\(\):",
    "sqlite error",
]

# Simple payloads that may trigger error messages
PAYLOADS = ["'", '"', "')", '" )', "'--", '"--']


def scan(url: str):
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if not query_params:
            return {"vulnerable": False, "details": [], "notes": "No parameters to test"}

        findings = []
        max_requests = 20
        requests_made = 0
        for param in list(query_params.keys())[:10]:
            # Limit to first 2 payloads per param
            for payload in PAYLOADS[:2]:
                if requests_made >= max_requests:
                    break
                test_params = query_params.copy()
                test_params[param] = (query_params[param] or [""])[0] + payload
                full_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                r = requests.get(full_url, timeout=4)
                requests_made += 1
                body = r.text.lower()
                if any(sig in body for sig in SQL_ERROR_PATTERNS):
                    findings.append({"parameter": param, "payload": payload, "indicator": "sql_error"})
                    break
            if requests_made >= max_requests:
                break

        return {"vulnerable": bool(findings), "details": findings, "notes": "request_budget_used=%d" % requests_made}
    except Exception as e:
        return {"error": str(e)}




