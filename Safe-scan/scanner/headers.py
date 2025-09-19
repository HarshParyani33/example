import requests

HEADERS_TO_CHECK = [
    'X-Frame-Options',
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy'
]

SEVERITY = {
    'X-Frame-Options': 'Medium',
    'Content-Security-Policy': 'Critical',
    'Strict-Transport-Security': 'Critical',
    'X-Content-Type-Options': 'Medium',
    'Referrer-Policy': 'Low',
    'Permissions-Policy': 'Low'
}

def check_headers(url):
    try:
        # Prefer HEAD for speed; fall back to GET if HEAD is not allowed
        try:
            r = requests.head(url, timeout=3, allow_redirects=True)
            # Some servers return no headers on HEAD; fall back to GET
            if not r.headers:
                r = requests.get(url, timeout=3)
        except Exception:
            r = requests.get(url, timeout=3)
        missing = [h for h in HEADERS_TO_CHECK if h not in r.headers]
        details = [{"header": h, "severity": SEVERITY[h]} for h in missing]
        return {"all_headers": dict(r.headers), "missing_headers": details}
    except Exception as e:
        return {"error": str(e)}
