import requests
from urllib.parse import urlparse, parse_qs, urlencode

PARAMS = ['redirect', 'url', 'next', 'dest']

def scan(url):
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # Cap params scanned to avoid very large URLs causing slow scans
        if len(query_params) > 10:
            query_params = dict(list(query_params.items())[:10])
        if not query_params:
            return {"vulnerable": False, "details": [], "notes": "No parameters to test"}

        vulnerable = []
        max_requests = 12
        requests_made = 0
        for param in PARAMS:
            if param in query_params:
                test_params = query_params.copy()
                test_params[param] = 'http://example.com'
                full_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                if requests_made >= max_requests:
                    break
                r = requests.get(full_url, allow_redirects=False, timeout=3)
                location = r.headers.get('Location', '')
                if 'example.com' in location:
                    vulnerable.append({"parameter": param, "redirected_to": location})
                requests_made += 1

        return {"vulnerable": bool(vulnerable), "details": vulnerable, "notes": "request_budget_used=%d" % requests_made}
    except Exception as e:
        return {"error": str(e)}
