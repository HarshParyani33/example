import requests
from urllib.parse import urlparse, parse_qs, urlencode

PAYLOADS = ['"><script>alert(1)</script>', '<img src=x onerror=alert(1)>', "';alert(1)//"]

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
        # Hard cap on total HTTP requests made by this check
        max_requests = 15
        requests_made = 0
        for param in list(query_params.keys())[:10]:
            found_for_param = False
            # Test only the first 2 payloads per parameter
            for payload in PAYLOADS[:2]:
                if requests_made >= max_requests:
                    break
                test_params = query_params.copy()
                test_params[param] = payload
                full_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                r = requests.get(full_url, timeout=4)
                requests_made += 1
                if payload in r.text:
                    vulnerable.append({"parameter": param, "payload": payload})
                    found_for_param = True
                    break
            if requests_made >= max_requests:
                break
            if found_for_param:
                continue

        return {"vulnerable": bool(vulnerable), "details": vulnerable, "notes": "request_budget_used=%d" % requests_made}
    except Exception as e:
        return {"error": str(e)}
