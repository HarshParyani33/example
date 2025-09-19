import requests


def scan(url: str):
    """Check Set-Cookie flags for Secure and HttpOnly on session-like cookies."""
    try:
        r = requests.get(url, timeout=3)
        cookies = r.headers.get("Set-Cookie")
        if not cookies:
            return {"vulnerable": False, "details": [], "notes": "No cookies set"}

        details = []
        cookie_headers = r.headers.get_all("Set-Cookie") if hasattr(r.headers, 'get_all') else [cookies]
        for c in cookie_headers:
            name = c.split("=", 1)[0]
            is_secure = "secure" in c.lower()
            is_httponly = "httponly" in c.lower()
            if not (is_secure and is_httponly):
                details.append({
                    "cookie": name,
                    "secure": is_secure,
                    "httponly": is_httponly,
                })

        return {"vulnerable": bool(details), "details": details}
    except Exception as e:
        return {"error": str(e)}




