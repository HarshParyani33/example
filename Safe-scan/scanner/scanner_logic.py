import datetime
from urllib.parse import urlparse

from . import headers as headers_scan
from . import redirect as redirect_scan
from . import xss as xss_scan
from . import sqli as sqli_scan
from . import cors as cors_scan
from . import cookies as cookies_scan


def _normalize_url(input_url: str) -> str:
    """Ensure URL has a scheme; default to http if missing."""
    if not input_url:
        return input_url
    parsed = urlparse(input_url)
    if not parsed.scheme:
        return f"http://{input_url}"
    return input_url


def run_scan(url, checks):
    result = {}
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    normalized_url = _normalize_url(url)
    result["meta"] = {
        "url": normalized_url,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "selected_checks": {k: bool(v) for k, v in (checks or {}).items()},
    }

    # HTTP Headers Check
    if checks.get("headers"):
        headers_result = headers_scan.check_headers(normalized_url)
        result["headers"] = headers_result
        if headers_result.get("missing_headers"):
            for item in headers_result["missing_headers"]:
                severity = (item.get("severity") or "low").lower()
                if severity in summary:
                    summary[severity] += 1

    # Open Redirect Check
    if checks.get("redirect"):
        redirect_result = redirect_scan.scan(normalized_url)
        result["redirect"] = redirect_result
        if redirect_result.get("vulnerable"):
            findings = redirect_result.get("details") or [1]
            summary["high"] += len(findings)

    # XSS Check
    if checks.get("xss"):
        xss_result = xss_scan.scan(normalized_url)
        result["xss"] = xss_result
        if xss_result.get("vulnerable"):
            findings = xss_result.get("details") or [1]
            summary["critical"] += len(findings)

    # SQLi Check (error-based)
    if checks.get("sqli"):
        sqli_result = sqli_scan.scan(normalized_url)
        result["sqli"] = sqli_result
        if sqli_result.get("vulnerable"):
            findings = sqli_result.get("details") or [1]
            summary["high"] += len(findings)

    # CORS Misconfiguration Check
    if checks.get("cors"):
        cors_result = cors_scan.scan(normalized_url)
        result["cors"] = cors_result
        if cors_result.get("vulnerable"):
            findings = cors_result.get("details") or [1]
            summary["medium"] += len(findings)

    # Insecure Cookie Flags Check
    if checks.get("cookies"):
        cookies_result = cookies_scan.scan(normalized_url)
        result["cookies"] = cookies_result
        if cookies_result.get("vulnerable"):
            findings = cookies_result.get("details") or [1]
            summary["low"] += len(findings)

    return result, summary
