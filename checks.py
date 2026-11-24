"""
checks.py — the detection logic.

Active checks (send payloads):
  - SQL injection, error-based with a baseline diff to cut false positives
  - Reflected XSS, confirmed by unescaped reflection of a unique marker

Passive checks (no payloads, just inspect the response):
  - Missing/weak HTTP security headers
  - Insecure cookie flags (HttpOnly, Secure, SameSite)
  - Forms with no apparent CSRF token

Every check returns zero or more finding dicts:
  {category, type, severity, url, detail, evidence, payload}
"""

import re
import requests

TIMEOUT = 8

# Distinctive database error signatures. Deliberately specific — bare words
# like "warning" or "mysql" caused false positives in the original version.
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\)|postgresql.*error|psql:",
    r"sqlite_?error|sqlite3::|unrecognized token",
    r"microsoft ole db provider|odbc sql server driver|incorrect syntax near",
    r"\bora-\d{5}\b|oracle error",
    r"mysql_fetch_|supplied argument is not a valid mysql",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# A marker whose special characters must survive unescaped for XSS to fire.
XSS_MARKER = "wvs7x9<\">z"

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _finding(category, vtype, severity, url, detail, evidence="", payload=""):
    return {"category": category, "type": vtype, "severity": severity,
            "url": url, "detail": detail, "evidence": evidence, "payload": payload}


def _send(session, action, method, data):
    try:
        if method == "post":
            return session.post(action, data=data, timeout=TIMEOUT)
        return session.get(action, params=data, timeout=TIMEOUT)
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# Active: SQL injection (error-based with baseline comparison)
# ---------------------------------------------------------------------------
def test_sqli(session, action, method, base_params, sqli_payloads):
    """
    Inject each payload into each parameter, one at a time. Flag only if a DB
    error signature appears that was NOT already in the clean baseline response.
    """
    findings = []
    baseline = _send(session, action, method, base_params)
    baseline_text = baseline.text.lower() if baseline is not None else ""
    baseline_has_error = bool(SQL_ERROR_RE.search(baseline_text))

    for param in base_params:
        for payload in sqli_payloads:
            data = dict(base_params)
            data[param] = payload
            resp = _send(session, action, method, data)
            if resp is None:
                continue
            match = SQL_ERROR_RE.search(resp.text)
            if match and not baseline_has_error:
                findings.append(_finding(
                    "injection", "SQL Injection", "High", action,
                    f"Parameter '{param}' returned a database error when injected.",
                    evidence=match.group(0)[:120], payload=payload))
                break  # one confirmation per parameter is enough
    return findings


# ---------------------------------------------------------------------------
# Active: reflected XSS (confirmed unescaped reflection)
# ---------------------------------------------------------------------------
def test_xss(session, action, method, base_params):
    """Inject a marker with special chars; flag only if it is reflected unescaped."""
    findings = []
    for param in base_params:
        data = dict(base_params)
        data[param] = XSS_MARKER
        resp = _send(session, action, method, data)
        if resp is None:
            continue
        # If the raw marker (with its < " > intact) appears, output is not escaped.
        if XSS_MARKER in resp.text:
            findings.append(_finding(
                "injection", "Reflected XSS", "Medium", action,
                f"Parameter '{param}' reflects input without HTML-encoding.",
                evidence=XSS_MARKER, payload=XSS_MARKER))
    return findings


# ---------------------------------------------------------------------------
# Passive: HTTP security headers
# ---------------------------------------------------------------------------
SECURITY_HEADERS = [
    ("Content-Security-Policy", "Medium",
     "No CSP; the page has no policy restricting script/content sources."),
    ("Strict-Transport-Security", "Medium",
     "No HSTS; browsers may allow downgrade to plain HTTP."),
    ("X-Frame-Options", "Low",
     "No framing protection; the page may be vulnerable to clickjacking."),
    ("X-Content-Type-Options", "Low",
     "Missing 'nosniff'; browsers may MIME-sniff responses."),
    ("Referrer-Policy", "Low",
     "No referrer policy; full URLs may leak to other sites."),
]


def check_security_headers(response, url):
    findings = []
    headers = {k.lower(): v for k, v in response.headers.items()}
    is_https = url.lower().startswith("https")
    for name, severity, detail in SECURITY_HEADERS:
        if name.lower() == "strict-transport-security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        if name.lower() not in headers:
            findings.append(_finding("headers", f"Missing {name}", severity,
                                     url, detail))
    # Information disclosure via Server / X-Powered-By
    for h in ("server", "x-powered-by"):
        if headers.get(h):
            findings.append(_finding("headers", f"Info disclosure: {h}", "Info",
                                     url, f"Response reveals '{h}: {headers[h]}'.",
                                     evidence=headers[h]))
    return findings


# ---------------------------------------------------------------------------
# Passive: cookie security flags
# ---------------------------------------------------------------------------
def check_cookies(response, url):
    findings = []
    is_https = url.lower().startswith("https")
    # Use raw Set-Cookie headers so flags can be read exactly as sent.
    raw = response.headers.get("Set-Cookie")
    if not raw:
        return findings
    # requests collapses multiple cookies; split conservatively on ', <name>='
    cookies = re.split(r",(?=[^;]+?=)", raw)
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if "httponly" not in low:
            findings.append(_finding("cookies", "Cookie missing HttpOnly", "Medium",
                                     url, f"Cookie '{name}' is readable by JavaScript."))
        if is_https and "secure" not in low:
            findings.append(_finding("cookies", "Cookie missing Secure", "Medium",
                                     url, f"Cookie '{name}' may be sent over plain HTTP."))
        if "samesite" not in low:
            findings.append(_finding("cookies", "Cookie missing SameSite", "Low",
                                     url, f"Cookie '{name}' has no SameSite attribute (CSRF risk)."))
    return findings


# ---------------------------------------------------------------------------
# Passive: CSRF token presence on state-changing forms
# ---------------------------------------------------------------------------
TOKEN_HINT = re.compile(r"csrf|token|nonce|authenticity|_wpnonce", re.IGNORECASE)


def check_csrf(form, url):
    if form["method"] != "post":
        return []
    names = " ".join(i["name"] for i in form["inputs"])
    if not TOKEN_HINT.search(names):
        return [_finding("csrf", "Form without CSRF token", "Medium", url,
                         f"POST form to '{form['action']}' has no hidden token field.")]
    return []
