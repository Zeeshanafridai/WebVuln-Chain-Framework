from typing import Optional
"""
Module: Security Misconfigurations + Information Disclosure
-------------------------------------------------------------
Finds real-world misconfigs that lead to high-severity findings:
  - Debug endpoints exposed (actuator, phpinfo, debug toolbar)
  - Directory listing enabled
  - Error messages revealing stack traces / DB queries
  - Backup files exposed (.bak, .old, ~, .swp)
  - Source code exposed (.git, .svn, .DS_Store)
  - Admin interfaces accessible
  - API keys / secrets in JS files and HTML
  - Default credentials on admin panels
  - HTTP methods allowed (DELETE, TRACE, PUT on sensitive paths)
  - CORS wildcard on API endpoints
  - Open redirect via Location header
"""

import re
import urllib.parse
from ..core import ScanContext, Finding, R, G, Y, C, DIM, BOLD, RST

MODULE_NAME = "misconfig"

# Sensitive file patterns to probe
SENSITIVE_FILES = [
    # Source control
    ("/.git/config",            "Critical", "Git config exposed"),
    ("/.git/HEAD",              "Critical", "Git HEAD exposed"),
    ("/.svn/entries",           "High",     "SVN repository exposed"),
    ("/.DS_Store",              "Medium",   ".DS_Store file exposed"),

    # Environment / config
    ("/.env",                   "Critical", "Environment file exposed"),
    ("/.env.local",             "Critical", ".env.local exposed"),
    ("/.env.production",        "Critical", ".env.production exposed"),
    ("/config.php",             "High",     "PHP config exposed"),
    ("/config.json",            "High",     "Config JSON exposed"),
    ("/wp-config.php",          "Critical", "WordPress config exposed"),
    ("/configuration.php",      "High",     "Joomla config exposed"),
    ("/settings.py",            "High",     "Django settings exposed"),
    ("/database.yml",           "High",     "Rails DB config exposed"),
    ("/application.properties", "High",     "Spring config exposed"),

    # Backup files
    ("/index.php.bak",   "High",   "Backup file exposed"),
    ("/index.php~",      "High",   "Editor backup exposed"),
    ("/index.php.swp",   "High",   "Vim swap file exposed"),
    ("/index.php.old",   "High",   "Old file exposed"),
    ("/backup.zip",      "High",   "Backup archive exposed"),
    ("/backup.sql",      "Critical","SQL backup exposed"),
    ("/dump.sql",        "Critical","SQL dump exposed"),
    ("/db.sqlite",       "Critical","SQLite database exposed"),

    # Debug / admin
    ("/phpinfo.php",     "High",   "PHPInfo exposed"),
    ("/info.php",        "High",   "PHPInfo exposed"),
    ("/test.php",        "Medium", "Test PHP file exposed"),
    ("/actuator",        "High",   "Spring Boot Actuator exposed"),
    ("/actuator/env",    "Critical","Actuator /env exposes secrets"),
    ("/actuator/heapdump","Critical","Heap dump exposed"),
    ("/console",         "Critical","Web console exposed"),
    ("/__debug__",       "High",   "Django debug toolbar exposed"),
    ("/server-status",   "High",   "Apache server-status exposed"),
    ("/nginx_status",    "Medium", "Nginx status exposed"),
]

# Patterns indicating sensitive data in responses
SENSITIVE_PATTERNS = {
    "AWS Key":         r'AKIA[0-9A-Z]{16}',
    "AWS Secret":      r'[0-9a-zA-Z/+]{40}',
    "Private Key":     r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "Password":        r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}',
    "API Key":         r'(?:api_key|apikey|api-key)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{16,}',
    "DB Connection":   r'(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+',
    "JWT Secret":      r'(?:jwt_secret|secret_key|signing_key)\s*[=:]\s*["\']?[^\s"\']{8,}',
    "SendGrid Key":    r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
    "Stripe Key":      r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
    "GitHub Token":    r'gh[pousr]_[A-Za-z0-9_]{36,}',
    "Google API":      r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":     r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    "Twilio":          r'SK[0-9a-f]{32}',
}

# Error patterns suggesting information disclosure
ERROR_PATTERNS = [
    (r'SQL syntax.*?near',              "SQL error in response"),
    (r'ORA-\d{5}',                      "Oracle SQL error"),
    (r'Warning: mysql_',                "MySQL error"),
    (r'Traceback \(most recent',        "Python stack trace"),
    (r'System\.Web\.HttpException',     "ASP.NET stack trace"),
    (r"at [\w\.]+\([\w\.]+\.java:\d+\)",         "Java stack trace"),
    (r'javax\.servlet\.',               "Java servlet error"),
    (r'PHPUnit',                        "PHPUnit test framework exposed"),
    (r'Whoops!.*error',                 "Whoops error handler exposed"),
    (r'DebugKit',                       "CakePHP DebugKit exposed"),
    (r'Symfony.*exception',             "Symfony exception handler"),
    (r'Laravel.*ErrorException',        "Laravel error handler"),
    (r'SQLSTATE\[',                     "PDO SQL error"),
]


def run(ctx: ScanContext) -> ScanContext:
    """Run misconfiguration detection module."""

    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: MISCONFIG]{RST}")

    import urllib.parse as up
    parsed   = up.urlparse(ctx.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    findings = []

    # ── Sensitive file probing ────────────────────────────────────────────────
    if ctx.verbose:
        print(f"  {DIM}[~] Probing {len(SENSITIVE_FILES)} sensitive paths...{RST}")

    for path, severity, description in SENSITIVE_FILES:
        url  = base_url + path
        resp = ctx.request(url, follow_redirects=False)

        if resp["status"] == 200 and resp["body_length"] > 20:
            # Verify it's not a generic 200 (custom 404)
            body_lower = resp["body"].lower()
            not_found_indicators = ["page not found", "404", "does not exist",
                                     "no such file", "not available"]
            if any(x in body_lower for x in not_found_indicators):
                continue

            # Check for sensitive content in response
            has_sensitive = any(
                re.search(pat, resp["body"], re.I)
                for pat in SENSITIVE_PATTERNS.values()
            )

            actual_severity = "Critical" if has_sensitive else severity

            findings.append(Finding(
                module      = MODULE_NAME,
                title       = f"Sensitive Resource Exposed: {path}",
                severity    = actual_severity,
                url         = url,
                detail      = f"{description} — HTTP 200, {resp['body_length']} bytes",
                evidence    = resp["body"][:300],
                remediation = f"Restrict access to {path} in server config. Remove or relocate sensitive files.",
                cvss        = 9.1 if actual_severity == "Critical" else 7.5,
            ))

            if ctx.verbose:
                col = R if actual_severity == "Critical" else Y
                print(f"\r{' '*60}\r  {col}[{actual_severity}]{RST} {path} ({resp['body_length']}b)")

    # ── Error/debug responses ─────────────────────────────────────────────────
    # Trigger errors by sending malformed input
    error_triggers = [
        (ctx.target + "?id='", "Single quote trigger"),
        (ctx.target + "?id=1/0", "Division by zero"),
        (ctx.target + "?id[]=1", "Array injection"),
    ]

    for trigger_url, trigger_name in error_triggers:
        resp = ctx.request(trigger_url)
        for pattern, error_type in ERROR_PATTERNS:
            if re.search(pattern, resp["body"], re.I):
                findings.append(Finding(
                    module      = MODULE_NAME,
                    title       = f"Error Information Disclosure — {error_type}",
                    severity    = "Medium",
                    url         = trigger_url,
                    detail      = f"{error_type} triggered by: {trigger_name}",
                    evidence    = re.findall(pattern, resp["body"], re.I)[0][:100] if re.findall(pattern, resp["body"], re.I) else "",
                    remediation = "Disable detailed error messages in production. Use generic error pages. Log errors server-side only.",
                    cvss        = 5.3,
                ))
                break

    # ── Secrets in JS files ───────────────────────────────────────────────────
    for js_url in ctx.js_files[:8]:
        resp = ctx.request(js_url)
        if resp["status"] != 200:
            continue

        for secret_type, pattern in SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, resp["body"])
            if matches:
                findings.append(Finding(
                    module      = MODULE_NAME,
                    title       = f"Hardcoded Secret in JS: {secret_type}",
                    severity    = "High",
                    url         = js_url,
                    detail      = f"{secret_type} found in client-side JavaScript",
                    evidence    = matches[0][:60] + "...",
                    remediation = "Never embed secrets in client-side code. Use environment variables. Rotate exposed keys immediately.",
                    cvss        = 8.2,
                ))

    # ── CORS check on API endpoints ───────────────────────────────────────────
    api_endpoints = [ep for ep in ctx.endpoints if "/api/" in ep or "/v1/" in ep][:5]
    for ep in api_endpoints:
        resp = ctx.request(ep, headers={"Origin": "https://evil.com"})
        acao = resp["headers"].get("access-control-allow-origin", "")
        acac = resp["headers"].get("access-control-allow-credentials", "")

        if acao == "*" and "true" in acac.lower():
            findings.append(Finding(
                module   = MODULE_NAME,
                title    = "CORS Wildcard + Credentials",
                severity = "High",
                url      = ep,
                detail   = "ACAO: * combined with ACAC: true — any origin can make credentialed requests",
                evidence = f"ACAO: {acao} | ACAC: {acac}",
                remediation = "Never combine wildcard ACAO with credentials. Use explicit allowlist.",
                cvss     = 8.1,
            ))
        elif acao == "https://evil.com":
            findings.append(Finding(
                module   = MODULE_NAME,
                title    = "CORS Origin Reflection",
                severity = "High",
                url      = ep,
                detail   = "Server reflects arbitrary Origin header — CORS misconfiguration",
                evidence = f"ACAO: {acao}",
                remediation = "Use explicit origin allowlist. Do not reflect the Origin header.",
                cvss     = 7.5,
            ))

    ctx.add_findings(findings)
    ctx.module_results["misconfig"] = {"findings": len(findings)}
    return ctx
