from typing import Optional
"""
Module: Recon
--------------
First module in every chain. Gathers intelligence:
  - Tech stack fingerprinting (framework, server, CMS, language)
  - Endpoint discovery from HTML links, JS imports, sitemaps
  - Form enumeration (action URLs, input fields, methods)
  - JS file collection for later analysis
  - Cookie/token extraction from responses
  - Security header analysis
  - Content discovery (robots.txt, sitemap.xml, .well-known)

Feeds into: XSS, SQLi, CSRF, IDOR, Header Injection modules
"""

import re
import json
import urllib.parse
from ..core import ScanContext, Finding, http_request, R, G, Y, C, DIM, BOLD, RST

MODULE_NAME = "recon"

# Tech stack fingerprints
TECH_FINGERPRINTS = {
    "PHP":           [r"\.php", r"X-Powered-By.*PHP", r"PHPSESSID"],
    "ASP.NET":       [r"\.aspx?", r"X-AspNet-Version", r"__VIEWSTATE", r"ASP\.NET"],
    "Java/Spring":   [r"JSESSIONID", r"\.jsp", r"org\.springframework"],
    "Django":        [r"csrfmiddlewaretoken", r"Django", r"djdt"],
    "Rails":         [r"authenticity_token", r"_rails", r"X-Request-Id.*rails"],
    "Laravel":       [r"laravel_session", r"_token.*[a-zA-Z0-9]{40}", r"Laravel"],
    "Express/Node":  [r"connect\.sid", r"X-Powered-By.*Express"],
    "WordPress":     [r"wp-content", r"wp-login\.php", r"wordpress"],
    "Drupal":        [r"Drupal\.settings", r"/sites/default/", r"drupal"],
    "Joomla":        [r"joomla", r"/components/com_", r"mosConfig"],
    "React":         [r"__REACT_", r"data-reactroot", r"react\.development"],
    "Angular":       [r"ng-version", r"_nghost", r"ng-binding"],
    "Vue":           [r"__vue__", r"data-v-", r"vue\.min\.js"],
    "Nginx":         [r"nginx"],
    "Apache":        [r"Apache"],
    "Cloudflare":    [r"cf-ray", r"__cfduid", r"cloudflare"],
    "AWS":           [r"X-Amz-", r"amazonaws\.com", r"AWSELBAuthSessionCookie"],
    "GCP":           [r"x-goog-", r"googleapis\.com"],
    "Azure":         [r"x-ms-request-id", r"azurewebsites\.net"],
}

# Security header checks
SECURITY_HEADERS = {
    "Content-Security-Policy":   "Missing CSP — XSS risk",
    "X-Frame-Options":           "Missing — clickjacking risk",
    "X-Content-Type-Options":    "Missing — MIME sniffing risk",
    "Strict-Transport-Security": "Missing HSTS",
    "Referrer-Policy":           "Missing referrer policy",
    "Permissions-Policy":        "Missing permissions policy",
    "X-XSS-Protection":          "Missing legacy XSS protection",
}

# Common content discovery paths
CONTENT_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/api", "/api/v1",
    "/api/v2", "/api/docs", "/swagger.json", "/openapi.json",
    "/graphql", "/.git/HEAD", "/.env", "/config.json",
    "/admin", "/admin/", "/login", "/register",
    "/api/users", "/api/user/me", "/api/profile",
    "/wp-admin", "/wp-login.php",
    "/phpinfo.php", "/info.php", "/.htaccess",
    "/server-status", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings",
    "/metrics", "/health", "/status", "/ping",
    "/_debug_toolbar", "/debug", "/__debug__",
    "/console", "/shell", "/terminal",
]


def run(ctx: ScanContext) -> ScanContext:
    """Run recon module against target."""

    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: RECON]{RST}")
        print(f"  {DIM}Fingerprinting + endpoint discovery...{RST}\n")

    parsed   = urllib.parse.urlparse(ctx.target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # ── Fetch base page ───────────────────────────────────────────────────────
    resp = ctx.request(ctx.target)

    if resp["status"] == 0:
        if ctx.verbose:
            print(f"  {R}[!] Target unreachable: {resp['error']}{RST}")
        return ctx

    body    = resp["body"]
    headers = resp["headers"]

    # ── Tech stack fingerprinting ─────────────────────────────────────────────
    all_text = body + " " + json.dumps(headers)
    for tech, patterns in TECH_FINGERPRINTS.items():
        for pat in patterns:
            if re.search(pat, all_text, re.I):
                if tech not in ctx.tech_stack:
                    ctx.tech_stack.append(tech)
                break

    if ctx.verbose and ctx.tech_stack:
        print(f"  {G}[+]{RST} Tech stack: {', '.join(ctx.tech_stack)}")

    # ── Security headers analysis ─────────────────────────────────────────────
    missing_headers = []
    for hdr, issue in SECURITY_HEADERS.items():
        if hdr.lower() not in headers:
            missing_headers.append(hdr)
            ctx.add_finding(Finding(
                module      = MODULE_NAME,
                title       = f"Missing Security Header: {hdr}",
                severity    = "Low",
                url         = ctx.target,
                detail      = issue,
                remediation = f"Add '{hdr}' response header with appropriate value",
                cvss        = 3.1,
            ))

    # ── Server info disclosure ────────────────────────────────────────────────
    server = headers.get("server", "")
    xpb    = headers.get("x-powered-by", "")
    if server and any(v in server for v in ["nginx/", "Apache/", "Microsoft-IIS/"]):
        ctx.add_finding(Finding(
            module   = MODULE_NAME,
            title    = "Server Version Disclosure",
            severity = "Info",
            url      = ctx.target,
            detail   = f"Server header reveals version: {server}",
            evidence = f"Server: {server}",
            remediation = "Remove or genericize the Server header",
            cvss     = 2.0,
        ))
    if xpb:
        ctx.add_finding(Finding(
            module   = MODULE_NAME,
            title    = "Technology Disclosure via X-Powered-By",
            severity = "Info",
            url      = ctx.target,
            detail   = f"X-Powered-By reveals backend: {xpb}",
            evidence = f"X-Powered-By: {xpb}",
            remediation = "Remove the X-Powered-By header",
            cvss     = 2.0,
        ))

    # ── Cookie analysis ───────────────────────────────────────────────────────
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        _analyze_cookies(ctx, set_cookie, resp)

    # ── Endpoint discovery from HTML ──────────────────────────────────────────
    endpoints = _extract_endpoints(body, base_url, ctx.target)
    for ep in endpoints:
        if ep not in ctx.endpoints:
            ctx.endpoints.append(ep)

    # ── JS file collection ────────────────────────────────────────────────────
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I):
        src = _absolutize(m.group(1), base_url, ctx.target)
        if src and src not in ctx.js_files:
            ctx.js_files.append(src)

    # ── Form enumeration ──────────────────────────────────────────────────────
    forms = _extract_forms(body, base_url, ctx.target)
    ctx.forms.extend(forms)

    # ── Content discovery ─────────────────────────────────────────────────────
    if ctx.verbose:
        print(f"  {C}[*]{RST} Content discovery ({len(CONTENT_PATHS)} paths)...")

    sensitive_found = []
    for path in CONTENT_PATHS:
        url  = base_url + path
        r    = ctx.request(url, follow_redirects=False)
        if r["status"] in (200, 204):
            ctx.endpoints.append(url)
            # Check for particularly sensitive content
            if any(x in path for x in [".env", ".git", "phpinfo",
                                         "actuator", "config", "server-status"]):
                sensitive_found.append((path, r["status"], r["body_length"]))
                ctx.add_finding(Finding(
                    module   = MODULE_NAME,
                    title    = f"Sensitive File Exposed: {path}",
                    severity = "High" if any(x in path for x in
                                              [".env", ".git", "phpinfo", "actuator/env"]) else "Medium",
                    url      = url,
                    detail   = f"Sensitive resource accessible: {path} (HTTP {r['status']}, {r['body_length']} bytes)",
                    evidence = r["body"][:200],
                    remediation = f"Restrict access to {path} via server config or remove the file",
                    cvss     = 7.5,
                ))

    if ctx.verbose:
        print(f"  {G}[+]{RST} Discovered {len(ctx.endpoints)} endpoints, "
              f"{len(ctx.js_files)} JS files, {len(ctx.forms)} forms")
        if sensitive_found:
            for path, status, length in sensitive_found:
                print(f"  {R}[!] SENSITIVE: {path} ({status}, {length}b){RST}")

    # Store raw results
    ctx.module_results["recon"] = {
        "tech_stack":    ctx.tech_stack,
        "endpoints":     ctx.endpoints[:50],
        "js_files":      ctx.js_files[:20],
        "forms":         ctx.forms[:20],
        "missing_headers": missing_headers,
        "server":        server,
    }

    # Chain hints
    if ctx.forms:
        ctx.add_chain_hint("recon", "xss",  "Forms found — test for XSS",   {"forms": ctx.forms})
        ctx.add_chain_hint("recon", "csrf", "Forms found — test for CSRF",  {"forms": ctx.forms})
        ctx.add_chain_hint("recon", "sqli", "Forms found — test for SQLi",  {"forms": ctx.forms})
    if ctx.endpoints:
        ctx.add_chain_hint("recon", "idor", "Endpoints found — test for IDOR", {"endpoints": ctx.endpoints})
    if "WordPress" in ctx.tech_stack:
        ctx.add_chain_hint("recon", "cms_scan", "WordPress detected — scan for WP vulns", {})

    return ctx


def _analyze_cookies(ctx: ScanContext, set_cookie: str, resp: dict):
    """Check cookies for security issues."""
    issues = []

    if "httponly" not in set_cookie.lower():
        issues.append("Missing HttpOnly flag — JS can read this cookie")
    if "secure" not in set_cookie.lower():
        issues.append("Missing Secure flag — sent over HTTP")
    if "samesite" not in set_cookie.lower():
        issues.append("Missing SameSite flag — CSRF risk")

    # Extract token values
    for m in re.finditer(r'([a-zA-Z_][a-zA-Z0-9_]*)=([^;,\s]{8,})', set_cookie):
        name, value = m.group(1), m.group(2)
        if any(t in name.lower() for t in ["session", "token", "auth", "jwt", "sess"]):
            ctx.tokens[name] = value

    if issues:
        ctx.add_finding(Finding(
            module   = "recon",
            title    = "Insecure Cookie Configuration",
            severity = "Medium",
            url      = resp["url"],
            detail   = " | ".join(issues),
            evidence = f"Set-Cookie: {set_cookie[:100]}",
            remediation = "Set HttpOnly; Secure; SameSite=Strict on all session cookies",
            cvss     = 5.3,
        ))


def _extract_endpoints(body: str, base_url: str, page_url: str) -> list:
    """Extract all links from HTML."""
    endpoints = []
    for m in re.finditer(r'(?:href|action|src|data-url)=["\']([^"\']+)["\']', body, re.I):
        url = _absolutize(m.group(1), base_url, page_url)
        if url and base_url in url:
            endpoints.append(url)
    # Also grab from JS fetch/axios calls
    for m in re.finditer(r'(?:fetch|axios\.(?:get|post)|\.ajax)\s*\(\s*["\']([^"\']+)["\']', body):
        url = _absolutize(m.group(1), base_url, page_url)
        if url:
            endpoints.append(url)
    return list(set(endpoints))


def _extract_forms(body: str, base_url: str, page_url: str) -> list:
    """Extract forms with their inputs."""
    forms = []
    for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.I | re.S):
        attrs   = fm.group(1)
        content = fm.group(2)

        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)

        action = _absolutize(action_m.group(1) if action_m else "", base_url, page_url) or page_url
        method = method_m.group(1).upper() if method_m else "GET"

        inputs = []
        for inp in re.finditer(r'<input([^>]*)>', content, re.I):
            ia    = inp.group(1)
            name  = re.search(r'name=["\']([^"\']+)["\']', ia, re.I)
            itype = re.search(r'type=["\']([^"\']+)["\']', ia, re.I)
            val   = re.search(r'value=["\']([^"\']*)["\']', ia, re.I)
            if name:
                inputs.append({
                    "name":  name.group(1),
                    "type":  itype.group(1) if itype else "text",
                    "value": val.group(1) if val else "",
                })

        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _absolutize(url: str, base_url: str, page_url: str) -> Optional[str]:
    """Make a URL absolute."""
    if not url or url.startswith(("javascript:", "mailto:", "#", "data:")):
        return None
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        return base_url + url
    if url.startswith("http"):
        return url
    # Relative URL
    return urllib.parse.urljoin(page_url, url)


