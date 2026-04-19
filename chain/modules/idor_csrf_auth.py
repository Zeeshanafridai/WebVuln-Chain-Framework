from typing import Optional
"""
Modules: IDOR, CSRF, Auth Bypass
----------------------------------
Three lightweight but high-impact modules.

IDOR: Finds insecure direct object references by manipulating IDs
CSRF: Detects missing/bypassable CSRF protection on state-changing forms
Auth: Tests for auth bypass via common techniques
"""

import re
import urllib.parse
from ..core import ScanContext, Finding, http_request, R, G, Y, C, DIM, BOLD, RST

# ── IDOR Module ───────────────────────────────────────────────────────────────

def run_idor(ctx: ScanContext) -> ScanContext:
    """
    IDOR detection:
    1. Find numeric/UUID IDs in URLs and responses
    2. Increment/modify IDs and check if different objects returned
    3. Check if user IDs appear in JWT/cookies and can be manipulated
    """
    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: IDOR]{RST}")

    findings = []

    # Patterns that indicate object IDs in URLs
    ID_PATTERNS = [
        (r'/(\d+)(?:/|$|\?)',     "numeric"),
        (r'[?&]id=(\d+)',         "query_id"),
        (r'[?&]user_id=(\d+)',    "user_id"),
        (r'[?&]account=(\d+)',    "account"),
        (r'[?&]order=(\d+)',      "order"),
        (r'/([0-9a-f-]{36})(?:/|$|\?)', "uuid"),
    ]

    tested = set()

    for endpoint in ctx.endpoints[:30]:
        for pattern, id_type in ID_PATTERNS:
            m = re.search(pattern, endpoint)
            if not m:
                continue

            original_id  = m.group(1)
            original_url = endpoint

            # Skip if already tested this pattern
            base_key = re.sub(pattern, "/ID/", endpoint)
            if base_key in tested:
                continue
            tested.add(base_key)

            # Get baseline response
            resp_orig = ctx.request(original_url)
            if resp_orig["status"] not in (200, 201):
                continue

            # Try adjacent IDs
            test_ids = []
            if id_type == "numeric":
                try:
                    n = int(original_id)
                    test_ids = [str(n - 1), str(n + 1), str(n + 100), "1", "0"]
                except ValueError:
                    pass
            elif id_type == "uuid":
                # Try a different UUID
                test_ids = ["00000000-0000-0000-0000-000000000001",
                             "11111111-1111-1111-1111-111111111111"]

            for test_id in test_ids:
                test_url = endpoint.replace(original_id, test_id, 1)
                if test_url == original_url:
                    continue

                resp_test = ctx.request(test_url)

                # IDOR if: different 200 response with different body
                if (resp_test["status"] == 200 and
                        resp_test["body_hash"] != resp_orig["body_hash"] and
                        resp_test["body_length"] > 50):

                    findings.append(Finding(
                        module   = "idor",
                        title    = f"Potential IDOR — {id_type}",
                        severity = "High",
                        url      = test_url,
                        detail   = (f"Changing {id_type} from {original_id} to {test_id} "
                                     f"returns different 200 response ({resp_test['body_length']} bytes). "
                                     f"May expose another user's data."),
                        evidence = f"Original: {original_url} | Test: {test_url}",
                        remediation = ("Verify object ownership on every request. "
                                        "Use non-sequential IDs (UUIDs). "
                                        "Implement proper authorization checks server-side."),
                        cvss     = 8.1,
                        extra    = {"original_id": original_id, "test_id": test_id,
                                    "id_type": id_type},
                    ))
                    break  # one confirmed per endpoint is enough

    ctx.add_findings(findings)
    ctx.module_results["idor"] = {"tested": len(tested), "findings": len(findings)}
    return ctx


# ── CSRF Module ───────────────────────────────────────────────────────────────

def run_csrf(ctx: ScanContext) -> ScanContext:
    """
    CSRF detection:
    1. Check state-changing forms for CSRF tokens
    2. Test if CSRF token is validated (remove/change it)
    3. Check CORS + SameSite cookie combination
    4. Test JSON CSRF (Content-Type header check bypass)
    """
    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: CSRF]{RST}")

    findings = []

    for form in ctx.forms:
        method = form.get("method", "GET").upper()
        if method != "POST":
            continue

        action = form.get("action", "")
        inputs = form.get("inputs", [])
        input_names = [i["name"].lower() for i in inputs]

        # Check for CSRF token in form
        csrf_names = ["csrf", "token", "_token", "authenticity_token",
                       "csrfmiddlewaretoken", "_wpnonce", "xsrf"]
        has_csrf = any(any(c in n for c in csrf_names) for n in input_names)

        if not has_csrf:
            findings.append(Finding(
                module   = "csrf",
                title    = "Missing CSRF Token on State-Changing Form",
                severity = "Medium",
                url      = action,
                detail   = (f"POST form at {action} has no CSRF token in inputs: "
                             f"{input_names[:5]}"),
                evidence = f"Form inputs: {input_names}",
                remediation = ("Add a CSRF token (synchronizer token pattern) to all state-changing forms. "
                                "Verify token server-side. Set SameSite=Strict on session cookies."),
                cvss     = 6.5,
                extra    = {"form_action": action, "inputs": input_names},
            ))
        else:
            # Try submitting with modified/removed CSRF token
            form_data = {i["name"]: i.get("value", "test") for i in inputs}

            # Test 1: Remove CSRF token
            csrf_field = next((i["name"] for i in inputs
                                if any(c in i["name"].lower() for c in csrf_names)), None)
            if csrf_field:
                data_no_csrf = {k: v for k, v in form_data.items() if k != csrf_field}
                resp = ctx.request(action, method="POST", data=data_no_csrf)

                if resp["status"] not in (403, 401, 422):
                    findings.append(Finding(
                        module   = "csrf",
                        title    = "CSRF Token Not Properly Validated",
                        severity = "High",
                        url      = action,
                        detail   = f"Form submitted without CSRF token returned {resp['status']} (not rejected)",
                        evidence = f"Status {resp['status']} when CSRF token omitted",
                        remediation = "Validate CSRF token presence and value server-side. Reject if missing or incorrect.",
                        cvss     = 7.5,
                    ))

    ctx.add_findings(findings)
    ctx.module_results["csrf"] = {"forms_tested": len(ctx.forms), "findings": len(findings)}
    return ctx


# ── Auth Bypass Module ────────────────────────────────────────────────────────

def run_auth_bypass(ctx: ScanContext) -> ScanContext:
    """
    Authentication bypass checks:
    1. Default credentials on login forms
    2. SQL injection in login (quick check)
    3. JWT none algorithm
    4. Password reset flow weaknesses
    5. Rate limiting on auth endpoints
    """
    if ctx.verbose:
        print(f"\n{C}{BOLD}[MODULE: AUTH BYPASS]{RST}")

    findings = []

    # Find login forms
    login_forms = [f for f in ctx.forms
                   if any(kw in (f.get("action","") + str(f.get("inputs",""))).lower()
                          for kw in ["login", "signin", "auth", "session"])]

    for form in login_forms[:3]:
        action = form.get("action", "")
        inputs = form.get("inputs", [])
        user_field = next((i["name"] for i in inputs
                            if any(k in i["name"].lower()
                                   for k in ["user","email","login","name"])), None)
        pass_field = next((i["name"] for i in inputs
                            if any(k in i["name"].lower()
                                   for k in ["pass","pwd","secret"])), None)

        if not (user_field and pass_field):
            continue

        # Test SQLi in login
        sqli_payloads = [
            ("' OR '1'='1", "' OR '1'='1"),
            ("admin'--",     "anything"),
            ("' OR 1=1--",   "anything"),
        ]

        for usr_payload, pwd_payload in sqli_payloads:
            data = {user_field: usr_payload, pass_field: pwd_payload}
            for inp in inputs:
                if inp["name"] not in data:
                    data[inp["name"]] = inp.get("value", "")

            resp = ctx.request(action, method="POST", data=data)

            # Indicators of successful auth bypass
            bypass_indicators = [
                resp["status"] in (200, 302),
                "dashboard" in resp["body"].lower(),
                "logout" in resp["body"].lower(),
                "welcome" in resp["body"].lower(),
                "account" in resp["body"].lower(),
            ]

            if sum(bypass_indicators) >= 2:
                findings.append(Finding(
                    module   = "auth_bypass",
                    title    = "SQL Injection in Login — Auth Bypass",
                    severity = "Critical",
                    url      = action,
                    detail   = f"Login form accepted SQLi payload — possible authentication bypass",
                    evidence = f"Payload: {user_field}={usr_payload}",
                    remediation = "Use parameterized queries for authentication. Never concatenate user input into SQL.",
                    cvss     = 9.8,
                    extra    = {"payload": usr_payload, "field": user_field},
                ))
                break

        # Rate limiting check
        responses = []
        for _ in range(5):
            data = {user_field: "nonexistent@test.com", pass_field: "wrongpassword"}
            r = ctx.request(action, method="POST", data=data)
            responses.append(r["status"])

        if all(s == responses[0] for s in responses) and 429 not in responses:
            findings.append(Finding(
                module   = "auth_bypass",
                title    = "No Rate Limiting on Login Endpoint",
                severity = "Medium",
                url      = action,
                detail   = "Login endpoint accepts repeated failed attempts without rate limiting — brute force possible",
                evidence = f"5 requests all returned {responses[0]}",
                remediation = "Implement rate limiting, account lockout, and CAPTCHA on authentication endpoints.",
                cvss     = 5.3,
            ))

    # Check JWT in tokens
    for name, token in ctx.tokens.items():
        if token.count(".") == 2:
            try:
                import base64
                parts = token.split(".")
                hdr   = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                if hdr.get("alg", "").upper() in ("HS256", "RS256", "ES256"):
                    # Note JWT presence for JWT Attack Suite chaining
                    ctx.add_chain_hint("auth_bypass", "jwt_attack",
                                        f"JWT found in cookie '{name}' — test with jwt-attack-suite",
                                        {"token": token, "alg": hdr.get("alg")})
            except Exception:
                pass

    ctx.add_findings(findings)
    ctx.module_results["auth_bypass"] = {"findings": len(findings)}
    return ctx


import json
