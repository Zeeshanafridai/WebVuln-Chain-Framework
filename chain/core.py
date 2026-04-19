from typing import Optional
"""
Core HTTP engine + shared scan context for WebVuln Chain Framework.
The context object carries state between modules —
each module can read findings from previous modules and chain attacks.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import time
import json
import hashlib
import re
from typing import Optional, Any

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
C    = "\033[96m"
M    = "\033[95m"
DIM  = "\033[90m"
BOLD = "\033[1m"
RST  = "\033[0m"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)

SEVERITY_COLORS = {
    "Critical": R + BOLD,
    "High":     R,
    "Medium":   Y,
    "Low":      B,
    "Info":     DIM,
}


def http_request(url: str, method: str = "GET",
                  headers: dict = None, data: dict = None,
                  json_body: dict = None, raw_body: str = None,
                  cookies: str = None, timeout: int = 12,
                  follow_redirects: bool = True) -> dict:
    """Full HTTP request with rich metadata."""
    req_headers = {
        "User-Agent": DEFAULT_UA,
        "Accept":     "text/html,application/json,*/*",
    }
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    body_bytes = None
    if json_body is not None:
        body_bytes = json.dumps(json_body).encode()
        req_headers.setdefault("Content-Type", "application/json")
    elif data is not None:
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif raw_body:
        body_bytes = raw_body.encode() if isinstance(raw_body, str) else raw_body

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    start = time.perf_counter()
    try:
        req    = urllib.request.Request(url, data=body_bytes,
                                         headers=req_headers, method=method.upper())
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX),
            *([urllib.request.HTTPRedirectHandler()] if follow_redirects else [NoRedirect()])
        )
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            body    = resp.read(512 * 1024).decode("utf-8", errors="replace")
            rhdrs   = {k.lower(): v for k, v in dict(resp.headers).items()}
            return _build(resp.status, rhdrs, body, elapsed, url, method)
    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        rhdrs   = {k.lower(): v for k, v in dict(e.headers).items()} if e.headers else {}
        try:
            body = e.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return _build(e.code, rhdrs, body, elapsed, url, method)
    except Exception as e:
        elapsed = time.perf_counter() - start
        return _build(0, {}, "", elapsed, url, method, error=str(e))


def _build(status, headers, body, elapsed, url, method, error=None):
    return {
        "status":       status,
        "headers":      headers,
        "body":         body,
        "body_length":  len(body),
        "body_hash":    hashlib.md5(body.encode()).hexdigest(),
        "elapsed":      round(elapsed, 3),
        "url":          url,
        "method":       method,
        "content_type": headers.get("content-type", ""),
        "location":     headers.get("location", ""),
        "server":       headers.get("server", ""),
        "set_cookie":   headers.get("set-cookie", ""),
        "error":        error,
    }


# ── Scan Context ──────────────────────────────────────────────────────────────

class Finding:
    """A single vulnerability finding."""
    def __init__(self, module: str, title: str, severity: str,
                 url: str, detail: str, evidence: str = "",
                 remediation: str = "", cvss: float = 0.0,
                 extra: dict = None):
        self.module      = module
        self.title       = title
        self.severity    = severity
        self.url         = url
        self.detail      = detail
        self.evidence    = evidence
        self.remediation = remediation
        self.cvss        = cvss
        self.extra       = extra or {}
        self.timestamp   = time.time()

    def to_dict(self) -> dict:
        return {
            "module":      self.module,
            "title":       self.title,
            "severity":    self.severity,
            "url":         self.url,
            "detail":      self.detail,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "cvss":        self.cvss,
            "extra":       self.extra,
        }

    def print(self):
        col = SEVERITY_COLORS.get(self.severity, DIM)
        print(f"\n  {col}[{self.severity.upper()}]{RST} {self.title}")
        print(f"    Module    : {self.module}")
        print(f"    URL       : {self.url[:80]}")
        print(f"    Detail    : {self.detail[:120]}")
        if self.evidence:
            print(f"    Evidence  : {self.evidence[:100]}")
        print()


class ScanContext:
    """
    Shared state passed between all modules.
    Modules read previous findings and feed their own back in.
    Enables true vulnerability chaining.
    """

    def __init__(self, target: str, cookies: str = None,
                  headers: dict = None, verbose: bool = True):
        self.target   = target
        self.cookies  = cookies
        self.headers  = headers or {}
        self.verbose  = verbose

        # Discovered state
        self.findings: list[Finding]  = []
        self.endpoints: list[str]     = []
        self.params:    dict          = {}  # endpoint → [param_names]
        self.tokens:    dict          = {}  # type → value (jwt, csrf, session...)
        self.tech_stack: list[str]    = []
        self.js_files:   list[str]    = []
        self.forms:      list[dict]   = []

        # Per-module results (raw)
        self.module_results: dict     = {}

        # Chain opportunities — filled by modules to signal what to chain next
        self.chain_hints: list[dict]  = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        if self.verbose:
            finding.print()

    def add_findings(self, findings: list):
        for f in findings:
            self.add_finding(f)

    def get_findings_by_severity(self, severity: str) -> list:
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_module(self, module: str) -> list:
        return [f for f in self.findings if f.module == module]

    def add_chain_hint(self, source_module: str, target_module: str,
                        reason: str, data: dict = None):
        """Signal that source_module finding can be chained into target_module."""
        self.chain_hints.append({
            "from":   source_module,
            "to":     target_module,
            "reason": reason,
            "data":   data or {},
        })

    def summary(self) -> dict:
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "target":    self.target,
            "total":     len(self.findings),
            "by_severity": counts,
            "endpoints": len(self.endpoints),
            "chains":    len(self.chain_hints),
        }

    def request(self, url: str, **kwargs) -> dict:
        """Make a request using the context's cookies and headers."""
        kwargs.setdefault("cookies", self.cookies)
        merged_headers = {**self.headers, **kwargs.pop("headers", {})}
        if merged_headers:
            kwargs["headers"] = merged_headers
        return http_request(url, **kwargs)
