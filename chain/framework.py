"""
WebVuln Chain Framework — Main Orchestrator
--------------------------------------------
Runs all modules in sequence. Each module:
  1. Reads the shared ScanContext
  2. Uses findings from previous modules
  3. Adds its own findings
  4. Leaves chain hints for downstream modules

The chain doesn't just run modules in isolation —
it actively uses earlier findings to improve later ones.
E.g. XSS module uses forms found by recon.
IDOR module uses endpoints found by recon.
Auth bypass chains into JWT attack hints.
"""

import json
import datetime
import time
from .core import ScanContext, Finding, R, G, Y, C, M, DIM, BOLD, RST, SEVERITY_COLORS
from .modules import recon, xss, idor_csrf_auth, misconfig

BANNER = f"""
{R}
  ██╗    ██╗███████╗██████╗ ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
  ██║    ██║██╔════╝██╔══██╗██║   ██║██║   ██║██║     ████╗  ██║
  ██║ █╗ ██║█████╗  ██████╔╝██║   ██║██║   ██║██║     ██╔██╗ ██║
  ██║███╗██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
  ╚███╔███╔╝███████╗██████╔╝ ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
   ╚══╝╚══╝ ╚══════╝╚═════╝   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
             {C}CHAIN FRAMEWORK{RST}{R}  — by Z33{RST}
{RST}{DIM}  Recon → XSS → IDOR → CSRF → Auth → Misconfig — Each Module Feeds the Next{RST}
"""

# Default pipeline — order matters
DEFAULT_PIPELINE = [
    ("recon",       recon.run,                "Fingerprint + endpoint/form discovery"),
    ("xss",         xss.run,                  "XSS detection (reflected, DOM, stored)"),
    ("idor",        idor_csrf_auth.run_idor,   "IDOR — object reference manipulation"),
    ("csrf",        idor_csrf_auth.run_csrf,   "CSRF — token presence + validation"),
    ("auth_bypass", idor_csrf_auth.run_auth_bypass, "Auth bypass + rate limiting"),
    ("misconfig",   misconfig.run,             "Misconfig + info disclosure + secrets"),
]


def run(target: str, cookies: str = None, headers: dict = None,
         modules: list = None, verbose: bool = True) -> ScanContext:
    """
    Run the full WebVuln Chain scan.

    Args:
        target:   Target URL
        cookies:  Session cookies
        headers:  Extra request headers
        modules:  List of module names to run (default: all)
        verbose:  Print progress

    Returns:
        Populated ScanContext with all findings
    """
    ctx = ScanContext(target, cookies=cookies, headers=headers, verbose=verbose)

    if verbose:
        print(BANNER)
        print(f"  {C}Target{RST}    : {target}")
        print(f"  {C}Cookies{RST}   : {'Yes' if cookies else 'No'}")
        print(f"  {C}Pipeline{RST}  : {len(DEFAULT_PIPELINE)} modules")
        print()

    # Select modules
    pipeline = DEFAULT_PIPELINE
    if modules:
        pipeline = [(name, fn, desc) for name, fn, desc in DEFAULT_PIPELINE
                    if name in modules]

    start_time = time.time()

    # Run each module
    for i, (name, fn, desc) in enumerate(pipeline, 1):
        if verbose:
            print(f"{DIM}{'─'*60}{RST}")
            print(f"{Y}[{i}/{len(pipeline)}]{RST} {name.upper()} — {desc}")

        try:
            ctx = fn(ctx)
        except Exception as e:
            if verbose:
                print(f"  {R}[!] Module {name} error: {e}{RST}")
            continue

        # Show chain hints triggered by this module
        new_hints = [h for h in ctx.chain_hints if h["from"] == name]
        if verbose and new_hints:
            for hint in new_hints:
                print(f"  {M}[CHAIN]{RST} {hint['from']} → {hint['to']}: {hint['reason']}")

    elapsed = round(time.time() - start_time, 1)

    if verbose:
        _print_final_summary(ctx, elapsed)

    return ctx


def _print_final_summary(ctx: ScanContext, elapsed: float):
    findings = ctx.findings
    summary  = ctx.summary()

    print(f"\n{R}{BOLD}{'═'*65}{RST}")
    print(f"{R}{BOLD}  WEBVULN CHAIN COMPLETE{RST}")
    print(f"{R}{BOLD}{'═'*65}{RST}\n")
    print(f"  Target     : {ctx.target}")
    print(f"  Duration   : {elapsed}s")
    print(f"  Endpoints  : {summary['endpoints']}")
    print(f"  Tech Stack : {', '.join(ctx.tech_stack) or 'Unknown'}")
    print(f"  Chains     : {summary['chains']} opportunities identified\n")

    if not findings:
        print(f"  {DIM}No vulnerabilities found.{RST}\n")
        return

    # Summary by severity
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    print(f"  {G}{BOLD}FINDINGS ({summary['total']} total){RST}\n")

    for sev in severity_order:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        col = SEVERITY_COLORS.get(sev, DIM)
        print(f"  {col}[{sev}]{RST} {len(sev_findings)} finding(s)")
        for f in sev_findings[:3]:  # show first 3 per severity
            print(f"    {G}→{RST} [{f.module}] {f.title}")
        if len(sev_findings) > 3:
            print(f"    {DIM}... +{len(sev_findings)-3} more{RST}")
        print()

    # Chain opportunities
    if ctx.chain_hints:
        print(f"  {M}{BOLD}CHAIN OPPORTUNITIES{RST}")
        for hint in ctx.chain_hints:
            print(f"    {M}→{RST} {hint['from']} → {hint['to']}: {hint['reason']}")
        print()

    # Tools to run next
    jwt_hints = [h for h in ctx.chain_hints if h["to"] == "jwt_attack"]
    sqli_hints = [h for h in ctx.chain_hints if h["to"] == "sqli"]
    if jwt_hints:
        print(f"  {Y}[NEXT]{RST} Run jwt-attack-suite against found JWT tokens")
    if sqli_hints:
        print(f"  {Y}[NEXT]{RST} Run sqli-fingerprinter against injectable forms")
    print()


def save_report(ctx: ScanContext, prefix: str = "webvuln_report") -> dict:
    """Save JSON + Markdown report."""
    import os

    now   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jpath = f"{prefix}_{now}.json"
    mpath = f"{prefix}_{now}.md"

    # JSON
    report_data = {
        "target":      ctx.target,
        "scan_date":   now,
        "tech_stack":  ctx.tech_stack,
        "summary":     ctx.summary(),
        "findings":    [f.to_dict() for f in ctx.findings],
        "chain_hints": ctx.chain_hints,
        "endpoints":   ctx.endpoints[:100],
    }
    with open(jpath, "w") as f:
        json.dump(report_data, f, indent=2, default=str)

    # Markdown
    lines = []
    lines.append("# WebVuln Chain Framework — Scan Report\n")
    lines.append(f"**Target:** `{ctx.target}`  ")
    lines.append(f"**Date:** {now}  ")
    lines.append(f"**Tech Stack:** {', '.join(ctx.tech_stack) or 'Unknown'}  ")
    lines.append(f"**Findings:** {len(ctx.findings)}  \n")
    lines.append("---\n")

    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    for sev in severity_order:
        sev_findings = [f for f in ctx.findings if f.severity == sev]
        if not sev_findings:
            continue
        lines.append(f"## {sev} Findings ({len(sev_findings)})\n")
        for f in sev_findings:
            lines.append(f"### [{f.module}] {f.title}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {f.severity} |")
            lines.append(f"| **URL** | `{f.url}` |")
            lines.append(f"| **CVSS** | {f.cvss} |")
            lines.append(f"| **Detail** | {f.detail} |")
            if f.evidence:
                lines.append(f"| **Evidence** | `{f.evidence[:100]}` |")
            if f.remediation:
                lines.append(f"\n**Remediation:** {f.remediation}\n")
            lines.append("---\n")

    if ctx.chain_hints:
        lines.append("## Chain Opportunities\n")
        for hint in ctx.chain_hints:
            lines.append(f"- **{hint['from']} → {hint['to']}**: {hint['reason']}")
        lines.append("")

    with open(mpath, "w") as f:
        f.write("\n".join(lines))

    return {"json": jpath, "markdown": mpath}
