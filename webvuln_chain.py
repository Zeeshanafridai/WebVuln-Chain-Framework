#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║        WEBVULN CHAIN FRAMEWORK  —  by 0xZ33                  ║
║      github.com/Zeeshanafridai/webvuln-chain-framework       ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from chain.framework import run, save_report, BANNER
from chain.core import R, G, Y, C, DIM, BOLD, RST


def main():
    parser = argparse.ArgumentParser(
        prog="webvuln-chain",
        description="WebVuln Chain Framework — Modular web vulnerability scanner"
    )

    parser.add_argument("-u", "--url",          required=True,
                        help="Target URL")
    parser.add_argument("-c", "--cookies",
                        help="Session cookies")
    parser.add_argument("-H", "--header",       action="append",
                        help="Extra header (Name: Value)")
    parser.add_argument("--modules",            nargs="+",
                        choices=["recon", "xss", "idor", "csrf",
                                  "auth_bypass", "misconfig"],
                        help="Modules to run (default: all)")
    parser.add_argument("--report",             action="store_true",
                        help="Generate Markdown + JSON report")
    parser.add_argument("--report-prefix",      default="webvuln_report")
    parser.add_argument("-o", "--output",
                        help="Save raw JSON findings")
    parser.add_argument("-q", "--quiet",        action="store_true")

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    ctx = run(
        target  = args.url,
        cookies = args.cookies,
        headers = headers or None,
        modules = args.modules,
        verbose = not args.quiet,
    )

    if args.report:
        paths = save_report(ctx, args.report_prefix)
        print(f"\n{C}[*] Reports:{RST}")
        print(f"    JSON     : {paths['json']}")
        print(f"    Markdown : {paths['markdown']}")

    if args.output:
        data = {
            "target":   ctx.target,
            "findings": [f.to_dict() for f in ctx.findings],
            "chains":   ctx.chain_hints,
            "summary":  ctx.summary(),
        }
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"\n{G}[+] Results: {args.output}{RST}")


if __name__ == "__main__":
    main()
