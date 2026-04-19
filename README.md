# WebVuln Chain Framework

> Modular web vulnerability scanner where every module feeds into the next. Recon discovers endpoints → XSS tests them → IDOR manipulates IDs → CSRF checks forms → Auth tests login logic → Misconfig hunts secrets and exposed files. All in one run.

---

## What Makes This Different

Most scanners test in isolation. This framework **chains** findings:

```
Recon discovers /api/users?id=1
    ↓
IDOR increments: /api/users?id=2 → different user's data
    ↓
Auth module finds JWT in cookie
    ↓
Chain hint: "run jwt-attack-suite against this token"
```

```
Recon finds login form at /api/auth/login
    ↓
CSRF checks: no CSRF token present
    ↓
Auth module: tests SQLi in username field
    ↓
Auth module: no rate limiting on 5 failed attempts
```

---

## Module Pipeline

```
[1] RECON       → Tech fingerprint, endpoint discovery, form enumeration,
                  security headers, cookie analysis, sensitive file probing
                  
[2] XSS         → Reflected (HTML/attr/JS contexts), DOM XSS sink detection,
                  WAF bypass payloads, context-aware encoding
                  
[3] IDOR        → Numeric ID manipulation, UUID enumeration,
                  cross-user data access verification
                  
[4] CSRF        → Token presence, token validation bypass,
                  JSON CSRF, SameSite cookie check
                  
[5] AUTH BYPASS → Default creds, SQLi in login, rate limiting,
                  JWT detection → chain hint for jwt-attack-suite
                  
[6] MISCONFIG   → 30+ sensitive file paths, stack traces, secrets in JS,
                  CORS misconfiguration, error disclosure
```

---

## Installation

```bash
git clone https://github.com/yourhandle/webvuln-chain
cd webvuln-chain
python3 webvuln_chain.py --help
```

Zero dependencies. Pure Python 3.6+.

---

## Usage

### Full scan (all modules)
```bash
python3 webvuln_chain.py -u "https://target.com"
```

### Authenticated scan
```bash
python3 webvuln_chain.py -u "https://target.com" \
  -c "session=abc123; token=xyz"
```

### Specific modules only
```bash
# Just recon + misconfig (fast, low noise)
python3 webvuln_chain.py -u "https://target.com" \
  --modules recon misconfig

# Auth-focused
python3 webvuln_chain.py -u "https://target.com/login" \
  --modules recon csrf auth_bypass
```

### Full workflow with report
```bash
python3 webvuln_chain.py -u "https://target.com" \
  -c "session=TOKEN" \
  --report \
  -o findings.json
```

---

## Chain Logic

Each module signals opportunities to downstream modules via **chain hints**:

| Source Module | → Target | Trigger | Action |
|---------------|----------|---------|--------|
| recon | xss | Forms found | Test all form params for XSS |
| recon | idor | Endpoints with IDs | Enumerate object references |
| recon | csrf | POST forms found | Check CSRF token presence |
| recon | sqli | Forms found | Test with sqli-fingerprinter |
| xss | csp_bypass | XSS confirmed | Check if CSP blocks exploitation |
| auth_bypass | jwt_attack | JWT in cookie | Run jwt-attack-suite |

---

## Integration with Other Tools in This Portfolio

The framework outputs chain hints pointing to other tools:

```
[CHAIN] auth_bypass → jwt_attack: JWT found in cookie 'session' (alg: HS256)
→ Run: python3 jwt_attack.py bruteforce -t TOKEN -w rockyou.txt

[CHAIN] recon → sqli: POST forms found — test for SQL injection
→ Run: python3 sqli_scan.py -u TARGET -m POST -d "username=test"

[CHAIN] recon → cors: API endpoints found
→ Run: python3 cors_exploit.py -u TARGET/api/user --discover
```

---

## Output Example

```
[CRITICAL] Actuator /env Exposes Secrets
    Module    : misconfig
    URL       : https://target.com/actuator/env
    Detail    : Sensitive resource accessible (HTTP 200, 8432 bytes)

[HIGH] Reflected XSS — html context
    Module    : xss
    URL       : https://target.com/search?q=<z33xsscanary>
    Evidence  : <img src=x onerror=alert("z33xsscanary")>

[HIGH] Potential IDOR — query_id
    Module    : idor
    URL       : https://target.com/api/orders?id=1338
    Detail    : Changing id from 1337 to 1338 returns different user's order

[MEDIUM] Missing CSRF Token on POST Form
    Module    : csrf
    URL       : https://target.com/api/profile/update

CHAIN OPPORTUNITIES
→ auth_bypass → jwt_attack: JWT found — run jwt-attack-suite
→ recon → sqli: POST forms found — run sqli-fingerprinter
```

---

## GitHub Info

**Description:**
```
Modular web vuln scanner — recon→XSS→IDOR→CSRF→auth→misconfig chain, each module feeds the next
```

**Topics:**
```
web-security, vulnerability-scanner, xss, idor, csrf, ssrf,
bug-bounty, penetration-testing, python, appsec, chained-attacks
```

---

## License
MIT — For authorized testing only.
