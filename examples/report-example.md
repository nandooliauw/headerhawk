# headerhawk report

- **Target:** `https://example.com/`
- **Final URL:** `https://example.com/`
- **Generated:** 2026-11-20 03:12:27 UTC
- **HTTP status:** 200
- **Redirects:** 0

## Score: 35/100 (grade F)

`4 pass` · `1 warn` · `7 fail` · `1 skip`

| Category | Score | Points |
| --- | --- | --- |
| exposure | 100 | 13/13 |
| headers | 4 | 2.5/60 |
| tls | 100 | 15/15 |

## Checks

| ID | Check | Category | Status | Evidence |
| --- | --- | --- | --- | --- |
| HDR-01 | HTTP Strict Transport Security | headers | **FAIL** | Header absent |
| HDR-02 | Content Security Policy | headers | **FAIL** | Header absent |
| HDR-03 | Clickjacking protection | headers | **FAIL** | Neither X-Frame-Options nor CSP frame-ancestors present |
| HDR-04 | MIME type sniffing protection | headers | **FAIL** | Header absent |
| HDR-05 | Referrer policy | headers | **FAIL** | Header absent (browser default leaks full URLs cross-origin) |
| HDR-06 | Permissions policy | headers | **FAIL** | Header absent |
| HDR-07 | Cross-origin isolation | headers | **FAIL** | No COOP/CORP/COEP headers |
| HDR-08 | Version disclosure | headers | **WARN** | server: cloudflare |
| CK-01 | Cookie security attributes | cookies | **SKIP** | No Set-Cookie header on the audited response |
| TLS-01 | TLS protocol version | tls | **PASS** | Negotiated TLSv1.3 |
| TLS-02 | Cipher suite strength | tls | **PASS** | TLS_AES_256_GCM_SHA384 (256 bit) |
| TLS-03 | Certificate validity | tls | **PASS** | 35 day(s) remaining, issued by Cloudflare TLS Issuing ECC CA 3 |
| EXP-01 | Sensitive path exposure | exposure | **PASS** | 8 paths probed, none returned a real leak |

## Findings

### 1. HDR-01 — HTTP Strict Transport Security

- **Severity:** HIGH
- **Status:** FAIL
- **Evidence:** Header absent
- **Remediation:** Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

### 2. HDR-02 — Content Security Policy

- **Severity:** HIGH
- **Status:** FAIL
- **Evidence:** Header absent
- **Remediation:** Add a restrictive CSP, e.g. `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html

### 3. HDR-03 — Clickjacking protection

- **Severity:** MEDIUM
- **Status:** FAIL
- **Evidence:** Neither X-Frame-Options nor CSP frame-ancestors present
- **Remediation:** Send `X-Frame-Options: DENY` (or `SAMEORIGIN`), or the modern equivalent `Content-Security-Policy: frame-ancestors 'none'`.
- **Reference:** https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html

### 4. HDR-04 — MIME type sniffing protection

- **Severity:** LOW
- **Status:** FAIL
- **Evidence:** Header absent
- **Remediation:** Send `X-Content-Type-Options: nosniff`.
- **Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options

### 5. HDR-05 — Referrer policy

- **Severity:** LOW
- **Status:** FAIL
- **Evidence:** Header absent (browser default leaks full URLs cross-origin)
- **Remediation:** Send `Referrer-Policy: strict-origin-when-cross-origin`.
- **Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy

### 6. HDR-06 — Permissions policy

- **Severity:** LOW
- **Status:** FAIL
- **Evidence:** Header absent
- **Remediation:** Send `Permissions-Policy: geolocation=(), microphone=(), camera=()` to disable powerful browser features you do not use.
- **Reference:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy

### 7. HDR-07 — Cross-origin isolation

- **Severity:** LOW
- **Status:** FAIL
- **Evidence:** No COOP/CORP/COEP headers
- **Remediation:** Send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin`.
- **Reference:** https://web.dev/articles/coop-coep

### 8. HDR-08 — Version disclosure

- **Severity:** LOW
- **Status:** WARN
- **Evidence:** server: cloudflare
- **Remediation:** Remove or strip down `Server` and `X-Powered-By` headers; stack versions help attackers pick exploits.
- **Reference:** https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration


## Exposure probes

| Path | Status | Confirmed |
| --- | --- | --- |
| `/.git/HEAD` | 404 | no |
| `/.env` | 404 | no |
| `/.svn/entries` | 404 | no |
| `/.DS_Store` | 404 | no |
| `/phpinfo.php` | 404 | no |
| `/server-status` | 404 | no |
| `/actuator/env` | 404 | no |
| `/wp-config.php.bak` | 404 | no |

## Raw response headers

```http
HTTP/1.1 200
Date: Fri, 20 Nov 2026 03:12:25 GMT
Content-Type: text/html; charset=utf-8
Transfer-Encoding: chunked
Connection: close
Server: cloudflare
last-modified: Thu, 19 Nov 2026 22:10:26 GMT
allow: GET, HEAD
Accept-Ranges: bytes
Age: 2
cf-cache-status: HIT
CF-RAY: a5d445de6d0da39b-SIN
alt-svc: h3=":443"; ma=86400
```

## TLS

- Protocol: `TLSv1.3`
- Cipher: `TLS_AES_256_GCM_SHA384` (256 bit)
- Subject: `commonName=example.com`
- Issuer: `countryName=US, organizationName=SSL Corporation, commonName=Cloudflare TLS Issuing ECC CA 3`
- Valid until: `Dec 25 22:56:35 2026 GMT` (35 days)
