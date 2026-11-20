"""All audit checks.

Every check is a pure function of the fetched :class:`~headerhawk.models.Response`
and returns a :class:`~headerhawk.models.Check`. No network access happens here
except in :func:`exposure_checks`, which is opt-in.
"""

from __future__ import annotations

import re

from .fetch import probe_path
from .models import Check, Response

# --- response headers that are worth their own check -------------------------

REFERRER_OK = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "same-origin",
}

# Paths probed for accidental exposure. Ordered by how often they leak in the
# wild: leaked VCS metadata first, then env/config, then server internals.
EXPOSURE_PATHS = [
    ("/.git/HEAD", "git_repo"),
    ("/.env", "dotenv"),
    ("/.svn/entries", "svn_repo"),
    ("/.DS_Store", "ds_store"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "apache_status"),
    ("/actuator/env", "spring_actuator"),
    ("/wp-config.php.bak", "wp_config_backup"),
]

# Signatures used to decide whether a 200 response is a real leak rather than a
# soft-404 page that returns 200 with a marketing template.
EXPOSURE_SIGNATURES = {
    "git_repo": lambda body, ctype: body.lstrip().startswith("ref:") or re.match(r"^[0-9a-f]{40}", body.strip()) is not None,
    "dotenv": lambda body, ctype: "=" in body and "<html" not in body.lower() and "APP_" in body.upper() or "DB_" in body.upper(),
    "svn_repo": lambda body, ctype: "dir" in body and "svn" in body.lower(),
    "ds_store": lambda body, ctype: body.startswith("\x00\x00\x00\x01Bud1"),
    "phpinfo": lambda body, ctype: "PHP Version" in body or "phpinfo()" in body,
    "apache_status": lambda body, ctype: "Apache Server Status" in body or "Server Status" in body,
    "spring_actuator": lambda body, ctype: "propertySources" in body or "activeProfiles" in body,
    "wp_config_backup": lambda body, ctype: "DB_PASSWORD" in body or "DB_NAME" in body,
}


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _https(response: Response) -> bool:
    return response.final_url.startswith("https://")


# --- 1. transport security headers -------------------------------------------


def header_checks(response: Response) -> list[Check]:
    checks: list[Check] = []
    https = _https(response)

    # HSTS -------------------------------------------------------------------
    check = Check(
        "HDR-01",
        "HTTP Strict Transport Security",
        "headers",
        "high",
        12,
        remediation=(
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
            "on every HTTPS response."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
    )
    hsts = response.header("strict-transport-security")
    if not https:
        check.status = "skip"
        check.evidence = "Target is not served over HTTPS"
    elif not hsts:
        check.status = "fail"
        check.evidence = "Header absent"
    else:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        max_age = int(match.group(1)) if match else 0
        flags = [f for f in ("includeSubDomains", "preload") if f.lower() in hsts.lower()]
        suffix = f"; {', '.join(flags)}" if flags else ""
        if max_age < 15_552_000:
            check.status = "warn"
            check.evidence = f"max-age={max_age}s is below the 180-day minimum{suffix}"
        else:
            check.status = "pass"
            check.evidence = f"max-age={max_age}s{suffix}"
    checks.append(check)

    # CSP --------------------------------------------------------------------
    csp = response.header("content-security-policy")
    check = Check(
        "HDR-02",
        "Content Security Policy",
        "headers",
        "high",
        12,
        remediation=(
            "Add a restrictive CSP, e.g. `default-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'`."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
    )
    if not csp:
        check.status = "fail"
        check.evidence = "Header absent"
    else:
        directives = _csp_directives(csp)
        weak: list[str] = []
        if "'unsafe-inline'" in csp.lower():
            weak.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp.lower():
            weak.append("'unsafe-eval'")
        if "*" in directives.get("default-src", []) or "*" in directives.get("script-src", []):
            weak.append("wildcard source")
        if "default-src" not in directives and "script-src" not in directives:
            weak.append("no default-src/script-src")
        if weak:
            check.status = "warn"
            check.evidence = f"Present but weakened by {', '.join(weak)}"
        else:
            check.status = "pass"
            check.evidence = f"{len(directives)} directives, no unsafe sources detected"
    checks.append(check)

    # Clickjacking -----------------------------------------------------------
    xfo = response.header("x-frame-options").strip().upper()
    frame_ancestors = _csp_directives(csp).get("frame-ancestors") if csp else None
    check = Check(
        "HDR-03",
        "Clickjacking protection",
        "headers",
        "medium",
        8,
        remediation=(
            "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`), or the modern equivalent "
            "`Content-Security-Policy: frame-ancestors 'none'`."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
    )
    if xfo in ("DENY", "SAMEORIGIN"):
        check.status = "pass"
        check.evidence = f"X-Frame-Options: {xfo}"
    elif frame_ancestors is not None:
        check.status = "pass"
        check.evidence = f"CSP frame-ancestors {' '.join(frame_ancestors)}"
    elif xfo:
        check.status = "warn"
        check.evidence = f"X-Frame-Options has an unexpected value: {xfo}"
    else:
        check.status = "fail"
        check.evidence = "Neither X-Frame-Options nor CSP frame-ancestors present"
    checks.append(check)

    # MIME sniffing ----------------------------------------------------------
    check = Check(
        "HDR-04",
        "MIME type sniffing protection",
        "headers",
        "low",
        8,
        remediation="Send `X-Content-Type-Options: nosniff`.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    )
    nosniff = response.header("x-content-type-options").strip().lower()
    if nosniff == "nosniff":
        check.status = "pass"
        check.evidence = "X-Content-Type-Options: nosniff"
    elif nosniff:
        check.status = "warn"
        check.evidence = f"Unexpected value: {nosniff}"
    else:
        check.status = "fail"
        check.evidence = "Header absent"
    checks.append(check)

    # Referrer policy --------------------------------------------------------
    check = Check(
        "HDR-05",
        "Referrer policy",
        "headers",
        "low",
        6,
        remediation="Send `Referrer-Policy: strict-origin-when-cross-origin`.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    )
    referrer = response.header("referrer-policy").strip().lower()
    tokens = [t.strip() for t in referrer.split(",") if t.strip()]
    if not referrer:
        check.status = "fail"
        check.evidence = "Header absent (browser default leaks full URLs cross-origin)"
    elif "unsafe-url" in tokens:
        check.status = "fail"
        check.evidence = "unsafe-url leaks full URLs to every origin"
    elif any(t in REFERRER_OK for t in tokens):
        check.status = "pass"
        check.evidence = f"Referrer-Policy: {referrer}"
    else:
        check.status = "warn"
        check.evidence = f"Uncommon value: {referrer}"
    checks.append(check)

    # Permissions policy -----------------------------------------------------
    check = Check(
        "HDR-06",
        "Permissions policy",
        "headers",
        "low",
        4,
        remediation=(
            "Send `Permissions-Policy: geolocation=(), microphone=(), camera=()` "
            "to disable powerful browser features you do not use."
        ),
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    )
    if response.header("permissions-policy"):
        check.status = "pass"
        check.evidence = response.header("permissions-policy")[:160]
    else:
        check.status = "fail"
        check.evidence = "Header absent"
    checks.append(check)

    # Cross-origin isolation -------------------------------------------------
    coop = response.header("cross-origin-opener-policy")
    corp = response.header("cross-origin-resource-policy")
    coep = response.header("cross-origin-embedder-policy")
    check = Check(
        "HDR-07",
        "Cross-origin isolation",
        "headers",
        "low",
        5,
        remediation=(
            "Send `Cross-Origin-Opener-Policy: same-origin` and "
            "`Cross-Origin-Resource-Policy: same-origin`."
        ),
        references=["https://web.dev/articles/coop-coep"],
    )
    present = [name for name, value in (("COOP", coop), ("CORP", corp), ("COEP", coep)) if value]
    if present:
        check.status = "pass"
        check.evidence = f"Present: {', '.join(present)}"
    else:
        check.status = "fail"
        check.evidence = "No COOP/CORP/COEP headers"
    checks.append(check)

    # Banner disclosure ------------------------------------------------------
    leaking = {
        name: response.header(name)
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache")
        if response.header(name)
    }
    check = Check(
        "HDR-08",
        "Version disclosure",
        "headers",
        "low",
        5,
        remediation=(
            "Remove or strip down `Server` and `X-Powered-By` headers; stack versions "
            "help attackers pick exploits."
        ),
        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
    )
    if leaking:
        check.status = "warn"
        check.evidence = "; ".join(f"{k}: {v}" for k, v in leaking.items())
    else:
        check.status = "pass"
        check.evidence = "No Server/X-Powered-By style headers"
    checks.append(check)

    return checks


# --- 2. cookies --------------------------------------------------------------


def cookie_checks(response: Response) -> list[Check]:
    cookies = response.header_all("set-cookie")
    https = _https(response)
    check = Check(
        "CK-01",
        "Cookie security attributes",
        "cookies",
        "medium",
        12,
        remediation=(
            "Every session cookie needs `Secure; HttpOnly; SameSite=Lax` "
            "(or `SameSite=Strict`)."
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    )

    if not cookies:
        check.status = "skip"
        check.evidence = "No Set-Cookie header on the audited response"
        return [check]

    issues: list[str] = []
    names: list[str] = []
    for raw in cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() or "(unnamed)"
        names.append(name)
        attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "") for p in parts[1:]}
        if https and "secure" not in attrs:
            issues.append(f"{name}: missing Secure")
        if "httponly" not in attrs:
            issues.append(f"{name}: missing HttpOnly")
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            issues.append(f"{name}: missing SameSite")
        elif samesite == "none" and "secure" not in attrs:
            issues.append(f"{name}: SameSite=None without Secure")

    if not issues:
        check.status = "pass"
        check.evidence = f"{len(cookies)} cookie(s) fully flagged: {', '.join(names)}"
    else:
        critical = any("SameSite=None without Secure" in i for i in issues)
        check.status = "fail" if critical or any("missing Secure" in i for i in issues) else "warn"
        check.evidence = "; ".join(issues[:6]) + (" …" if len(issues) > 6 else "")
    return [check]


# --- 3. TLS ------------------------------------------------------------------


def tls_checks(response: Response) -> list[Check]:
    tls = response.tls or {}
    https = _https(response)

    version = Check(
        "TLS-01",
        "TLS protocol version",
        "tls",
        "high",
        8,
        remediation="Allow only TLS 1.2 and TLS 1.3; disable TLS 1.0/1.1 and SSLv3.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
    )
    if not https:
        version.status = "skip"
        version.evidence = "No TLS in use"
    else:
        negotiated = str(tls.get("version", "unknown"))
        if negotiated in ("TLSv1.2", "TLSv1.3"):
            version.status = "pass"
            version.evidence = f"Negotiated {negotiated}"
        elif negotiated in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            version.status = "fail"
            version.evidence = f"Negotiated legacy {negotiated}"
        else:
            version.status = "warn"
            version.evidence = f"Unrecognised protocol string: {negotiated}"

    cipher = Check(
        "TLS-02",
        "Cipher suite strength",
        "tls",
        "medium",
        4,
        remediation="Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305); disable RC4, 3DES and NULL.",
        references=["https://ssl-config.mozilla.org/"],
    )
    if not https:
        cipher.status = "skip"
        cipher.evidence = "No TLS in use"
    elif tls.get("weak_cipher"):
        cipher.status = "fail"
        cipher.evidence = f"Weak suite negotiated: {tls.get('cipher')}"
    elif not tls.get("cipher"):
        cipher.status = "warn"
        cipher.evidence = "Cipher suite could not be read from the connection"
    else:
        cipher.status = "pass"
        cipher.evidence = f"{tls.get('cipher')} ({tls.get('cipher_bits')} bit)"

    expiry = Check(
        "TLS-03",
        "Certificate validity",
        "tls",
        "high",
        3,
        remediation="Renew before expiry and automate renewal (ACME).",
        references=["https://letsencrypt.org/docs/"],
    )
    days = tls.get("days_until_expiry")
    if not https:
        expiry.status = "skip"
        expiry.evidence = "No TLS in use"
    elif days is None:
        expiry.status = "warn"
        expiry.evidence = "Certificate expiry could not be read"
    elif days < 0:
        expiry.status = "fail"
        expiry.evidence = f"Certificate expired {abs(days)} day(s) ago"
    elif days < 15:
        expiry.status = "warn"
        expiry.evidence = f"Expires in {days} day(s)"
    else:
        issuer = str(tls.get("issuer", ""))
        match = re.search(r"commonName=([^,]+)", issuer)
        issuer_short = match.group(1) if match else (issuer[:60] or "unknown")
        expiry.status = "pass"
        expiry.evidence = f"{days} day(s) remaining, issued by {issuer_short}"

    return [version, cipher, expiry]


# --- 4. exposure probes (opt-in) --------------------------------------------


def exposure_checks(
    response: Response,
    timeout: float = 8.0,
    user_agent: str = "",
    verify_tls: bool = True,
    cafile: str | None = None,
) -> tuple[list[Check], list[dict]]:
    """Probe a fixed list of paths for accidentally published files."""

    check = Check(
        "EXP-01",
        "Sensitive path exposure",
        "exposure",
        "critical",
        13,
        remediation=(
            "Remove the file from the web root, block the path at the reverse proxy, "
            "and rotate any credential it contained."
        ),
        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
    )
    found: list[str] = []
    probed: list[dict] = []

    for path, kind in EXPOSURE_PATHS:
        result = probe_path(
            response.final_url,
            path,
            timeout=timeout,
            user_agent=user_agent,
            verify_tls=verify_tls,
            cafile=cafile,
        )
        result["kind"] = kind
        signature = EXPOSURE_SIGNATURES.get(kind)
        confirmed = (
            result["status"] == 200
            and not result["error"]
            and signature is not None
            and signature(result["snippet"], result["content_type"])
        )
        result["confirmed"] = bool(confirmed)
        if confirmed:
            found.append(path)
        probed.append(result)

    if found:
        check.status = "fail"
        check.evidence = f"Reachable: {', '.join(found)}"
    else:
        check.status = "pass"
        check.evidence = f"{len(probed)} paths probed, none returned a real leak"
    return [check], probed
