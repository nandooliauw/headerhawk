"""HTTP fetching with TLS metadata capture.

Only the standard library is used: ``http.client`` + ``ssl`` give us the
negotiated protocol version, the chosen cipher and the peer certificate, none
of which ``urllib`` exposes. Redirects are followed manually so the full chain
can be reported.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from .models import Hop, Response

DEFAULT_USER_AGENT = (
    "headerhawk/1.0 (+https://github.com/; authorised security audit)"
)
MAX_REDIRECTS = 5
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "anon")


# Windows ships no OpenSSL trust store for CPython, so a fresh install fails
# every HTTPS request with "unable to get local issuer certificate". We look for
# a usable bundle in the places it commonly lives before giving up.
CA_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/usr/local/etc/openssl/cert.pem",
    r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    r"C:\Program Files\Common Files\SSL\cert.pem",
]


def find_ca_bundle() -> str:
    """Return a CA bundle path, or an empty string when the default context works."""

    for env in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        candidate = os.environ.get(env)
        if candidate and os.path.isfile(candidate):
            return candidate
    try:  # optional dependency, never required
        import certifi  # type: ignore

        return certifi.where()
    except Exception:
        pass
    for candidate in CA_BUNDLE_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return ""


def make_context(verify: bool = True, cafile: str | None = None) -> ssl.SSLContext:
    if not verify:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    # CPython on Windows often reports a partially populated default store, so a
    # non-zero cert count is not proof that verification will succeed. Prefer an
    # explicit bundle when one exists; only fall back to the platform default
    # when nothing else is available.
    bundle = find_ca_bundle()
    if bundle:
        try:
            return ssl.create_default_context(cafile=bundle)
        except (ssl.SSLError, OSError):
            pass
    return ssl.create_default_context()


def _split(url: str) -> tuple[str, str, int, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme in URL: {url}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return parsed.scheme, host, port, path


def _cert_info(sock: ssl.SSLSocket) -> dict[str, Any]:
    info: dict[str, Any] = {
        "version": sock.version() or "unknown",
        "cipher": "",
        "cipher_bits": 0,
        "subject": "",
        "issuer": "",
        "not_before": "",
        "not_after": "",
        "days_until_expiry": None,
        "expired": None,
        "weak_cipher": False,
        "sni": True,
    }
    cipher = sock.cipher()
    if cipher:
        name, _proto, bits = cipher[0], cipher[1], cipher[2]
        info["cipher"] = name
        info["cipher_bits"] = bits
        info["weak_cipher"] = any(marker.lower() in name.lower() for marker in WEAK_CIPHER_MARKERS)

    try:
        cert = sock.getpeercert()
    except ValueError:
        cert = {}
    if cert:
        info["subject"] = _flatten_name(cert.get("subject", ()))
        info["issuer"] = _flatten_name(cert.get("issuer", ()))
        info["not_before"] = cert.get("notBefore", "")
        info["not_after"] = cert.get("notAfter", "")
        info["sans"] = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"][:20]
        try:
            expiry = ssl.cert_time_to_seconds(info["not_after"])
            info["days_until_expiry"] = int((expiry - time.time()) // 86400)
            info["expired"] = info["days_until_expiry"] < 0
        except (ValueError, TypeError):
            pass
    return info


def _flatten_name(parts: Any) -> str:
    bits = []
    for rdn in parts or ():
        for key, value in rdn:
            bits.append(f"{key}={value}")
    return ", ".join(bits)


def fetch(
    url: str,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
    verify_tls: bool = True,
    max_body: int = 2048,
    cafile: str | None = None,
) -> Response:
    """Fetch ``url`` and return headers plus TLS metadata for the final hop."""

    response = Response(requested_url=url)
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        scheme, host, port, path = _split(current)
        hop = Hop(url=current)

        if scheme == "https":
            context = make_context(verify_tls, cafile)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        try:
            conn.request(
                "GET",
                path,
                headers={
                    "User-Agent": user_agent,
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            # The socket is still attached here; after the body is read,
            # http.client detaches it (we send Connection: close), so TLS
            # metadata must be captured before getresponse().
            socket_ref = conn.sock
            if scheme == "https" and socket_ref is not None:
                hop.tls = _cert_info(socket_ref)
            raw = conn.getresponse()
            body = raw.read(max_body)
        except ssl.SSLCertVerificationError as exc:
            response.error = f"TLS verification failed: {exc.verify_message or exc}"
            hop.status = 0
            response.hops.append(hop)
            response.final_url = current
            return response
        except (ssl.SSLError, socket.timeout, OSError, http.client.HTTPException) as exc:
            response.error = f"{type(exc).__name__}: {exc}"
            hop.status = 0
            response.hops.append(hop)
            response.final_url = current
            return response

        hop.status = raw.status
        response.headers = {}
        for name, value in raw.getheaders():
            response.headers.setdefault(name.lower(), []).append(value)
        response.raw_headers = list(raw.getheaders())
        response.status = raw.status
        response.body_snippet = body.decode("utf-8", "replace")
        response.final_url = current
        response.tls = hop.tls

        location = raw.getheader("Location") or ""
        hop.location = location
        response.hops.append(hop)
        conn.close()

        if raw.status in (301, 302, 303, 307, 308) and location:
            current = urllib.parse.urljoin(current, location)
            continue
        break

    return response


def probe_path(
    base_url: str,
    path: str,
    timeout: float = 8.0,
    user_agent: str = DEFAULT_USER_AGENT,
    verify_tls: bool = True,
    cafile: str | None = None,
) -> dict[str, Any]:
    """Request a single path on the target and return a small status record."""

    url = urllib.parse.urljoin(base_url, path)
    scheme, host, port, req_path = _split(url)
    result: dict[str, Any] = {
        "path": path,
        "url": url,
        "status": 0,
        "length": 0,
        "content_type": "",
        "snippet": "",
        "error": "",
    }
    if scheme == "https":
        context = make_context(verify_tls, cafile)
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.request("GET", req_path, headers={"User-Agent": user_agent, "Connection": "close"})
        raw = conn.getresponse()
        body = raw.read(1024)
        result["status"] = raw.status
        result["length"] = int(raw.getheader("Content-Length") or len(body))
        result["content_type"] = raw.getheader("Content-Type") or ""
        result["snippet"] = body.decode("utf-8", "replace")
    except (ssl.SSLError, socket.timeout, OSError, http.client.HTTPException) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
