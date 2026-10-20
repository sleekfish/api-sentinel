"""
API Sentinel — security scanner (v2).

Design principles
-----------------
* Every finding is evidence-based: a finding is only emitted when the
  observed HTTP response conclusively supports it.  No findings are
  fabricated or assumed.
* Confidence is reported for each finding:
    high   — the condition is directly observable in the response.
    medium — the condition is inferred (e.g. absence of an optional header).
    low    — heuristic or partial signal only.
* Destructive tests (credential brute-force, payload injection, uncontrolled
  crawling) are NOT performed.
* Concurrency is bounded: at most MAX_WORKERS parallel probe requests.
* All outbound requests carry explicit timeouts (CONNECT_TIMEOUT, READ_TIMEOUT).
* Input validation lives in models.py (ScanRequest); the scanner trusts that
  the URL has already been validated before run_scan() is called.
"""
from __future__ import annotations

import re
import ssl
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Literal

import httpx

# ── Tunables ──────────────────────────────────────────────────────────────────

CONNECT_TIMEOUT = 8.0   # seconds
READ_TIMEOUT    = 12.0  # seconds
MAX_WORKERS     = 4     # max parallel probe threads

_TIMEOUT = httpx.Timeout(connect=CONNECT_TIMEOUT, read=READ_TIMEOUT,
                         write=5.0, pool=5.0)

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity:    Literal["critical", "high", "medium", "low", "info"]
    category:    str
    title:       str
    description: str
    remediation: str
    affected_url: str = ""
    evidence:    str = ""
    confidence:  Literal["high", "medium", "low"] = "high"

    def to_dict(self) -> dict:
        return asdict(self)


def _f(
    severity: str,
    category: str,
    title: str,
    description: str,
    remediation: str,
    affected_url: str = "",
    evidence: str = "",
    confidence: str = "high",
) -> Finding:
    return Finding(
        severity=severity,       # type: ignore[arg-type]
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        affected_url=affected_url,
        evidence=evidence,
        confidence=confidence,   # type: ignore[arg-type]
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm_headers(headers: httpx.Headers) -> dict[str, str]:
    """Return a lowercase-keyed copy of headers."""
    return {k.lower(): v for k, v in headers.items()}


def _safe_truncate(text: str, limit: int = 300) -> str:
    """Truncate long strings for evidence fields."""
    return text[:limit] + "…" if len(text) > limit else text


# ── Check: HTTPS ──────────────────────────────────────────────────────────────

def _check_https(url: str) -> list[Finding]:
    if url.startswith("http://"):
        return [_f(
            "critical", "Transport Security",
            "Endpoint does not use HTTPS",
            "The target URL uses plain HTTP. All traffic — including credentials and "
            "session tokens — is transmitted in cleartext and is trivially interceptable.",
            "Redirect all HTTP traffic to HTTPS. Obtain a valid TLS certificate from a "
            "trusted CA (e.g. Let's Encrypt).",
            affected_url=url,
            evidence=f"URL scheme is 'http': {url}",
            confidence="high",
        )]
    return []


# ── Check: TLS configuration (passive, connect only) ─────────────────────────

def _check_tls(url: str) -> list[Finding]:
    """
    Passively inspect TLS negotiation by opening a raw SSL socket.
    Only checks that the certificate is verifiable by the system trust store.
    Does NOT test cipher suites or perform active negotiation attacks.
    """
    findings: list[Finding] = []
    if not url.startswith("https://"):
        return findings

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                # Check for near-expiry (< 30 days) — observation only
                import datetime
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    remaining = not_after - datetime.datetime.now(datetime.timezone.utc)
                    if remaining.days < 0:
                        findings.append(_f(
                            "critical", "TLS",
                            "TLS certificate has expired",
                            f"The certificate for {host} expired on {not_after_str}. "
                            "Clients will see a hard browser error.",
                            "Renew the TLS certificate immediately.",
                            affected_url=url,
                            evidence=f"notAfter: {not_after_str}",
                            confidence="high",
                        ))
                    elif remaining.days < 30:
                        findings.append(_f(
                            "medium", "TLS",
                            f"TLS certificate expires in {remaining.days} day(s)",
                            f"The certificate for {host} expires on {not_after_str}. "
                            "Allow time for renewal before it causes outages.",
                            "Renew the TLS certificate before it expires.",
                            affected_url=url,
                            evidence=f"notAfter: {not_after_str}, days remaining: {remaining.days}",
                            confidence="high",
                        ))
    except ssl.SSLCertVerificationError as exc:
        findings.append(_f(
            "high", "TLS",
            "TLS certificate verification failed",
            "The server presented a TLS certificate that could not be verified against "
            "the system trust store. Clients may see certificate warnings.",
            "Use a certificate issued by a publicly trusted CA and ensure the full chain "
            "is served. Check for hostname mismatches or self-signed certs in production.",
            affected_url=url,
            evidence=_safe_truncate(str(exc)),
            confidence="high",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Network-level errors are reported by the HTTP connectivity check; skip here.
        pass
    except Exception:
        pass

    return findings


# ── Check: Security headers ───────────────────────────────────────────────────

# (severity, header_name, title, description, remediation)
_SECURITY_HEADER_CHECKS: list[tuple[str, str, str, str, str]] = [
    (
        "high",
        "strict-transport-security",
        "HSTS header missing",
        "Strict-Transport-Security (HSTS) is absent. Without it, browsers will not "
        "automatically upgrade future requests to HTTPS, leaving users vulnerable to "
        "SSL-stripping attacks on first visit.",
        "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    (
        "medium",
        "x-content-type-options",
        "X-Content-Type-Options header missing",
        "Without 'X-Content-Type-Options: nosniff', browsers may MIME-sniff response "
        "bodies, allowing content-type confusion attacks.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    (
        "medium",
        "x-frame-options",
        "X-Frame-Options header missing",
        "Without X-Frame-Options, the response can be embedded in an <iframe>, enabling "
        "clickjacking attacks.",
        "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing by the same origin is required)",
    ),
    (
        "medium",
        "content-security-policy",
        "Content-Security-Policy header missing",
        "Without a Content-Security-Policy, the application is more susceptible to "
        "cross-site scripting (XSS) and data-injection attacks.",
        "Define a strict Content-Security-Policy. Start with "
        "'default-src \\'self\\'' and expand as needed.",
    ),
    (
        "low",
        "referrer-policy",
        "Referrer-Policy header missing",
        "Without Referrer-Policy, the full URL (including query parameters) may be sent "
        "as the Referer header to third-party resources, potentially leaking sensitive data.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "low",
        "permissions-policy",
        "Permissions-Policy header missing",
        "Without Permissions-Policy, browser features (camera, microphone, geolocation) "
        "are not explicitly restricted, increasing the attack surface.",
        "Add a Permissions-Policy header that disables features not needed by the API.",
    ),
]


def _check_security_headers(headers: httpx.Headers, url: str) -> list[Finding]:
    findings: list[Finding] = []
    hdr = _norm_headers(headers)

    # HSTS is only relevant over HTTPS.
    relevant_checks = _SECURITY_HEADER_CHECKS
    if url.startswith("http://"):
        relevant_checks = [c for c in _SECURITY_HEADER_CHECKS
                           if c[1] != "strict-transport-security"]

    for severity, header_name, title, desc, rem in relevant_checks:
        if header_name not in hdr:
            findings.append(_f(
                severity, "Security Headers", title, desc, rem,
                affected_url=url,
                evidence=f"Header '{header_name}' absent from response",
                confidence="high",
            ))
        else:
            # Report weak/misconfigured values for HSTS specifically
            if header_name == "strict-transport-security":
                val = hdr[header_name].lower()
                match = re.search(r"max-age\s*=\s*(\d+)", val)
                if match and int(match.group(1)) < 2592000:  # < 30 days
                    findings.append(_f(
                        "medium", "Security Headers",
                        "HSTS max-age is too short",
                        "The Strict-Transport-Security max-age value is less than 30 days "
                        "(2592000 seconds), providing insufficient protection.",
                        "Set max-age to at least 63072000 (2 years).",
                        affected_url=url,
                        evidence=f"strict-transport-security: {hdr[header_name]}",
                        confidence="high",
                    ))
    return findings


# ── Check: Server / technology disclosure ────────────────────────────────────

_DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wp-total",
)


def _check_server_disclosure(headers: httpx.Headers, url: str) -> list[Finding]:
    findings: list[Finding] = []
    hdr = _norm_headers(headers)
    for h in _DISCLOSURE_HEADERS:
        if h in hdr:
            findings.append(_f(
                "low", "Information Disclosure",
                f"Response header '{h}' discloses technology details",
                f"The response includes the '{h}' header, revealing implementation "
                f"details that may assist an attacker in targeting known vulnerabilities.",
                f"Remove or neutralise the '{h}' response header in the server/framework "
                f"configuration.",
                affected_url=url,
                evidence=f"{h}: {_safe_truncate(hdr[h], 120)}",
                confidence="high",
            ))
    return findings


# ── Check: CORS ───────────────────────────────────────────────────────────────

def _check_cors_simple(headers: httpx.Headers, url: str) -> list[Finding]:
    """
    Inspect CORS headers on the baseline response.
    Only report wildcard ACAO or the dangerous wildcard+credentials combo.
    """
    findings: list[Finding] = []
    hdr = _norm_headers(headers)
    acao = hdr.get("access-control-allow-origin", "")
    acac = hdr.get("access-control-allow-credentials", "").lower()

    if acao == "*" and acac == "true":
        findings.append(_f(
            "critical", "CORS",
            "CORS wildcard origin combined with credentials=true",
            "The response sets Access-Control-Allow-Origin: * together with "
            "Access-Control-Allow-Credentials: true. Although browsers block this "
            "combination per the CORS spec, it signals a CORS misconfiguration and "
            "may be exploitable in non-browser clients or future browser versions.",
            "Never combine a wildcard ACAO with Allow-Credentials: true. "
            "Explicitly enumerate allowed origins.",
            affected_url=url,
            evidence=(
                f"access-control-allow-origin: {acao}  |  "
                f"access-control-allow-credentials: {acac}"
            ),
            confidence="high",
        ))
    elif acao == "*":
        findings.append(_f(
            "high", "CORS",
            "CORS policy allows all origins (wildcard)",
            "Access-Control-Allow-Origin: * permits any website to issue "
            "cross-origin requests to this API, potentially exposing data to "
            "malicious third-party pages.",
            "Restrict CORS to an explicit list of trusted origins.",
            affected_url=url,
            evidence=f"access-control-allow-origin: {acao}",
            confidence="high",
        ))
    return findings


def _check_cors_reflection(client: httpx.Client, url: str) -> list[Finding]:
    """
    Send an Origin header and check whether the server reflects it back
    unchanged — a common over-permissive CORS misconfiguration.
    """
    findings: list[Finding] = []
    probe_origin = "https://evil.sentinel-probe.invalid"
    try:
        resp = client.get(
            url, headers={"Origin": probe_origin}, timeout=_TIMEOUT
        )
        reflected = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        if reflected == probe_origin:
            sev = "critical" if acac == "true" else "high"
            creds_note = (
                " The server also sets Allow-Credentials: true, meaning cookies and "
                "auth headers are forwarded — this is directly exploitable."
                if acac == "true" else ""
            )
            findings.append(_f(
                sev, "CORS",
                "Server reflects arbitrary Origin header in ACAO",
                f"When sent Origin: {probe_origin}, the server responded with "
                f"Access-Control-Allow-Origin: {reflected}.{creds_note} "
                "This allows any website to make authenticated cross-origin requests.",
                "Maintain an explicit allowlist of trusted origins. Never reflect the "
                "incoming Origin header without validating it against the allowlist.",
                affected_url=url,
                evidence=(
                    f"Request Origin: {probe_origin}  →  "
                    f"ACAO: {reflected}  |  ACAC: {acac or 'absent'}"
                ),
                confidence="high",
            ))
    except Exception:
        pass
    return findings


# ── Check: HTTP methods ───────────────────────────────────────────────────────

_DANGEROUS_METHODS = ("TRACE", "TRACK")
_SENSITIVE_METHODS = ("DELETE", "PUT", "PATCH")


def _check_methods(client: httpx.Client, url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        resp = client.options(url, timeout=_TIMEOUT)
        allow_raw = resp.headers.get("allow", resp.headers.get("access-control-allow-methods", ""))
        if not allow_raw:
            return findings
        allow_upper = allow_raw.upper()

        dangerous = [m for m in _DANGEROUS_METHODS if m in allow_upper]
        if dangerous:
            findings.append(_f(
                "high", "HTTP Methods",
                f"Dangerous HTTP method(s) enabled: {', '.join(dangerous)}",
                f"The server advertises {', '.join(dangerous)} via the Allow header. "
                "TRACE/TRACK enable Cross-Site Tracing (XST) attacks that can bypass "
                "HttpOnly cookie protections.",
                "Disable TRACE and TRACK at the web-server level.",
                affected_url=url,
                evidence=f"Allow: {_safe_truncate(allow_raw, 200)}",
                confidence="high",
            ))

        sensitive = [m for m in _SENSITIVE_METHODS if m in allow_upper]
        if sensitive:
            findings.append(_f(
                "info", "HTTP Methods",
                f"Sensitive HTTP method(s) advertised: {', '.join(sensitive)}",
                f"The server advertises {', '.join(sensitive)} in the Allow header. "
                "These are expected for REST APIs but should be protected by "
                "authentication and authorisation controls.",
                "Ensure DELETE, PUT, and PATCH endpoints require authentication "
                "and are not accessible without appropriate authorisation.",
                affected_url=url,
                evidence=f"Allow: {_safe_truncate(allow_raw, 200)}",
                confidence="high",
            ))
    except Exception:
        pass
    return findings


# ── Check: Cookie flags ───────────────────────────────────────────────────────

def _check_cookies(response: httpx.Response, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in response.cookies.jar:
        name = cookie.name
        if not cookie.secure:
            findings.append(_f(
                "high", "Cookie Security",
                f"Cookie '{name}' is missing the Secure flag",
                f"The cookie '{name}' does not have the Secure attribute. It can be "
                "transmitted over plain HTTP connections, risking interception.",
                "Set the Secure flag on all cookies containing sensitive data or session IDs.",
                affected_url=url,
                evidence=f"Set-Cookie: {name}=… (Secure flag absent)",
                confidence="high",
            ))
        if not cookie.has_nonstandard_attr("HttpOnly"):
            findings.append(_f(
                "high", "Cookie Security",
                f"Cookie '{name}' is missing the HttpOnly flag",
                f"The cookie '{name}' is accessible via JavaScript. An XSS vulnerability "
                "in the application could be used to steal it.",
                "Set the HttpOnly flag on all session and authentication cookies.",
                affected_url=url,
                evidence=f"Set-Cookie: {name}=… (HttpOnly flag absent)",
                confidence="high",
            ))
        samesite = cookie.get_nonstandard_attr("SameSite") or ""
        if not samesite:
            findings.append(_f(
                "medium", "Cookie Security",
                f"Cookie '{name}' is missing the SameSite attribute",
                f"Without SameSite, the cookie '{name}' may be sent in cross-site "
                "requests, contributing to CSRF vulnerabilities.",
                "Set SameSite=Strict or SameSite=Lax on all cookies.",
                affected_url=url,
                evidence=f"Set-Cookie: {name}=… (SameSite attribute absent)",
                confidence="high",
            ))
    return findings


# ── Check: API versioning ─────────────────────────────────────────────────────

def _check_versioning(url: str) -> list[Finding]:
    if not re.search(r"/v\d+", url, re.IGNORECASE):
        return [_f(
            "info", "API Design",
            "No API version segment detected in URL path",
            "The URL does not contain a version segment (e.g. /v1/). Without versioning "
            "it is harder to evolve the API without breaking existing clients.",
            "Consider a URL-path version prefix such as /v1/.",
            affected_url=url,
            evidence=f"URL path: {urllib.parse.urlparse(url).path or '/'}",
            confidence="medium",
        )]
    return []


# ── Check: Rate-limit headers ─────────────────────────────────────────────────

_RATE_LIMIT_HEADER_PATTERNS = (
    "ratelimit", "rate-limit", "x-ratelimit", "x-rate-limit", "retry-after",
)


def _check_rate_limit_headers(headers: httpx.Headers, url: str) -> list[Finding]:
    hdr_names = " ".join(k.lower() for k in headers.keys())
    has = any(p in hdr_names for p in _RATE_LIMIT_HEADER_PATTERNS)
    if not has:
        return [_f(
            "medium", "Rate Limiting",
            "No rate-limit response headers detected",
            "The API does not return standard rate-limit headers "
            "(RateLimit-Limit, X-RateLimit-*, Retry-After). Without rate limiting, "
            "the API is more susceptible to brute-force and denial-of-service attacks.",
            "Implement rate limiting and expose RateLimit-Limit and RateLimit-Remaining "
            "headers so clients can self-throttle.",
            affected_url=url,
            evidence="None of: " + ", ".join(_RATE_LIMIT_HEADER_PATTERNS) + " found in response headers",
            confidence="medium",
        )]
    return []


# ── Check: Auth header exposure ───────────────────────────────────────────────

def _check_auth_exposure(headers: httpx.Headers, url: str) -> list[Finding]:
    findings: list[Finding] = []
    hdr = _norm_headers(headers)
    for h in ("www-authenticate", "proxy-authenticate"):
        val = hdr.get(h, "")
        if val and "basic" in val.lower():
            findings.append(_f(
                "high", "Authentication",
                f"HTTP Basic authentication advertised via '{h}' header",
                "HTTP Basic authentication encodes credentials in Base64 (not encryption). "
                "Over plain HTTP this is equivalent to cleartext transmission. "
                "Even over HTTPS, Basic auth is weaker than token-based schemes.",
                "Replace HTTP Basic auth with a modern token-based scheme "
                "(e.g. OAuth 2.0 Bearer tokens or API keys via request headers).",
                affected_url=url,
                evidence=f"{h}: {_safe_truncate(val, 120)}",
                confidence="high",
            ))
    return findings


# ── Check: Error-response leakage ────────────────────────────────────────────

_LEAKY_PATTERNS: list[tuple[str, str]] = [
    (r"traceback \(most recent call last\)", "Python traceback"),
    (r"stack trace:", "stack trace"),
    (r"at [a-zA-Z0-9_$.]+\([A-Za-z0-9_.]+\.java:\d+\)", "Java stack frame"),
    (r"sqlstate\[", "SQL error state"),
    (r"\bora-\d{4,5}\b", "Oracle error code"),
    (r"\bmysql_\w+\(", "MySQL function name"),
    (r"pg_query\(", "PostgreSQL query call"),
    (r"django\.core\.", "Django internal module"),
    (r'file "[^"]+", line \d+', "Python file reference"),
    (r"<b>Warning</b>:.*on line <b>\d+</b>", "PHP warning"),
]


def _check_error_leakage(client: httpx.Client, url: str) -> list[Finding]:
    findings: list[Finding] = []
    probe_url = url.rstrip("/") + "/__sentinel_probe_404__"
    try:
        resp = client.get(probe_url, timeout=_TIMEOUT)
        body = resp.text
        body_lower = body.lower()
        matched: list[str] = []
        snippets: list[str] = []
        for pattern, label in _LEAKY_PATTERNS:
            m = re.search(pattern, body_lower, re.IGNORECASE)
            if m:
                matched.append(label)
                start = max(0, m.start() - 40)
                end   = min(len(body_lower), m.end() + 40)
                snippets.append(f"[{label}] …{body_lower[start:end]}…")
        if matched:
            findings.append(_f(
                "high", "Information Disclosure",
                "Error response leaks internal implementation details",
                "A probe request to a nonexistent path returned a response containing "
                "internal details (stack traces, framework names, SQL errors). This "
                "information assists an attacker in targeting known vulnerabilities.",
                "Suppress detailed error output in production. Return generic error "
                "responses and log details server-side only.",
                affected_url=probe_url,
                evidence=_safe_truncate("; ".join(snippets), 400),
                confidence="high",
            ))
    except Exception:
        pass
    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_scan(target_url: str) -> list[dict]:
    """
    Run all security checks against *target_url* and return a deduplicated,
    severity-sorted list of finding dicts.

    The caller is responsible for ensuring target_url has already been
    validated via ScanRequest (input validation, authorisation flag).
    """
    findings: list[Finding] = []

    # ── Static (no network) checks ────────────────────────────────────────────
    findings += _check_https(target_url)
    findings += _check_versioning(target_url)

    # ── TLS check (raw socket, no HTTP) ──────────────────────────────────────
    findings += _check_tls(target_url)

    # ── HTTP checks (shared client) ───────────────────────────────────────────
    try:
        # verify=False is intentional: we want to scan endpoints that may have
        # self-signed / expired certs (TLS issues are reported by _check_tls).
        with httpx.Client(
            follow_redirects=True,
            verify=False,
            timeout=_TIMEOUT,
        ) as client:
            resp = client.get(target_url)

            # Single-response checks (sequential — one request)
            findings += _check_security_headers(resp.headers, target_url)
            findings += _check_server_disclosure(resp.headers, target_url)
            findings += _check_cors_simple(resp.headers, target_url)
            findings += _check_cookies(resp, target_url)
            findings += _check_rate_limit_headers(resp.headers, target_url)
            findings += _check_auth_exposure(resp.headers, target_url)

            # Multi-request probes run concurrently (bounded pool)
            probes = [
                (_check_cors_reflection, client, target_url),
                (_check_methods,         client, target_url),
                (_check_error_leakage,   client, target_url),
            ]
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {
                    pool.submit(fn, *args): fn.__name__
                    for fn, *args in probes
                }
                for future in as_completed(futures):
                    try:
                        findings += future.result()
                    except Exception:
                        pass  # individual probe failure doesn't abort the scan

    except httpx.ConnectError as exc:
        findings.append(_f(
            "critical", "Connectivity",
            "Unable to connect to target URL",
            f"API Sentinel could not establish a TCP connection to {target_url}. "
            "The host may be unreachable, firewalled, or the URL may be incorrect.",
            "Verify the URL is reachable from this host and that the server is running.",
            affected_url=target_url,
            evidence=_safe_truncate(str(exc)),
            confidence="high",
        ))
    except httpx.TimeoutException:
        findings.append(_f(
            "high", "Connectivity",
            "Connection to target URL timed out",
            f"The HTTP request to {target_url} did not complete within "
            f"{READ_TIMEOUT}s (connect) / {CONNECT_TIMEOUT}s (read).",
            "Check network connectivity and server responsiveness.",
            affected_url=target_url,
            evidence=f"Timeout after connect={CONNECT_TIMEOUT}s, read={READ_TIMEOUT}s",
            confidence="high",
        ))
    except Exception as exc:
        findings.append(_f(
            "medium", "Scanner",
            "Unexpected error during scan",
            "An unhandled exception occurred during scanning. "
            "This is likely a transient network or TLS error.",
            "Review the evidence field and try again.",
            affected_url=target_url,
            evidence=_safe_truncate(str(exc)),
            confidence="low",
        ))

    # ── Deduplicate by title, sort by severity ────────────────────────────────
    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.title not in seen:
            seen.add(f.title)
            unique.append(f)

    unique.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return [f.to_dict() for f in unique]
