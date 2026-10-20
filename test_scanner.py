"""
API Sentinel — unit tests for the scanning engine.

Strategy
--------
* The mock target (tests/mock_target.py) is embedded in-process via
  httpx.Client + httpx.MockTransport so NO real network calls are made.
* Each test configures the mock with deliberate header/CORS settings and
  asserts that exactly the expected findings are produced (or not produced).
* Tests for input validation work directly against the Pydantic model.
* A separate section tests the database layer with an in-memory SQLite DB.

Run with:
    python -m pytest tests/ -v
"""
from __future__ import annotations

import os
import sqlite3
import threading
from typing import Any

import pytest
import httpx
from fastapi.testclient import TestClient

# ── Test helpers ──────────────────────────────────────────────────────────────

# Point the DB at an in-memory path for all tests so we never touch sentinel.db
os.environ.setdefault("DB_PATH", ":memory:")

from tests.mock_target import build_app
from backend import scanner as sc
from backend.models import ScanRequest
from backend.database import init_db, create_scan, finish_scan, save_findings, get_findings


def _scan_against(config: dict[str, Any], url: str = "http://mock") -> list[dict]:
    """
    Run the scanner against a mock target built from *config*.

    We patch httpx.Client so that the scanner's internal HTTP calls are
    routed to the in-process TestClient transport — no real network I/O.
    """
    mock_app = build_app(config)
    transport = httpx.MockTransport(  # type: ignore[attr-defined]
        handler=None  # filled below
    )

    # Use TestClient as the ASGI transport
    tc = TestClient(mock_app, raise_server_exceptions=False)

    # Monkey-patch: replace the httpx.Client that scanner.run_scan creates
    # with one whose transport points at our mock ASGI app.
    original_client = sc.httpx.Client

    class _MockClient(httpx.Client):
        """httpx.Client routed to the in-process mock ASGI app."""
        def __init__(self, **kwargs):
            # Override transport with the TestClient's ASGI transport
            kwargs.pop("verify", None)
            kwargs.pop("follow_redirects", None)
            super().__init__(
                transport=httpx.WSGITransport(app=None),  # placeholder
                **kwargs,
            )
            # Re-wire to the real ASGI transport
            self._transport = tc._transport  # type: ignore[attr-defined]

    sc.httpx.Client = _MockClient  # type: ignore[assignment]
    try:
        # _check_tls does a raw socket call; it will silently skip for http://
        findings = sc.run_scan(url)
    finally:
        sc.httpx.Client = original_client  # type: ignore[assignment]

    return findings


def _titles(findings) -> set[str]:
    """Accept either Finding dataclass instances or plain dicts."""
    result = set()
    for f in findings:
        result.add(f["title"] if isinstance(f, dict) else f.title)
    return result


def _by_title(findings, title: str):
    for f in findings:
        t = f["title"] if isinstance(f, dict) else f.title
        if t == title:
            return f.to_dict() if not isinstance(f, dict) else f
    return None


def _severities(findings) -> list[str]:
    return [f["severity"] if isinstance(f, dict) else f.severity for f in findings]


# ── Input validation tests ────────────────────────────────────────────────────

class TestInputValidation:
    def test_rejects_missing_scheme(self):
        with pytest.raises(Exception, match="http"):
            ScanRequest(target_url="example.com")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(Exception):
            ScanRequest(target_url="ftp://example.com")

    def test_rejects_unauthorized(self):
        with pytest.raises(Exception, match="authorized"):
            ScanRequest(target_url="http://example.com", authorized=False)

    def test_rejects_private_ip_10(self):
        with pytest.raises(Exception, match="RFC-1918"):
            ScanRequest(target_url="http://10.0.0.1/api")

    def test_rejects_private_ip_192(self):
        with pytest.raises(Exception, match="RFC-1918"):
            ScanRequest(target_url="http://192.168.1.1/api")

    def test_rejects_private_ip_172(self):
        with pytest.raises(Exception, match="RFC-1918"):
            ScanRequest(target_url="http://172.16.5.5/api")

    def test_allows_localhost(self):
        req = ScanRequest(target_url="http://127.0.0.1:9999/api")
        assert req.target_url == "http://127.0.0.1:9999/api"

    def test_allows_localhost_hostname(self):
        req = ScanRequest(target_url="http://localhost:8080")
        assert "localhost" in req.target_url

    def test_strips_trailing_slash(self):
        req = ScanRequest(target_url="https://example.com/api/")
        assert not req.target_url.endswith("/")

    def test_rejects_too_long_url(self):
        with pytest.raises(Exception, match="too long"):
            ScanRequest(target_url="https://example.com/" + "a" * 2048)


# ── HTTP / HTTPS check ────────────────────────────────────────────────────────

class TestHttpsCheck:
    def test_plain_http_fires_critical(self):
        findings = sc._check_https("http://example.com")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert f.category == "Transport Security"
        assert "http" in f.evidence.lower()

    def test_https_clean(self):
        assert sc._check_https("https://example.com") == []


# ── Security header checks ────────────────────────────────────────────────────

class TestSecurityHeaders:
    def _headers(self, d: dict) -> httpx.Headers:
        return httpx.Headers(d)

    def test_all_headers_missing_fires_five_findings(self):
        # Over HTTPS: HSTS + XCTO + XFO + CSP + Referrer + Permissions = 6
        findings = sc._check_security_headers(self._headers({}), "https://x.com")
        titles = _titles(findings)
        assert "HSTS header missing" in titles
        assert "X-Content-Type-Options header missing" in titles
        assert "X-Frame-Options header missing" in titles
        assert "Content-Security-Policy header missing" in titles
        assert "Referrer-Policy header missing" in titles
        assert "Permissions-Policy header missing" in titles

    def test_hsts_not_required_over_http(self):
        findings = sc._check_security_headers(self._headers({}), "http://x.com")
        titles = _titles(findings)
        assert "HSTS header missing" not in titles

    def test_present_headers_suppress_findings(self):
        headers = self._headers({
            "strict-transport-security": "max-age=63072000",
            "x-content-type-options":    "nosniff",
            "x-frame-options":           "DENY",
            "content-security-policy":   "default-src 'self'",
            "referrer-policy":           "strict-origin-when-cross-origin",
            "permissions-policy":        "camera=()",
        })
        findings = sc._check_security_headers(headers, "https://x.com")
        assert findings == []

    def test_hsts_short_max_age_fires_medium(self):
        headers = self._headers({"strict-transport-security": "max-age=3600"})
        findings = sc._check_security_headers(headers, "https://x.com")
        titles = _titles(findings)
        assert "HSTS max-age is too short" in titles
        short_finding = _by_title(findings, "HSTS max-age is too short")
        assert short_finding is not None
        assert short_finding["severity"] == "medium"
        assert "3600" in short_finding["evidence"]

    def test_hsts_adequate_max_age_no_finding(self):
        headers = self._headers({"strict-transport-security": "max-age=63072000; includeSubDomains"})
        findings = sc._check_security_headers(headers, "https://x.com")
        titles = _titles(findings)
        assert "HSTS max-age is too short" not in titles
        assert "HSTS header missing" not in titles


# ── CORS checks ───────────────────────────────────────────────────────────────

class TestCorsSimple:
    def _headers(self, d: dict) -> httpx.Headers:
        return httpx.Headers(d)

    def test_wildcard_acao_fires_high(self):
        findings = sc._check_cors_simple(
            self._headers({"access-control-allow-origin": "*"}), "https://x.com"
        )
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].confidence == "high"
        assert "*" in findings[0].evidence

    def test_wildcard_with_credentials_fires_critical(self):
        findings = sc._check_cors_simple(
            self._headers({
                "access-control-allow-origin":      "*",
                "access-control-allow-credentials": "true",
            }),
            "https://x.com",
        )
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_specific_origin_no_finding(self):
        findings = sc._check_cors_simple(
            self._headers({"access-control-allow-origin": "https://trusted.example.com"}),
            "https://x.com",
        )
        assert findings == []

    def test_no_cors_headers_no_finding(self):
        findings = sc._check_cors_simple(self._headers({}), "https://x.com")
        assert findings == []


class TestCorsReflection:
    """
    Test the reflection probe using a real httpx.Client pointed at an
    in-process TestClient.
    """
    def _client_for(self, config: dict) -> httpx.Client:
        app = build_app(config)
        tc = TestClient(app, raise_server_exceptions=False)
        client = httpx.Client(transport=tc._transport)  # type: ignore[attr-defined]
        return client

    def test_reflection_fires_high(self):
        client = self._client_for({"cors_reflect_origin": True})
        findings = sc._check_cors_reflection(client, "http://mock")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert "evil.sentinel-probe.invalid" in f.evidence

    def test_reflection_with_credentials_fires_critical(self):
        client = self._client_for({"cors_reflect_origin": True, "cors_credentials": True})
        findings = sc._check_cors_reflection(client, "http://mock")
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_no_reflection_no_finding(self):
        client = self._client_for({"cors_origin": "https://trusted.com"})
        findings = sc._check_cors_reflection(client, "http://mock")
        assert findings == []

    def test_wildcard_not_reflected_no_reflection_finding(self):
        # Wildcard is caught by _check_cors_simple, not by reflection check
        client = self._client_for({"cors_origin": "*"})
        findings = sc._check_cors_reflection(client, "http://mock")
        assert findings == []


# ── Server disclosure ─────────────────────────────────────────────────────────

class TestServerDisclosure:
    def _headers(self, d: dict) -> httpx.Headers:
        return httpx.Headers(d)

    def test_server_header_fires_low(self):
        findings = sc._check_server_disclosure(
            self._headers({"server": "Apache/2.4.51"}), "https://x.com"
        )
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert "Apache/2.4.51" in findings[0].evidence

    def test_x_powered_by_fires(self):
        findings = sc._check_server_disclosure(
            self._headers({"x-powered-by": "PHP/7.4"}), "https://x.com"
        )
        assert any("x-powered-by" in f.title.lower() for f in findings)

    def test_no_disclosure_no_finding(self):
        findings = sc._check_server_disclosure(self._headers({}), "https://x.com")
        assert findings == []


# ── HTTP methods ──────────────────────────────────────────────────────────────

class TestHttpMethods:
    def _client_for(self, allow: str) -> httpx.Client:
        app = build_app({"allow_methods": allow})
        tc = TestClient(app, raise_server_exceptions=False)
        return httpx.Client(transport=tc._transport)  # type: ignore[attr-defined]

    def test_trace_fires_high(self):
        client = self._client_for("GET, POST, TRACE, OPTIONS")
        findings = sc._check_methods(client, "http://mock")
        titles = _titles(findings)
        assert any("TRACE" in t for t in titles)
        dangerous = [f for f in findings if "TRACE" in f.title]
        assert dangerous[0].severity == "high"

    def test_sensitive_methods_fire_info(self):
        client = self._client_for("GET, POST, PUT, DELETE, OPTIONS")
        findings = sc._check_methods(client, "http://mock")
        info_f = [f for f in findings if f.severity == "info"]
        assert len(info_f) >= 1
        assert any("DELETE" in f.title or "PUT" in f.title for f in info_f)

    def test_safe_methods_only_no_dangerous_finding(self):
        client = self._client_for("GET, POST, OPTIONS")
        findings = sc._check_methods(client, "http://mock")
        dangerous = [f for f in findings if f.severity == "high"]
        assert dangerous == []


# ── Error leakage ─────────────────────────────────────────────────────────────

class TestErrorLeakage:
    def _client_for(self, leak: bool) -> httpx.Client:
        app = build_app({"leak_errors": leak})
        tc = TestClient(app, raise_server_exceptions=False)
        return httpx.Client(transport=tc._transport)  # type: ignore[attr-defined]

    def test_leak_fires_high(self):
        client = self._client_for(leak=True)
        findings = sc._check_error_leakage(client, "http://mock")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert f.confidence == "high"
        assert "traceback" in f.evidence.lower() or "python" in f.evidence.lower()

    def test_no_leak_no_finding(self):
        client = self._client_for(leak=False)
        findings = sc._check_error_leakage(client, "http://mock")
        assert findings == []


# ── Rate-limit headers ────────────────────────────────────────────────────────

class TestRateLimitHeaders:
    def _headers(self, d: dict) -> httpx.Headers:
        return httpx.Headers(d)

    def test_absent_fires_medium(self):
        findings = sc._check_rate_limit_headers(self._headers({}), "https://x.com")
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert findings[0].confidence == "medium"

    def test_ratelimit_limit_suppresses(self):
        findings = sc._check_rate_limit_headers(
            self._headers({"ratelimit-limit": "100"}), "https://x.com"
        )
        assert findings == []

    def test_x_ratelimit_suppresses(self):
        findings = sc._check_rate_limit_headers(
            self._headers({"x-ratelimit-limit": "100"}), "https://x.com"
        )
        assert findings == []

    def test_retry_after_suppresses(self):
        findings = sc._check_rate_limit_headers(
            self._headers({"retry-after": "60"}), "https://x.com"
        )
        assert findings == []


# ── Auth header exposure ──────────────────────────────────────────────────────

class TestAuthExposure:
    def _headers(self, d: dict) -> httpx.Headers:
        return httpx.Headers(d)

    def test_basic_auth_fires_high(self):
        findings = sc._check_auth_exposure(
            self._headers({"www-authenticate": "Basic realm=\"API\""}), "https://x.com"
        )
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Basic" in findings[0].evidence

    def test_bearer_does_not_fire(self):
        findings = sc._check_auth_exposure(
            self._headers({"www-authenticate": "Bearer realm=\"API\""}), "https://x.com"
        )
        assert findings == []

    def test_absent_does_not_fire(self):
        findings = sc._check_auth_exposure(self._headers({}), "https://x.com")
        assert findings == []


# ── API versioning ────────────────────────────────────────────────────────────

class TestVersioning:
    def test_no_version_fires_info(self):
        findings = sc._check_versioning("http://example.com/api/users")
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert findings[0].confidence == "medium"

    def test_v1_suppresses(self):
        assert sc._check_versioning("http://example.com/v1/users") == []

    def test_v2_suppresses(self):
        assert sc._check_versioning("https://api.example.com/v2") == []


# ── Finding structure ─────────────────────────────────────────────────────────

class TestFindingStructure:
    """Every finding dict must contain the required keys with non-empty values."""

    REQUIRED_KEYS = {"severity", "category", "title", "description",
                     "remediation", "affected_url", "evidence", "confidence"}
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_CONFIDENCES = {"high", "medium", "low"}

    def _all_findings(self) -> list[dict]:
        checks: list[list] = [
            sc._check_https("http://x.com"),
            sc._check_https("https://x.com"),
            sc._check_security_headers(httpx.Headers({}), "https://x.com"),
            sc._check_server_disclosure(httpx.Headers({"server": "nginx"}), "https://x.com"),
            sc._check_cors_simple(
                httpx.Headers({"access-control-allow-origin": "*"}), "https://x.com"
            ),
            sc._check_rate_limit_headers(httpx.Headers({}), "https://x.com"),
            sc._check_auth_exposure(
                httpx.Headers({"www-authenticate": "Basic realm=x"}), "https://x.com"
            ),
            sc._check_versioning("https://x.com/api"),
        ]
        return [f.to_dict() for group in checks for f in group]

    def test_all_required_keys_present(self):
        for f in self._all_findings():
            missing = self.REQUIRED_KEYS - f.keys()
            assert not missing, f"Finding missing keys {missing}: {f['title']}"

    def test_severity_values_valid(self):
        for f in self._all_findings():
            assert f["severity"] in self.VALID_SEVERITIES, \
                f"Invalid severity '{f['severity']}' in: {f['title']}"

    def test_confidence_values_valid(self):
        for f in self._all_findings():
            assert f["confidence"] in self.VALID_CONFIDENCES, \
                f"Invalid confidence '{f['confidence']}' in: {f['title']}"

    def test_no_empty_title_or_description(self):
        for f in self._all_findings():
            assert f["title"].strip(), "Finding has empty title"
            assert f["description"].strip(), "Finding has empty description"
            assert f["remediation"].strip(), "Finding has empty remediation"


# ── Deduplication ─────────────────────────────────────────────────────────────

class TestDeduplication:
    def test_no_duplicate_titles(self):
        # CORS wildcard fires both _check_cors_simple and potentially others;
        # run_scan should deduplicate.
        # We mock a minimal response with lots of headers absent.
        import httpx as _httpx

        # Build a trivial mock that returns a bare 200 with wildcard CORS
        from fastapi import FastAPI as _FA
        from fastapi.responses import JSONResponse as _JR

        _app = build_app({"cors_origin": "*"})
        tc = TestClient(_app, raise_server_exceptions=False)

        original = sc.httpx.Client

        class _MC(_httpx.Client):
            def __init__(self, **kw):
                kw.pop("verify", None)
                kw.pop("follow_redirects", None)
                super().__init__(transport=tc._transport, **kw)  # type: ignore

        sc.httpx.Client = _MC  # type: ignore
        try:
            findings = sc.run_scan("http://mock")
        finally:
            sc.httpx.Client = original  # type: ignore

        titles = [f["title"] for f in findings]
        assert len(titles) == len(set(titles)), "Duplicate finding titles found"


# ── Severity ordering ─────────────────────────────────────────────────────────

class TestSeverityOrdering:
    def test_results_sorted_by_severity(self):
        # Plain HTTP URL → will have critical first
        import httpx as _httpx

        _app = build_app({"server_header": "nginx", "allow_methods": "GET, TRACE, OPTIONS"})
        tc = TestClient(_app, raise_server_exceptions=False)
        original = sc.httpx.Client

        class _MC(_httpx.Client):
            def __init__(self, **kw):
                kw.pop("verify", None)
                kw.pop("follow_redirects", None)
                super().__init__(transport=tc._transport, **kw)  # type: ignore

        sc.httpx.Client = _MC  # type: ignore
        try:
            findings = sc.run_scan("http://mock")
        finally:
            sc.httpx.Client = original  # type: ignore

        order = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "info"])}
        sev_indices = [order[f["severity"]] for f in findings]
        assert sev_indices == sorted(sev_indices), "Findings are not sorted by severity"


# ── Database tests ────────────────────────────────────────────────────────────

class TestDatabase:
    """Test DB helpers with an isolated per-test temporary database file."""

    def setup_method(self):
        import tempfile
        import backend.database as db_mod
        self._orig_path = db_mod.DB_PATH
        # Use a named temp file so every get_connection() call in the same
        # test hits the same on-disk DB (":memory:" creates a fresh DB each
        # connection).
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        db_mod.DB_PATH = self._tmp.name
        db_mod.init_db()

    def teardown_method(self):
        import os
        import backend.database as db_mod
        db_mod.DB_PATH = self._orig_path
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def test_create_and_finish_scan(self):
        import backend.database as db_mod
        sid = db_mod.create_scan("https://example.com")
        assert isinstance(sid, int)
        assert sid > 0
        row = db_mod.get_scan(sid)
        assert row is not None
        assert row["status"] == "running"
        db_mod.finish_scan(sid)
        row = db_mod.get_scan(sid)
        assert row["status"] == "done"
        assert row["finished_at"] is not None

    def test_fail_scan(self):
        import backend.database as db_mod
        sid = db_mod.create_scan("https://example.com")
        db_mod.fail_scan(sid)
        row = db_mod.get_scan(sid)
        assert row["status"] == "failed"

    def test_save_and_retrieve_findings(self):
        import backend.database as db_mod
        sid = db_mod.create_scan("https://example.com")
        sample = [
            {
                "severity":    "high",
                "category":    "CORS",
                "title":       "Wildcard CORS",
                "description": "desc",
                "remediation": "fix it",
                "affected_url": "https://example.com",
                "evidence":    "acao: *",
                "confidence":  "high",
            }
        ]
        db_mod.save_findings(sid, sample)
        rows = db_mod.get_findings(sid)
        assert len(rows) == 1
        assert rows[0]["title"] == "Wildcard CORS"
        assert rows[0]["evidence"] == "acao: *"
        assert rows[0]["confidence"] == "high"
        assert rows[0]["affected_url"] == "https://example.com"

    def test_count_findings(self):
        import backend.database as db_mod
        sid = db_mod.create_scan("https://example.com")
        findings = [
            {"severity": "low", "category": "X", "title": f"F{i}",
             "description": "d", "remediation": "r",
             "affected_url": "", "evidence": "", "confidence": "high"}
            for i in range(3)
        ]
        db_mod.save_findings(sid, findings)
        assert db_mod.count_findings(sid) == 3

    def test_list_scans_returns_most_recent_first(self):
        import time
        import backend.database as db_mod
        id1 = db_mod.create_scan("https://a.com")
        # Ensure the second scan gets a strictly later created_at timestamp.
        time.sleep(1.1)
        id2 = db_mod.create_scan("https://b.com")
        rows = db_mod.list_scans()
        ids = [r["id"] for r in rows]
        assert ids.index(id2) < ids.index(id1), (
            f"Expected id2={id2} before id1={id1} in {ids}"
        )

    def test_findings_sorted_by_severity(self):
        import backend.database as db_mod
        sid = db_mod.create_scan("https://example.com")
        findings = [
            {"severity": "low",      "category": "X", "title": "Low F",      "description": "d", "remediation": "r", "affected_url": "", "evidence": "", "confidence": "high"},
            {"severity": "critical", "category": "X", "title": "Critical F",  "description": "d", "remediation": "r", "affected_url": "", "evidence": "", "confidence": "high"},
            {"severity": "medium",   "category": "X", "title": "Medium F",   "description": "d", "remediation": "r", "affected_url": "", "evidence": "", "confidence": "high"},
        ]
        db_mod.save_findings(sid, findings)
        rows = db_mod.get_findings(sid)
        order = ["critical", "high", "medium", "low", "info"]
        indices = [order.index(r["severity"]) for r in rows]
        assert indices == sorted(indices)

    def test_migration_adds_columns_to_old_schema(self):
        """Simulate a pre-migration DB that has no extended columns."""
        import backend.database as db_mod

        # Create the old schema manually
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """CREATE TABLE findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                remediation TEXT NOT NULL
            )"""
        )
        conn.commit()

        # Run migration helper
        db_mod._add_column_if_missing(conn, "findings", "affected_url", "TEXT NOT NULL DEFAULT ''")
        db_mod._add_column_if_missing(conn, "findings", "evidence",     "TEXT NOT NULL DEFAULT ''")
        db_mod._add_column_if_missing(conn, "findings", "confidence",   "TEXT NOT NULL DEFAULT 'high'")

        cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        assert "affected_url" in cols
        assert "evidence" in cols
        assert "confidence" in cols
        conn.close()
