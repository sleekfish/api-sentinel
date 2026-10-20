"""Pydantic schemas for request/response validation."""
from __future__ import annotations

import re
from pydantic import BaseModel, field_validator
from typing import Literal

# ── Input validation ──────────────────────────────────────────────────────────

# Reject private / loopback ranges *except* localhost (127.0.0.1 / ::1 / localhost)
# so that the test-suite's mock server is always reachable.
# Actual private-network scanning is blocked for safety.
_PRIVATE_IP_RE = re.compile(
    r"^https?://"
    r"("
    r"10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|169\.254\.\d+\.\d+"   # link-local
    r"|fc[0-9a-f]{2}:"       # IPv6 ULA
    r")"
)


class ScanRequest(BaseModel):
    target_url: str
    # If True the caller asserts they own / have authorised access to this target.
    # The UI always sends True; the field exists to make the contract explicit.
    authorized: bool = True

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        # Strip trailing slash for consistency
        v = v.rstrip("/")
        if len(v) > 2048:
            raise ValueError("target_url is too long (max 2048 characters)")
        if _PRIVATE_IP_RE.match(v.lower()):
            raise ValueError(
                "Scanning private/RFC-1918 IP addresses is not permitted. "
                "Use a public hostname or 127.0.0.1/localhost for local testing."
            )
        return v

    @field_validator("authorized")
    @classmethod
    def must_be_authorized(cls, v: bool) -> bool:
        if not v:
            raise ValueError(
                "You must confirm you are authorized to scan this target "
                "(set authorized=true)."
            )
        return v


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: str
    title: str
    description: str
    remediation: str
    # Extended fields (default to empty string / "high" so old DB rows still work)
    affected_url: str = ""
    evidence: str = ""
    confidence: Literal["high", "medium", "low"] = "high"


# ── Scan ──────────────────────────────────────────────────────────────────────

class ScanOut(BaseModel):
    id: int
    target_url: str
    status: str
    created_at: str
    finished_at: str | None
    findings: list[FindingOut] = []


class ScanSummary(BaseModel):
    id: int
    target_url: str
    status: str
    created_at: str
    finished_at: str | None
    finding_count: int = 0


# ── Stats ────────────────────────────────────────────────────────────────────

class StatsOut(BaseModel):
    total_scans:    int
    done_scans:     int
    total_findings: int
    critical:       int
    high:           int
    medium:         int
    low:            int
    info:           int


# ── Health ────────────────────────────────────────────────────────────────────

class HealthOut(BaseModel):
    status: str
    version: str
    db: str
