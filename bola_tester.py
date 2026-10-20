"""
backend/lab/bola_tester.py — BOLA / IDOR Automated Test Runner
==============================================================

What it does
------------
Executes a repeatable set of BOLA (Broken Object Level Authorization) /
IDOR (Insecure Direct Object Reference) test scenarios against the local
demo API.

Each scenario describes:
  • The attacker identity (User B)
  • The victim's record ID (owned by User A)
  • The expected outcome in a secure system (403 or 404)
  • The actual HTTP response received
  • A verdict: PASS (access denied as expected) or FAIL (unauthorized access granted)
  • The full request/response evidence

No real user data is involved.  All records are synthetic.
The vulnerable demo API is only ever instantiated in-process.

Usage
-----
    from backend.lab.bola_tester import run_bola_tests
    results = run_bola_tests(secure=True)   # or secure=False
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Literal

import httpx
from fastapi.testclient import TestClient

from backend.lab.demo_api import build_demo_app, USERS, RECORDS

# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class ScenarioResult:
    scenario_id:    str
    title:          str
    description:    str
    attacker:       str          # username of the caller
    attacker_token: str          # token used (shown redacted in display)
    victim:         str          # username of the record owner
    record_id:      int
    mode:           Literal["secure", "vulnerable"]

    # Request details
    request_method: str
    request_url:    str
    request_headers: dict[str, str]

    # Expected / actual
    expected_status: int          # 403 or 404 in a secure system
    actual_status:   int
    actual_body:     str          # truncated response body

    # Verdict
    verdict:         Literal["PASS", "FAIL"]
    verdict_reason:  str

    def to_dict(self) -> dict:
        d = asdict(self)
        # Redact the token in the output — show only first/last 4 chars
        tok = self.attacker_token
        d["attacker_token_display"] = tok[:10] + "…" if len(tok) > 10 else tok
        return d


@dataclass
class BolaTestRun:
    mode:       Literal["secure", "vulnerable"]
    total:      int
    passed:     int
    failed:     int
    scenarios:  list[ScenarioResult]

    @property
    def overall_verdict(self) -> Literal["PASS", "FAIL"]:
        return "PASS" if self.failed == 0 else "FAIL"

    def to_dict(self) -> dict:
        return {
            "mode":            self.mode,
            "total":           self.total,
            "passed":          self.passed,
            "failed":          self.failed,
            "overall_verdict": self.overall_verdict,
            "scenarios":       [s.to_dict() for s in self.scenarios],
        }


# ── Test scenarios ────────────────────────────────────────────────────────────

# We test cross-user access in both directions.
# Each entry: (scenario_id, attacker_token_key, victim_record_id, description)
_SCENARIOS: list[tuple[str, str, int, str]] = [
    (
        "BOLA-01",
        "token-bob-002",    # attacker = bob
        1,                   # victim's record = alice's record id=1
        "User B (bob) attempts to read User A (alice)'s record id=1 "
        "using bob's own valid token.",
    ),
    (
        "BOLA-02",
        "token-bob-002",    # attacker = bob
        2,                   # victim's record = alice's record id=2
        "User B (bob) attempts to read User A (alice)'s record id=2 "
        "using bob's own valid token.",
    ),
    (
        "BOLA-03",
        "token-alice-001",  # attacker = alice
        3,                   # victim's record = bob's record id=3
        "User A (alice) attempts to read User B (bob)'s record id=3 "
        "using alice's own valid token.",
    ),
    (
        "BOLA-04",
        "token-alice-001",  # attacker = alice
        4,                   # victim's record = bob's record id=4
        "User A (alice) attempts to read User B (bob)'s record id=4 "
        "using alice's own valid token.",
    ),
]


# ── Runner ────────────────────────────────────────────────────────────────────

def run_bola_tests(secure: bool = True) -> BolaTestRun:
    """
    Run all BOLA test scenarios against the demo API.

    Parameters
    ----------
    secure : bool
        True  → test the secure (correct) implementation; expect all PASS
        False → test the vulnerable implementation; expect all FAIL
    """
    mode: Literal["secure", "vulnerable"] = "secure" if secure else "vulnerable"
    app  = build_demo_app(secure=secure)

    # Use httpx TestClient backed by the in-process ASGI app — no network I/O
    with TestClient(app, raise_server_exceptions=False) as tc:
        results: list[ScenarioResult] = []

        for scenario_id, attacker_token, record_id, description in _SCENARIOS:
            attacker_user = USERS[attacker_token]
            victim_record = RECORDS[record_id]
            victim_user   = USERS[
                next(t for t, u in USERS.items() if u["user_id"] == victim_record["owner_id"])
            ]

            url     = f"/demo/records/{record_id}"
            headers = {"Authorization": f"Bearer {attacker_token}"}

            resp = tc.get(url, headers=headers)

            # In a correctly secured system cross-user access must yield 403 or 404.
            # We accept either — 404 is valid if the server masks existence.
            expected_status = 403  # canonical correct status for ownership violation
            secure_statuses = {403, 404}

            actual_body = _truncate(resp.text, 500)

            if secure:
                # Expect access DENIED
                if resp.status_code in secure_statuses:
                    verdict        = "PASS"
                    verdict_reason = (
                        f"Access correctly denied with HTTP {resp.status_code}. "
                        "The server enforced object-level authorization."
                    )
                else:
                    verdict        = "FAIL"
                    verdict_reason = (
                        f"Expected HTTP 403/404 but received HTTP {resp.status_code}. "
                        "The server did NOT enforce object-level authorization — "
                        "this is a BOLA vulnerability."
                    )
            else:
                # Expect access GRANTED (demonstrates the vulnerability)
                if resp.status_code == 200:
                    verdict        = "FAIL"
                    verdict_reason = (
                        f"Unauthorized access GRANTED (HTTP 200). "
                        f"Record id={record_id} belonging to '{victim_record['owner']}' "
                        f"was returned to '{attacker_user['username']}' without "
                        "any ownership check. This is a confirmed BOLA vulnerability."
                    )
                elif resp.status_code in secure_statuses:
                    # Vulnerable mode unexpectedly blocked — still a PASS for safety
                    verdict        = "PASS"
                    verdict_reason = (
                        f"Access denied (HTTP {resp.status_code}) even in vulnerable mode. "
                        "This is unexpected but safe."
                    )
                else:
                    verdict        = "FAIL"
                    verdict_reason = (
                        f"Unexpected HTTP {resp.status_code}. "
                        "Cannot determine whether access control is enforced."
                    )

            results.append(ScenarioResult(
                scenario_id      = scenario_id,
                title            = (
                    f"{scenario_id}: {attacker_user['username']} → "
                    f"record {record_id} (owned by {victim_record['owner']})"
                ),
                description      = description,
                attacker         = attacker_user["username"],
                attacker_token   = attacker_token,
                victim           = victim_record["owner"],
                record_id        = record_id,
                mode             = mode,
                request_method   = "GET",
                request_url      = url,
                request_headers  = {"Authorization": f"Bearer {attacker_token[:10]}…"},
                expected_status  = expected_status,
                actual_status    = resp.status_code,
                actual_body      = actual_body,
                verdict          = verdict,
                verdict_reason   = verdict_reason,
            ))

    passed = sum(1 for r in results if r.verdict == "PASS")
    failed = len(results) - passed

    return BolaTestRun(
        mode      = mode,
        total     = len(results),
        passed    = passed,
        failed    = failed,
        scenarios = results,
    )


def _truncate(text: str, limit: int) -> str:
    return text[:limit] + "…" if len(text) > limit else text
