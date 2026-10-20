"""
tests/test_bola.py — Automated tests for the BOLA / IDOR authorization lab.

Test coverage
-------------
TestDemoApiAuth
  - Unauthenticated requests are rejected with 401
  - Bad tokens are rejected with 401
  - Malformed Authorization headers are rejected with 401

TestDemoApiOwnership_Secure
  - Users can access their own records (200)
  - Cross-user access is rejected with 403
  - Own /demo/me returns correct identity

TestDemoApiOwnership_Vulnerable
  - Users can access their own records (200) — unchanged
  - Cross-user access succeeds with 200 — the intentional BOLA
  - The returned record body contains the victim's data

TestBolaRunner_SecureMode
  - All 4 scenarios PASS (access denied as expected)
  - Overall verdict is PASS
  - Each scenario actual_status is 403
  - Result mode field is "secure"

TestBolaRunner_VulnerableMode
  - All 4 scenarios FAIL (unauthorized access granted)
  - Overall verdict is FAIL
  - Each scenario actual_status is 200
  - Result mode field is "vulnerable"
  - Victim's record content is present in response body

TestBolaRunnerStructure
  - All required fields present in each ScenarioResult
  - attacker != victim for every scenario
  - attacker_token_display is redacted

TestLabApiRoutes
  - POST /api/lab/bola?secure=true  returns overall_verdict=PASS
  - POST /api/lab/bola?secure=false returns overall_verdict=FAIL
  - GET  /api/lab/info  returns user and record lists
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.lab.demo_api import build_demo_app, USERS, RECORDS
from backend.lab.bola_tester import run_bola_tests, ScenarioResult, BolaTestRun
from backend.main import app as main_app

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def secure_client():
    return TestClient(build_demo_app(secure=True),  raise_server_exceptions=False)

@pytest.fixture()
def vuln_client():
    return TestClient(build_demo_app(secure=False), raise_server_exceptions=False)

@pytest.fixture()
def api_client():
    return TestClient(main_app, raise_server_exceptions=False)

# Convenience token constants
ALICE = "token-alice-001"
BOB   = "token-bob-002"

def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── TestDemoApiAuth ───────────────────────────────────────────────────────────

class TestDemoApiAuth:
    def test_no_token_returns_401(self, secure_client):
        resp = secure_client.get("/demo/records/1")
        assert resp.status_code == 401

    def test_bad_token_returns_401(self, secure_client):
        resp = secure_client.get("/demo/records/1", headers={"Authorization": "Bearer bad-token"})
        assert resp.status_code == 401

    def test_malformed_header_returns_401(self, secure_client):
        resp = secure_client.get("/demo/records/1", headers={"Authorization": "token-alice-001"})
        assert resp.status_code == 401

    def test_missing_bearer_prefix_returns_401(self, secure_client):
        resp = secure_client.get("/demo/records/1", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_whoami_no_token_returns_401(self, secure_client):
        resp = secure_client.get("/demo/me")
        assert resp.status_code == 401


# ── TestDemoApiOwnership_Secure ───────────────────────────────────────────────

class TestDemoApiOwnership_Secure:
    def test_alice_reads_own_record_1(self, secure_client):
        resp = secure_client.get("/demo/records/1", headers=_auth(ALICE))
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert data["owner"] == "alice"

    def test_alice_reads_own_record_2(self, secure_client):
        resp = secure_client.get("/demo/records/2", headers=_auth(ALICE))
        assert resp.status_code == 200
        assert resp.json()["owner"] == "alice"

    def test_bob_reads_own_record_3(self, secure_client):
        resp = secure_client.get("/demo/records/3", headers=_auth(BOB))
        assert resp.status_code == 200
        assert resp.json()["owner"] == "bob"

    def test_bob_reads_own_record_4(self, secure_client):
        resp = secure_client.get("/demo/records/4", headers=_auth(BOB))
        assert resp.status_code == 200
        assert resp.json()["owner"] == "bob"

    def test_bob_cannot_read_alice_record_1(self, secure_client):
        """Cross-user access must be denied in secure mode."""
        resp = secure_client.get("/demo/records/1", headers=_auth(BOB))
        assert resp.status_code == 403

    def test_bob_cannot_read_alice_record_2(self, secure_client):
        resp = secure_client.get("/demo/records/2", headers=_auth(BOB))
        assert resp.status_code == 403

    def test_alice_cannot_read_bob_record_3(self, secure_client):
        resp = secure_client.get("/demo/records/3", headers=_auth(ALICE))
        assert resp.status_code == 403

    def test_alice_cannot_read_bob_record_4(self, secure_client):
        resp = secure_client.get("/demo/records/4", headers=_auth(ALICE))
        assert resp.status_code == 403

    def test_403_detail_mentions_owner(self, secure_client):
        resp = secure_client.get("/demo/records/1", headers=_auth(BOB))
        body = resp.json()
        assert "alice" in body.get("detail", "").lower()
        assert "bob" in body.get("detail", "").lower()

    def test_unknown_record_returns_404(self, secure_client):
        resp = secure_client.get("/demo/records/999", headers=_auth(ALICE))
        assert resp.status_code == 404

    def test_whoami_alice(self, secure_client):
        resp = secure_client.get("/demo/me", headers=_auth(ALICE))
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_whoami_bob(self, secure_client):
        resp = secure_client.get("/demo/me", headers=_auth(BOB))
        assert resp.status_code == 200
        assert resp.json()["username"] == "bob"

    def test_list_records_only_returns_own(self, secure_client):
        resp = secure_client.get("/demo/records", headers=_auth(ALICE))
        assert resp.status_code == 200
        records = resp.json()["records"]
        assert all(r["owner"] == "alice" for r in records)
        assert len(records) == 2


# ── TestDemoApiOwnership_Vulnerable ──────────────────────────────────────────

class TestDemoApiOwnership_Vulnerable:
    """The vulnerable mode intentionally allows cross-user record access."""

    def test_alice_reads_own_record_still_works(self, vuln_client):
        resp = vuln_client.get("/demo/records/1", headers=_auth(ALICE))
        assert resp.status_code == 200

    def test_bob_reads_alice_record_1_succeeds(self, vuln_client):
        """BOLA — bob reads alice's record. Expect 200 in vulnerable mode."""
        resp = vuln_client.get("/demo/records/1", headers=_auth(BOB))
        assert resp.status_code == 200, (
            "Expected vulnerable mode to return 200 for cross-user access"
        )

    def test_bob_reads_alice_record_2_succeeds(self, vuln_client):
        resp = vuln_client.get("/demo/records/2", headers=_auth(BOB))
        assert resp.status_code == 200

    def test_alice_reads_bob_record_3_succeeds(self, vuln_client):
        resp = vuln_client.get("/demo/records/3", headers=_auth(ALICE))
        assert resp.status_code == 200

    def test_alice_reads_bob_record_4_succeeds(self, vuln_client):
        resp = vuln_client.get("/demo/records/4", headers=_auth(ALICE))
        assert resp.status_code == 200

    def test_victim_data_leaked_in_response(self, vuln_client):
        """The response body contains alice's secret content."""
        resp = vuln_client.get("/demo/records/1", headers=_auth(BOB))
        body = resp.json()
        assert body["owner"] == "alice"
        assert "secret-a1" in body["content"], (
            "Victim's sensitive content was not present in the leaked response"
        )

    def test_all_four_records_accessible_by_any_user(self, vuln_client):
        for record_id in [1, 2, 3, 4]:
            for token in [ALICE, BOB]:
                resp = vuln_client.get(f"/demo/records/{record_id}", headers=_auth(token))
                assert resp.status_code == 200, (
                    f"Expected 200 for record {record_id} with token {token[:15]}"
                )


# ── TestBolaRunner_SecureMode ─────────────────────────────────────────────────

class TestBolaRunner_SecureMode:
    def setup_method(self):
        self.run = run_bola_tests(secure=True)

    def test_mode_is_secure(self):
        assert self.run.mode == "secure"

    def test_total_is_four(self):
        assert self.run.total == 4

    def test_all_scenarios_pass(self):
        assert self.run.passed == 4
        assert self.run.failed == 0

    def test_overall_verdict_is_pass(self):
        assert self.run.overall_verdict == "PASS"

    def test_each_actual_status_is_403(self):
        for s in self.run.scenarios:
            assert s.actual_status == 403, (
                f"{s.scenario_id}: expected 403 in secure mode, got {s.actual_status}"
            )

    def test_each_verdict_is_pass(self):
        for s in self.run.scenarios:
            assert s.verdict == "PASS", f"{s.scenario_id} verdict: {s.verdict}"

    def test_verdict_reason_mentions_denied(self):
        for s in self.run.scenarios:
            assert "denied" in s.verdict_reason.lower(), (
                f"{s.scenario_id}: reason should mention 'denied'"
            )


# ── TestBolaRunner_VulnerableMode ─────────────────────────────────────────────

class TestBolaRunner_VulnerableMode:
    def setup_method(self):
        self.run = run_bola_tests(secure=False)

    def test_mode_is_vulnerable(self):
        assert self.run.mode == "vulnerable"

    def test_total_is_four(self):
        assert self.run.total == 4

    def test_all_scenarios_fail(self):
        assert self.run.failed == 4
        assert self.run.passed == 0

    def test_overall_verdict_is_fail(self):
        assert self.run.overall_verdict == "FAIL"

    def test_each_actual_status_is_200(self):
        for s in self.run.scenarios:
            assert s.actual_status == 200, (
                f"{s.scenario_id}: expected 200 in vulnerable mode, got {s.actual_status}"
            )

    def test_each_verdict_is_fail(self):
        for s in self.run.scenarios:
            assert s.verdict == "FAIL", f"{s.scenario_id} verdict: {s.verdict}"

    def test_verdict_reason_mentions_unauthorized_access(self):
        for s in self.run.scenarios:
            r = s.verdict_reason.lower()
            assert "unauthorized" in r or "granted" in r or "bola" in r, (
                f"{s.scenario_id}: reason should indicate unauthorized access"
            )

    def test_victim_content_in_response_body(self):
        """The actual_body must contain the victim's record content."""
        for s in self.run.scenarios:
            victim_record = RECORDS[s.record_id]
            assert victim_record["content"] in s.actual_body, (
                f"{s.scenario_id}: victim's secret content not found in body"
            )


# ── TestBolaRunnerStructure ───────────────────────────────────────────────────

class TestBolaRunnerStructure:
    REQUIRED_SCENARIO_FIELDS = {
        "scenario_id", "title", "description", "attacker", "attacker_token",
        "victim", "record_id", "mode", "request_method", "request_url",
        "request_headers", "expected_status", "actual_status", "actual_body",
        "verdict", "verdict_reason",
    }

    def _all_scenarios(self) -> list[dict]:
        secure_run = run_bola_tests(secure=True)
        vuln_run   = run_bola_tests(secure=False)
        return [
            s.to_dict()
            for run in [secure_run, vuln_run]
            for s in run.scenarios
        ]

    def test_all_required_fields_present(self):
        for s in self._all_scenarios():
            missing = self.REQUIRED_SCENARIO_FIELDS - s.keys()
            assert not missing, f"Scenario missing fields: {missing}"

    def test_attacker_is_not_victim(self):
        for s in self._all_scenarios():
            assert s["attacker"] != s["victim"], (
                f"Scenario {s['scenario_id']}: attacker and victim should differ"
            )

    def test_token_display_is_redacted(self):
        for s in self._all_scenarios():
            full_token = s["attacker_token"]
            display    = s["attacker_token_display"]
            assert display != full_token, "Token display should not equal full token"
            assert "…" in display, "Token display should contain ellipsis"

    def test_request_method_is_get(self):
        for s in self._all_scenarios():
            assert s["request_method"] == "GET"

    def test_request_url_contains_record_id(self):
        for s in self._all_scenarios():
            assert str(s["record_id"]) in s["request_url"]

    def test_verdict_values_valid(self):
        for s in self._all_scenarios():
            assert s["verdict"] in {"PASS", "FAIL"}

    def test_to_dict_serialises_all_fields(self):
        run  = run_bola_tests(secure=True)
        data = run.to_dict()
        assert "mode" in data
        assert "total" in data
        assert "passed" in data
        assert "failed" in data
        assert "overall_verdict" in data
        assert "scenarios" in data
        assert isinstance(data["scenarios"], list)

    def test_scenario_ids_are_unique(self):
        for mode in [True, False]:
            run = run_bola_tests(secure=mode)
            ids = [s.scenario_id for s in run.scenarios]
            assert len(ids) == len(set(ids)), "Duplicate scenario IDs"

    def test_four_scenarios_exist(self):
        for mode in [True, False]:
            run = run_bola_tests(secure=mode)
            assert run.total == 4


# ── TestLabApiRoutes ──────────────────────────────────────────────────────────

class TestLabApiRoutes:
    def test_bola_secure_mode_returns_pass(self, api_client):
        resp = api_client.post("/api/lab/bola?secure=true")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_verdict"] == "PASS"
        assert data["mode"] == "secure"

    def test_bola_vulnerable_mode_returns_fail(self, api_client):
        resp = api_client.post("/api/lab/bola?secure=false")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_verdict"] == "FAIL"
        assert data["mode"] == "vulnerable"

    def test_bola_default_is_secure(self, api_client):
        resp = api_client.post("/api/lab/bola")
        assert resp.status_code == 200
        assert resp.json()["mode"] == "secure"

    def test_lab_info_returns_users(self, api_client):
        resp = api_client.get("/api/lab/info")
        assert resp.status_code == 200
        data = resp.json()
        assert "users" in data
        usernames = {u["username"] for u in data["users"]}
        assert "alice" in usernames
        assert "bob" in usernames

    def test_lab_info_returns_records(self, api_client):
        resp = api_client.get("/api/lab/info")
        data = resp.json()
        assert "records" in data
        assert len(data["records"]) == 4

    def test_lab_info_does_not_expose_tokens(self, api_client):
        resp = api_client.get("/api/lab/info")
        body = resp.text
        assert "token-alice-001" not in body
        assert "token-bob-002" not in body

    def test_lab_info_does_not_expose_record_secrets(self, api_client):
        resp = api_client.get("/api/lab/info")
        body = resp.text
        assert "secret-a1" not in body
        assert "secret-b1" not in body

    def test_bola_response_contains_scenarios(self, api_client):
        resp = api_client.post("/api/lab/bola?secure=true")
        data = resp.json()
        assert len(data["scenarios"]) == 4

    def test_bola_vulnerable_scenarios_show_200_status(self, api_client):
        resp = api_client.post("/api/lab/bola?secure=false")
        data = resp.json()
        for s in data["scenarios"]:
            assert s["actual_status"] == 200, (
                f"{s['scenario_id']}: expected 200 in vulnerable mode"
            )

    def test_bola_secure_scenarios_show_403_status(self, api_client):
        resp = api_client.post("/api/lab/bola?secure=true")
        data = resp.json()
        for s in data["scenarios"]:
            assert s["actual_status"] == 403, (
                f"{s['scenario_id']}: expected 403 in secure mode"
            )
