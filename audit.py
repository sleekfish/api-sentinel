"""End-to-end audit script for API Sentinel.
Run after the server is up: python audit.py
"""
import urllib.request
import urllib.error
import json
import sys

BASE = "http://127.0.0.1:8765"
PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  PASS  {name}" + (f"  [{detail}]" if detail else ""))
        PASS += 1
    else:
        print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))
        FAIL += 1


def get(path, as_json=True):
    r = urllib.request.urlopen(BASE + path)
    body = r.read()
    data = json.loads(body) if as_json else body
    return r.status, data, r.headers

def post(path):
    req = urllib.request.Request(BASE + path, method="POST")
    r = urllib.request.urlopen(req)
    return r.status, json.loads(r.read())


print("=" * 60)
print("  API Sentinel — End-to-End Audit")
print("=" * 60)

# ── 1. Health ─────────────────────────────────────────────────
print("\n[1] Health endpoint")
status, h, _ = get("/api/health")
check("HTTP 200", status == 200)
check("status == ok", h.get("status") == "ok", h.get("status"))
check("db == ok", h.get("db") == "ok", h.get("db"))
check("version present", bool(h.get("version")), h.get("version"))

# ── 2. Stats ──────────────────────────────────────────────────
print("\n[2] Stats endpoint")
status, s, _ = get("/api/stats")
check("HTTP 200", status == 200)
for key in ("total_scans", "done_scans", "total_findings", "critical", "high", "medium", "low", "info"):
    check(f"field '{key}' present", key in s)

# ── 3. Scans list ─────────────────────────────────────────────
print("\n[3] Scans list")
status, scans, _ = get("/api/scans")
check("HTTP 200", status == 200)
check("returns a list", isinstance(scans, list), f"{len(scans)} items")

# ── 4. Lab info ───────────────────────────────────────────────
print("\n[4] Lab info — no secrets exposed")
status, info, _ = get("/api/lab/info")
check("HTTP 200", status == 200)
check("users list present", isinstance(info.get("users"), list), f"{len(info.get('users', []))} users")
check("records list present", isinstance(info.get("records"), list), f"{len(info.get('records', []))} records")
check("no tokens in users", not any("token" in str(u).lower() for u in info.get("users", [])))
check("no secrets in records", not any("secret" in str(r).lower() for r in info.get("records", [])))

# ── 5. BOLA secure mode ───────────────────────────────────────
print("\n[5] BOLA lab — secure mode")
status, bola = post("/api/lab/bola?secure=true")
check("HTTP 200", status == 200)
check("overall_verdict == PASS", bola.get("overall_verdict") == "PASS", bola.get("overall_verdict"))
check("4 scenarios", len(bola.get("scenarios", [])) == 4, str(len(bola.get("scenarios", []))))
for sc in bola.get("scenarios", []):
    check(f"  scenario {sc['scenario_id']}: actual_status 403",
          sc.get("actual_status") == 403, str(sc.get("actual_status")))

# ── 6. BOLA vulnerable mode ───────────────────────────────────
print("\n[6] BOLA lab — vulnerable mode")
status, bola = post("/api/lab/bola?secure=false")
check("HTTP 200", status == 200)
check("overall_verdict == FAIL", bola.get("overall_verdict") == "FAIL", bola.get("overall_verdict"))
for sc in bola.get("scenarios", []):
    check(f"  scenario {sc['scenario_id']}: actual_status 200",
          sc.get("actual_status") == 200, str(sc.get("actual_status")))

# ── 7. 404 on unknown scan ────────────────────────────────────
print("\n[7] 404 for unknown scan")
try:
    urllib.request.urlopen(BASE + "/api/scans/99999")
    check("/api/scans/99999 returns 404", False, "got 200")
except urllib.error.HTTPError as e:
    check("/api/scans/99999 returns 404", e.code == 404, str(e.code))

# ── 8. Frontend ───────────────────────────────────────────────
print("\n[8] Frontend")
status, body, headers = get("/", as_json=False)
check("GET / returns 200", status == 200)
check("content-type is HTML", "html" in headers.get("content-type", ""), headers.get("content-type"))
check("body contains API Sentinel", b"API Sentinel" in body)

# ── 9. API docs (Swagger UI) ──────────────────────────────────
print("\n[9] API docs")
status, body, headers = get("/api/docs", as_json=False)
check("GET /api/docs returns 200", status == 200)
check("docs page contains swagger", b"swagger" in body.lower())

# ── Summary ───────────────────────────────────────────────────
total = PASS + FAIL
print()
print("=" * 60)
print(f"  Result: {PASS}/{total} checks passed  ({FAIL} failed)")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
