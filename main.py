"""
API Sentinel — FastAPI application entry point.

Run with:
    uvicorn backend.main:app --reload
or:
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
"""
import os
from contextlib import asynccontextmanager
from pathlib import Path

# Load .env if present (no error if absent)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / ".env", override=False)
except ImportError:
    pass

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.database import (
    init_db, create_scan, finish_scan, fail_scan, save_findings,
    get_scan, get_findings, list_scans, count_findings,
)
from backend.models import ScanRequest, ScanOut, ScanSummary, FindingOut, HealthOut, StatsOut
from backend.scanner import run_scan
from backend.lab.bola_tester import run_bola_tests
from backend.lab.demo_api import USERS, RECORDS

APP_VERSION = "1.0.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database on startup."""
    init_db()
    yield


app = FastAPI(
    title="API Sentinel",
    description="API Security Assessment Tool",
    version=APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthOut, tags=["System"])
def health():
    """Liveness / readiness check."""
    db_status = "ok"
    try:
        from backend.database import get_connection
        with get_connection() as conn:
            conn.execute("SELECT 1")
    except Exception as exc:
        db_status = f"error: {exc}"
    return HealthOut(status="ok", version=APP_VERSION, db=db_status)


# ── Scans ─────────────────────────────────────────────────────────────────────

def _run_scan_task(scan_id: int, target_url: str) -> None:
    try:
        findings = run_scan(target_url)
        save_findings(scan_id, findings)
        finish_scan(scan_id)
    except Exception:
        fail_scan(scan_id)
        raise


@app.post("/api/scans", response_model=dict, status_code=202, tags=["Scans"])
def start_scan(body: ScanRequest, background_tasks: BackgroundTasks):
    """Kick off a new security scan (runs in the background)."""
    scan_id = create_scan(body.target_url)
    background_tasks.add_task(_run_scan_task, scan_id, body.target_url)
    return {"scan_id": scan_id, "status": "running"}


@app.get("/api/scans", response_model=list[ScanSummary], tags=["Scans"])
def get_scans():
    """List recent scans."""
    rows = list_scans()
    return [
        ScanSummary(
            id=row["id"],
            target_url=row["target_url"],
            status=row["status"],
            created_at=row["created_at"],
            finished_at=row["finished_at"],
            finding_count=count_findings(row["id"]),
        )
        for row in rows
    ]


@app.get("/api/scans/{scan_id}", response_model=ScanOut, tags=["Scans"])
def get_scan_detail(scan_id: int):
    """Get a scan and its findings."""
    row = get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    finding_rows = get_findings(scan_id)
    findings = [
        FindingOut(
            id=f["id"],
            severity=f["severity"],
            category=f["category"],
            title=f["title"],
            description=f["description"],
            remediation=f["remediation"],
            affected_url=f["affected_url"] or "",
            evidence=f["evidence"] or "",
            confidence=f["confidence"] or "high",
        )
        for f in finding_rows
    ]
    return ScanOut(
        id=row["id"],
        target_url=row["target_url"],
        status=row["status"],
        created_at=row["created_at"],
        finished_at=row["finished_at"],
        findings=findings,
    )


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats", response_model=StatsOut, tags=["System"])
def get_stats():
    """Aggregate metrics: total scans, findings grouped by severity."""
    from backend.database import get_connection
    with get_connection() as conn:
        total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        done_scans  = conn.execute("SELECT COUNT(*) FROM scans WHERE status='done'").fetchone()[0]
        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        rows = conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM findings GROUP BY severity"
        ).fetchall()
    by_severity = {r["severity"]: r["cnt"] for r in rows}
    return StatsOut(
        total_scans=total_scans,
        done_scans=done_scans,
        total_findings=total_findings,
        critical=by_severity.get("critical", 0),
        high=by_severity.get("high", 0),
        medium=by_severity.get("medium", 0),
        low=by_severity.get("low", 0),
        info=by_severity.get("info", 0),
    )


# ── Lab: BOLA / IDOR authorization tests ─────────────────────────────────────

@app.post("/api/lab/bola", tags=["Lab"])
def run_bola_lab(secure: bool = Query(default=True, description="True=secure mode, False=vulnerable mode")):
    """
    Run the BOLA/IDOR authorization test against the local demo API.

    Set **secure=false** to demonstrate the vulnerability (unauthorized access
    is granted and recorded as evidence). Set **secure=true** to verify the
    secure implementation rejects cross-user access with 403.

    All data is synthetic. No real users or external network calls are made.
    """
    result = run_bola_tests(secure=secure)
    return result.to_dict()


@app.get("/api/lab/info", tags=["Lab"])
def lab_info():
    """Return demo user list and record manifest (no secrets exposed)."""
    users = [
        {"user_id": u["user_id"], "username": u["username"]}
        for u in USERS.values()
    ]
    records = [
        {"id": r["id"], "owner": r["owner"], "title": r["title"]}
        for r in RECORDS.values()
    ]
    return {
        "description": (
            "Local authorization-testing lab. All data is synthetic. "
            "Tokens are shown in tests only — they convey no real access."
        ),
        "users":   users,
        "records": records,
    }


# ── Frontend (static files) ───────────────────────────────────────────────────

_frontend_dir = Path(__file__).parent.parent / "frontend"

if _frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend():
        return FileResponse(str(_frontend_dir / "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    def catch_all(path: str):
        # Prevent catch-all from swallowing /api/* routes
        if path.startswith("api/"):
            raise HTTPException(status_code=404)
        fp = _frontend_dir / path
        if fp.exists() and fp.is_file():
            return FileResponse(str(fp))
        return FileResponse(str(_frontend_dir / "index.html"))
