"""
backend/lab/demo_api.py — Authorization Testing Lab: Demo API
=============================================================

Purpose
-------
Provides a self-contained local demo API with two isolated test users and
records they own.  The API can be mounted in two modes:

  secure=False  (VULNERABLE)
      Object-ownership is NOT checked.  Any authenticated user can read any
      record by ID.  This intentionally demonstrates BOLA / IDOR.

  secure=True   (SECURE)
      Every record read validates that the authenticated caller owns the
      requested record.  Cross-user access is rejected with 403 Forbidden.

⚠  The vulnerable mode is deliberately insecure.  It MUST only ever be
   instantiated inside this lab environment and never exposed on the network.
   No real user data is involved — all records are synthetic.

Users and tokens
----------------
  USER_A  token="token-alice-001"   owns records 1, 2
  USER_B  token="token-bob-002"     owns records 3, 4

Records
-------
  id=1  owner=alice  title="Alice's private note"   content="secret-a1"
  id=2  owner=alice  title="Alice's second note"    content="secret-a2"
  id=3  owner=bob    title="Bob's private note"     content="secret-b1"
  id=4  owner=bob    title="Bob's second note"      content="secret-b2"

Endpoints
---------
  GET /demo/me              — return caller identity (requires auth)
  GET /demo/records/{id}    — fetch record by id (ownership checked only in secure mode)
  GET /demo/records         — list only caller's own records (always filtered)
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

# ── Synthetic data — no real user information ─────────────────────────────────

USERS: dict[str, dict] = {
    "token-alice-001": {"user_id": "u1", "username": "alice"},
    "token-bob-002":   {"user_id": "u2", "username": "bob"},
}

RECORDS: dict[int, dict] = {
    1: {"id": 1, "owner_id": "u1", "owner": "alice",
        "title": "Alice's private note",   "content": "secret-a1"},
    2: {"id": 2, "owner_id": "u1", "owner": "alice",
        "title": "Alice's second note",    "content": "secret-a2"},
    3: {"id": 3, "owner_id": "u2", "owner": "bob",
        "title": "Bob's private note",     "content": "secret-b1"},
    4: {"id": 4, "owner_id": "u2", "owner": "bob",
        "title": "Bob's second note",      "content": "secret-b2"},
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _authenticate(authorization: str | None) -> dict:
    """Parse 'Bearer <token>' and return the user dict, or raise 401."""
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. "
                   "Use: Authorization: Bearer <token>",
        )
    parts = authorization.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Malformed Authorization header. Expected: Bearer <token>",
        )
    token = parts[1]
    user = USERS.get(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or unknown token")
    return user


# ── App factory ───────────────────────────────────────────────────────────────

def build_demo_app(secure: bool = True) -> FastAPI:
    """
    Return a FastAPI demo application.

    Parameters
    ----------
    secure : bool
        True  → enforce object-ownership (production-like behaviour)
        False → omit ownership check (intentionally vulnerable for BOLA demo)
    """
    mode_label = "secure" if secure else "VULNERABLE"
    app = FastAPI(
        title=f"API Sentinel — Demo API ({mode_label})",
        description=(
            "Local authorization-testing lab. "
            "Contains synthetic data only. "
            f"Object-ownership enforcement: {'ON' if secure else 'OFF (BOLA demo)'}."
        ),
        docs_url=None,
        redoc_url=None,
    )

    # ── /demo/me ──────────────────────────────────────────────────────────────

    @app.get("/demo/me")
    def whoami(authorization: str | None = Header(default=None)):
        """Return the authenticated caller's identity."""
        user = _authenticate(authorization)
        return {"user_id": user["user_id"], "username": user["username"]}

    # ── /demo/records ─────────────────────────────────────────────────────────

    @app.get("/demo/records")
    def list_records(authorization: str | None = Header(default=None)):
        """List all records owned by the authenticated caller."""
        user = _authenticate(authorization)
        owned = [r for r in RECORDS.values() if r["owner_id"] == user["user_id"]]
        return {"user": user["username"], "records": owned}

    # ── /demo/records/{record_id} ─────────────────────────────────────────────

    @app.get("/demo/records/{record_id}")
    def get_record(
        record_id: int,
        authorization: str | None = Header(default=None),
    ):
        """
        Fetch a single record by ID.

        VULNERABLE mode: returns the record regardless of who owns it.
        SECURE mode:     returns 403 if the caller does not own the record.
        """
        user   = _authenticate(authorization)
        record = RECORDS.get(record_id)

        if record is None:
            raise HTTPException(status_code=404, detail="Record not found")

        if secure and record["owner_id"] != user["user_id"]:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Access denied. Record {record_id} belongs to "
                    f"'{record['owner']}', not '{user['username']}'."
                ),
            )

        return record

    return app
