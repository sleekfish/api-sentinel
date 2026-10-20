# API Sentinel

A self-hosted **API security assessment** tool built with Python, FastAPI, and SQLite.
Scan any public HTTP/HTTPS API for common misconfigurations, run an interactive
BOLA/IDOR authorization lab, and view all results in a clean web dashboard — no cloud
services, no paid APIs, no hardcoded secrets.

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Running the Application](#running-the-application)
6. [Usage Guide](#usage-guide)
7. [BOLA / IDOR Lab Demo](#bola--idor-lab-demo)
8. [Running Tests](#running-tests)
9. [Project Structure](#project-structure)
10. [Test Results](#test-results)
11. [Known Limitations](#known-limitations)

---

## Features

### Security Scanner (10 checks)
| Check | Severity | Description |
|---|---|---|
| HTTPS enforcement | Critical | Detects plain-HTTP targets |
| TLS certificate | High | Flags invalid or self-signed certificates |
| Security headers | Medium | Checks for `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, `HSTS` (HTTPS only) |
| CORS wildcard | High / Critical | Flags `Access-Control-Allow-Origin: *` (Critical when combined with credentials) |
| CORS reflection | High / Critical | Detects APIs that mirror the `Origin` request header |
| Server disclosure | Low | Reports `Server` or `X-Powered-By` headers leaking software versions |
| Dangerous HTTP methods | High | Flags enabled `TRACE` / `TRACK` (XST); notes `PUT`, `DELETE` if present |
| Cookie flags | Medium | Checks for missing `Secure` and `HttpOnly` flags |
| Rate-limit headers | Medium | Warns when no rate-limit signal headers are present |
| Error leakage | High | Detects stack traces / internal paths in error responses |

Every finding includes: **severity**, **category**, **title**, **description**, **remediation**, **affected URL**, **evidence**, and **confidence** level.

### Dashboard
- Live stat cards: total scans, completed scans, total findings, findings by severity
- Scan history with finding counts
- Per-scan findings table with severity badges and confidence tags
- Search / filter findings by text or severity
- Export results as JSON or printable HTML report

### BOLA / IDOR Authorization Lab
An in-process educational lab that demonstrates **Broken Object-Level Authorization (OWASP API3)**:
- **Secure mode**: cross-user record access is correctly denied (HTTP 403)
- **Vulnerable mode**: access control is absent — attackers read victim records (HTTP 200)
- No real users, no real tokens, no external network calls

### API
- `GET  /api/health` — liveness check
- `GET  /api/stats` — aggregate metrics
- `POST /api/scans` — start a background scan
- `GET  /api/scans` — list recent scans
- `GET  /api/scans/{id}` — scan detail + findings
- `POST /api/lab/bola?secure=true|false` — run BOLA lab
- `GET  /api/lab/info` — lab manifest (no secrets)
- `GET  /api/docs` — interactive Swagger UI
- `GET  /api/redoc` — ReDoc documentation

---

## Requirements

- **Python 3.11 +** (tested on 3.14)
- No external database server — SQLite is included in the Python standard library
- Internet access only required when actually scanning a remote URL

---

## Installation

```bash
# 1. Clone or unzip the project
cd "cybersecurity proj"

# 2. (Optional but recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

`requirements.txt` contains:
```
fastapi>=0.115
uvicorn[standard]>=0.29
httpx>=0.27
python-multipart>=0.0.9
python-dotenv>=1.0
pytest>=8.0
```

---

## Configuration

Copy `.env.example` to `.env` and adjust as needed:

```bash
copy .env.example .env   # Windows
cp  .env.example .env    # macOS / Linux
```

`.env.example`:
```ini
# Host and port the server listens on
APP_HOST=127.0.0.1
APP_PORT=8000

# SQLite database path (use :memory: for ephemeral / test use)
DB_PATH=./sentinel.db
```

All values have safe defaults — the application starts without a `.env` file.
**Never commit a `.env` file containing real secrets.**

---

## Running the Application

```bash
# Default (127.0.0.1:8000, auto-reload)
uvicorn backend.main:app --reload

# Custom host / port
uvicorn backend.main:app --host 0.0.0.0 --port 9000

# Using the environment file
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Then open **http://127.0.0.1:8000** in your browser.

---

## Usage Guide

### Running a Scan

1. Open the app and click the **Scanner** tab.
2. Enter a public HTTPS URL (e.g. `https://httpbin.org`).
3. Tick the *"I am authorized"* checkbox.
4. Click **Start Scan** — the scan runs in the background.
5. Switch to the **Dashboard** tab; findings appear once the scan completes.
6. Click any scan row to expand its findings, or use the export buttons.

**Input rules enforced by the backend:**
- URL must start with `http://` or `https://`
- Private / RFC-1918 IP addresses are blocked (10.x, 172.16–31.x, 192.168.x)
- Maximum URL length: 2 048 characters
- `authorized` flag must be `true`

### Reading Findings

Each finding shows:
- **Severity badge** — Critical / High / Medium / Low / Info
- **Confidence tag** — High / Medium / Low (how certain the check is)
- **Title** and **description** of the issue
- **Remediation** advice
- **Affected URL** and raw **evidence** (request/response snippet)

---

## BOLA / IDOR Lab Demo

The lab ships with two synthetic users and four records:

| User | Owns records |
|------|-------------|
| alice | 1, 2 |
| bob   | 3, 4 |

### Demo: secure mode (correct behaviour)

1. Go to the **BOLA Lab** tab.
2. Make sure *Secure mode* is selected and click **Run Lab**.
3. All four scenarios should show **PASS** — Bob's attempt to read Alice's records (and vice-versa) returns **403 Forbidden**.

### Demo: vulnerable mode (intentional bug)

1. Switch to *Vulnerable mode* and click **Run Lab**.
2. All four scenarios show **FAIL** — unauthorized cross-user access succeeds (**200 OK**) and the victim's record content is visible in the response body.
3. This reproduces **OWASP API Security Top 10 — API3:2023 Broken Object Level Authorization**.

> **Note:** The vulnerable API is never mounted on the network.
> It is an in-process ASGI app used only by the test runner.
> There is no way to reach it from a browser.

---

## Running Tests

```bash
# All 115 tests
python -m pytest tests/ -v

# Scanner tests only (56)
python -m pytest tests/test_scanner.py -v

# BOLA lab tests only (59)
python -m pytest tests/test_bola.py -v
```

### End-to-end audit (requires a running server)

```bash
# Terminal 1 — start the server
uvicorn backend.main:app --host 127.0.0.1 --port 8765

# Terminal 2 — run the audit
python audit.py
```

---

## Project Structure

```
.
├── backend/
│   ├── __init__.py
│   ├── main.py          ← FastAPI app, all routes, lifespan startup
│   ├── database.py      ← SQLite helpers (WAL mode, schema migration)
│   ├── models.py        ← Pydantic request/response schemas
│   ├── scanner.py       ← 10-check security scanner
│   └── lab/
│       ├── __init__.py
│       ├── demo_api.py  ← In-process vulnerable/secure demo API
│       └── bola_tester.py ← BOLA test runner (not network-exposed)
├── frontend/
│   ├── index.html       ← 3-tab SPA (Dashboard / Scanner / BOLA Lab)
│   ├── style.css        ← Design system, responsive, print styles
│   └── app.js           ← All UI logic: stats, history, export
├── tests/
│   ├── __init__.py
│   ├── mock_target.py   ← Configurable in-process mock server
│   ├── test_scanner.py  ← 56 scanner + database tests
│   └── test_bola.py     ← 59 BOLA lab tests
├── audit.py             ← End-to-end live-server audit (39 checks)
├── requirements.txt
├── .env.example
└── README.md
```

---

## Test Results

All results were produced by actually running the commands on Python 3.13 / Windows 10.

### Unit & integration tests

```
platform win32 -- Python 3.13.5, pytest-8.3.4
collected 115 items

tests/test_bola.py    59 passed
tests/test_scanner.py 56 passed

115 passed in 5.97s
```

### End-to-end audit (`python audit.py`)

```
[1] Health endpoint         4/4  PASS
[2] Stats endpoint          9/9  PASS
[3] Scans list              2/2  PASS
[4] Lab info                5/5  PASS
[5] BOLA secure mode        7/7  PASS
[6] BOLA vulnerable mode    6/6  PASS
[7] 404 for unknown scan    1/1  PASS
[8] Frontend                3/3  PASS
[9] API docs                2/2  PASS

Result: 39/39 checks passed  (0 failed)
```

### Feature checklist

| Feature | Implemented | Tested |
|---|:---:|:---:|
| `/api/health` endpoint | ✅ | ✅ (E2E + unit) |
| `/api/stats` endpoint | ✅ | ✅ (E2E) |
| `/api/scans` CRUD | ✅ | ✅ (unit + E2E) |
| HTTPS check | ✅ | ✅ (unit) |
| TLS certificate check | ✅ | ✅ (unit) |
| Security headers (6) | ✅ | ✅ (unit) |
| CORS wildcard + credentials | ✅ | ✅ (unit) |
| CORS reflection | ✅ | ✅ (unit) |
| Server disclosure | ✅ | ✅ (unit) |
| Dangerous HTTP methods | ✅ | ✅ (unit) |
| Rate-limit headers | ✅ | ✅ (unit) |
| Auth header exposure | ✅ | ✅ (unit) |
| Error leakage | ✅ | ✅ (unit) |
| RFC-1918 input block | ✅ | ✅ (unit) |
| BOLA lab secure mode | ✅ | ✅ (unit + E2E) |
| BOLA lab vulnerable mode | ✅ | ✅ (unit + E2E) |
| Frontend dashboard | ✅ | ✅ (E2E — HTML served) |
| JSON export | ✅ | ⚠️ UI only — not automated |
| HTML report export | ✅ | ⚠️ UI only — not automated |
| Print styles | ✅ | ⚠️ Visual — not automated |

---

## Known Limitations

- **Background scans use `BackgroundTasks`** — if the server process restarts mid-scan the scan status stays `running`. Mitigation: the `fail_scan` helper is called on exception; a restart leaves a stale `running` row (cosmetic only — add a startup cleanup query if needed).
- **No authentication on the API** — API Sentinel is designed for local / private-network use. Do not expose it publicly without adding auth (e.g. HTTP Basic via a reverse proxy).
- **Scanner uses `verify=False` for HTTPS requests** — TLS errors are reported as findings via the dedicated TLS check, not by aborting the connection. This is intentional.
- **Rate-limit check is heuristic** — absence of rate-limit headers is flagged as a finding; it does not perform actual rate-limit testing.
- **Cookie flag check** — reads `Set-Cookie` headers from the base URL response only; cookies set by subsequent redirects or subpaths are not checked.
- **Python 3.16 compatibility warning** — third-party libraries (starlette, fastapi) currently call the deprecated `asyncio.iscoroutinefunction()`. This is a library issue unrelated to our code and will be fixed upstream before Python 3.16.
- **No scan scheduling or queueing** — scans run one-at-a-time in FastAPI background tasks. For concurrent heavy use, replace with Celery + Redis.
