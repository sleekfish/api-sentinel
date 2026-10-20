"""
Mock target server for API Sentinel tests.

Usage
-----
Start standalone (for manual testing):
    python -m tests.mock_target

Use programmatically (for unit tests):
    from tests.mock_target import build_app
    from fastapi.testclient import TestClient
    client = TestClient(build_app(config))

Configuration dict keys (all optional, default to the "bad" / insecure values
so that most checks fire unless explicitly overridden):

    cors_origin          str   ACAO header value (default: "*")
    cors_credentials     bool  ACAC header (default: False)
    cors_reflect_origin  bool  Reflect request Origin verbatim (default: False)
    hsts                 str   STS header value (default: absent)
    xcto                 str   X-Content-Type-Options value (default: absent)
    xfo                  str   X-Frame-Options value (default: absent)
    csp                  str   Content-Security-Policy value (default: absent)
    referrer_policy      str   Referrer-Policy value (default: absent)
    permissions_policy   str   Permissions-Policy value (default: absent)
    server_header        str   Server header value (default: absent)
    x_powered_by         str   X-Powered-By header value (default: absent)
    www_authenticate     str   WWW-Authenticate header value (default: absent)
    ratelimit_header     str   RateLimit-Limit header value (default: absent)
    allow_methods        str   Allow header on OPTIONS (default: "GET, POST, OPTIONS")
    leak_errors          bool  Return a fake traceback on unknown paths (default: False)
    set_cookie           str   Full Set-Cookie header value (default: absent)
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# ── Default (insecure) configuration ─────────────────────────────────────────

_DEFAULTS: dict[str, Any] = {
    "cors_origin":         "",        # no CORS headers by default
    "cors_credentials":    False,
    "cors_reflect_origin": False,
    "hsts":                "",
    "xcto":                "",
    "xfo":                 "",
    "csp":                 "",
    "referrer_policy":     "",
    "permissions_policy":  "",
    "server_header":       "",
    "x_powered_by":        "",
    "www_authenticate":    "",
    "ratelimit_header":    "",
    "allow_methods":       "GET, POST, OPTIONS",
    "leak_errors":         False,
    "set_cookie":          "",
}


def build_app(config: dict[str, Any] | None = None) -> FastAPI:
    """Return a configured FastAPI mock-target application."""
    cfg: dict[str, Any] = {**_DEFAULTS, **(config or {})}

    app = FastAPI(title="Sentinel Mock Target", docs_url=None, redoc_url=None)

    def _apply_headers(response: Response, origin: str = "") -> None:
        """Attach configured security (and insecurity) headers."""
        # CORS
        if cfg["cors_reflect_origin"] and origin:
            response.headers["access-control-allow-origin"] = origin
        elif cfg["cors_origin"]:
            response.headers["access-control-allow-origin"] = cfg["cors_origin"]

        if cfg["cors_credentials"]:
            response.headers["access-control-allow-credentials"] = "true"

        # Security headers (only set if configured)
        if cfg["hsts"]:
            response.headers["strict-transport-security"] = cfg["hsts"]
        if cfg["xcto"]:
            response.headers["x-content-type-options"] = cfg["xcto"]
        if cfg["xfo"]:
            response.headers["x-frame-options"] = cfg["xfo"]
        if cfg["csp"]:
            response.headers["content-security-policy"] = cfg["csp"]
        if cfg["referrer_policy"]:
            response.headers["referrer-policy"] = cfg["referrer_policy"]
        if cfg["permissions_policy"]:
            response.headers["permissions-policy"] = cfg["permissions_policy"]

        # Disclosure headers
        if cfg["server_header"]:
            response.headers["server"] = cfg["server_header"]
        if cfg["x_powered_by"]:
            response.headers["x-powered-by"] = cfg["x_powered_by"]

        # Auth
        if cfg["www_authenticate"]:
            response.headers["www-authenticate"] = cfg["www_authenticate"]

        # Rate limit
        if cfg["ratelimit_header"]:
            response.headers["ratelimit-limit"] = cfg["ratelimit_header"]

        # Cookie
        if cfg["set_cookie"]:
            response.headers["set-cookie"] = cfg["set_cookie"]

    @app.get("/")
    async def root(request: Request) -> Response:
        origin = request.headers.get("origin", "")
        resp = JSONResponse({"status": "ok", "service": "mock-target"})
        _apply_headers(resp, origin)
        return resp

    @app.options("/{path:path}")
    async def options_handler(request: Request, path: str) -> Response:
        origin = request.headers.get("origin", "")
        resp = Response(status_code=204)
        resp.headers["allow"] = cfg["allow_methods"]
        _apply_headers(resp, origin)
        return resp

    @app.get("/{path:path}")
    async def catch_all(request: Request, path: str) -> Response:
        origin = request.headers.get("origin", "")
        if cfg["leak_errors"]:
            # Simulate a Python traceback in the error body
            body = (
                "Internal Server Error\n\n"
                "Traceback (most recent call last):\n"
                '  File "/app/server.py", line 42, in handle\n'
                "    result = db.query(sql)\n"
                "ValueError: invalid literal"
            )
            resp = Response(content=body, status_code=500, media_type="text/plain")
        else:
            resp = JSONResponse({"error": "not found"}, status_code=404)
        _apply_headers(resp, origin)
        return resp

    return app


# ── Standalone entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    app = build_app({
        "cors_origin":     "*",
        "server_header":   "MockServer/1.0",
        "x_powered_by":    "Python/3.x",
        "allow_methods":   "GET, POST, PUT, DELETE, TRACE, OPTIONS",
        "leak_errors":     True,
    })
    uvicorn.run(app, host="127.0.0.1", port=9999)
