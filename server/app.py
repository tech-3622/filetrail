#!/usr/bin/env python3
"""
FileTrail — auth server (v0.1)

Standard library only. No pip install, no framework, no network dependency.
Run:  python3 server/app.py        then open http://localhost:8000/

Routes
------

  GET  /                  serve web/index.html
  GET  /web/*             static assets (css/img) with path-traversal guard
  GET  /login             login page (redirects to /dashboard if already in)

  POST /api/login         JSON {email, password}  -> sets HttpOnly session cookie
  POST /api/logout        destroys the session server-side, clears cookie
  GET  /api/me            returns the signed-in user, 401 if not
  GET  /api/files         v0.1 placeholder: the movement ledger for the dashboard

  GET  /dashboard         protected. 302 to /login when there is no session.

Security decisions (each one is deliberate)
-------------------------------------------
  * Passwords are PBKDF2 hashes, never stored or logged in plain text.
  * Session cookie is HttpOnly + SameSite=Lax, so JavaScript cannot read it
    and cross-site form posts cannot ride on it. Sessions live in the database,
    so logout genuinely kills them.
  * Login is rate limited per email+IP (5 tries / 15 min) — brute force on a
    registry account is the realistic attack here.
  * The login endpoint answers the same way for "no such user" and "wrong
    password", so it cannot be used to enumerate staff accounts.
  * Login failures are deliberately boring: no hint about which half was wrong.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from security import (  # noqa: E402
    SESSION_TTL_HOURS,
    hash_password,
    new_session_token,
    verify_password,
)

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("FILETRAIL_DB", ROOT / "filetrail.db"))
WEB = ROOT / "web"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

MAX_ATTEMPTS = 5
ATTEMPT_WINDOW_MIN = 15

# The one seeded account (v0.1). Changing this password later is a DB update.
SEED_USER = {
    "email": "main@gmail.com",
    "password": "111111111",
    "full_name": "Registry Admin",
    "role": "registrar",
}


# --------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = db()
    with conn:
        conn.executescript((ROOT / "db" / "schema.sql").read_text())
        conn.executescript((ROOT / "db" / "auth.sql").read_text())
        # demo ledger data, only when the ledger is empty (never overwrites real work)
        if conn.execute("SELECT COUNT(*) AS n FROM files").fetchone()["n"] == 0:
            conn.executescript((ROOT / "db" / "seed.sql").read_text())

        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (SEED_USER["email"],)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (email, full_name, role, password_hash) VALUES (?,?,?,?)",
                (
                    SEED_USER["email"],
                    SEED_USER["full_name"],
                    SEED_USER["role"],
                    hash_password(SEED_USER["password"]),
                ),
            )
    conn.close()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")


def client_ip(handler: "Handler") -> str:
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0] if handler.client_address else "unknown"


def create_session(user_id: int, ip: str, user_agent: str) -> tuple[str, str]:
    token = new_session_token()
    expires = now_utc() + timedelta(hours=SESSION_TTL_HOURS)
    conn = db()
    with conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at, ip, user_agent) VALUES (?,?,?,?,?)",
            (token, user_id, iso(expires), ip, user_agent[:300]),
        )
        conn.execute(
            "UPDATE users SET last_login_at = datetime('now') WHERE id = ?", (user_id,)
        )
    conn.close()
    return token, expires.strftime("%a, %d %b %Y %H:%M:%S GMT")


def session_user(token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    conn = db()
    row = conn.execute(
        """SELECT u.id, u.email, u.full_name, u.role, s.expires_at
             FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND u.is_active = 1
              AND s.expires_at > datetime('now')""",
        (token,),
    ).fetchone()
    if row is None:
        with conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.close()
    return row


def destroy_session(token: str | None) -> None:
    if not token:
        return
    conn = db()
    with conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.close()


def rate_limited(email: str, ip: str) -> bool:
    conn = db()
    row = conn.execute(
        """SELECT COUNT(*) AS n FROM login_attempts
            WHERE success = 0 AND email = ? AND ip = ?
              AND attempted_at > datetime('now', ?)""",
        (email, ip, f"-{ATTEMPT_WINDOW_MIN} minutes"),
    ).fetchone()
    conn.close()
    return (row["n"] if row else 0) >= MAX_ATTEMPTS


def record_attempt(email: str, ip: str, success: bool) -> None:
    conn = db()
    with conn:
        conn.execute(
            "INSERT INTO login_attempts (email, ip, success) VALUES (?,?,?)",
            (email, ip, 1 if success else 0),
        )
        if success:
            conn.execute(
                "DELETE FROM login_attempts WHERE email = ? AND ip = ?", (email, ip)
            )
    conn.close()


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "FileTrail/0.1"

    # ---- plumbing -------------------------------------------------------
    def log_message(self, fmt: str, *args) -> None:  # quieter, no secrets
        sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))

    def _cookies(self) -> SimpleCookie:
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        return c

    def _session_token(self) -> str | None:
        morsel = self._cookies().get("filetrail_session")
        return morsel.value if morsel else None

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra_headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, payload: dict, extra_headers: dict | None = None) -> None:
        body = json.dumps(payload).encode()
        self._send(code, body, "application/json; charset=utf-8", extra_headers)

    def _redirect(self, location: str, extra_headers: dict | None = None) -> None:
        self._send(302, b"", "text/html; charset=utf-8",
                   {"Location": location, **(extra_headers or {})})

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return {}
        if length <= 0 or length > 8192:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _serve_file(self, path: Path, ctype: str) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        self._send(200, data, ctype)

    def _static(self, rel: str, base: Path = WEB) -> None:
        target = (base / rel).resolve()
        if not str(target).startswith(str(base.resolve())) or not target.is_file():
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return
        ext = target.suffix.lower()
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }.get(ext, "application/octet-stream")
        self._serve_file(target, ctype)

    # ---- routes ---------------------------------------------------------
    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path.startswith("/web/"):
            return self._static(path[len("/web/"):])
        if path == "/assets" or path.startswith("/assets/"):
            return self._static(path[len("/assets/"):] if path != "/assets" else "",
                                base=WEB / "assets")

        if path == "/login":
            if session_user(self._session_token()):
                return self._redirect("/dashboard")
            return self._static("login.html")

        if path == "/dashboard":
            user = session_user(self._session_token())
            if not user:
                return self._redirect("/login")
            return self._static("dashboard.html")

        if path == "/api/me":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            return self._json(200, {"ok": True, "user": dict(user)})

        if path == "/api/files":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            conn = db()
            rows = conn.execute(
                "SELECT file_number, subject, current_office, status, days_held "
                "FROM v_aging LIMIT 50"
            ).fetchall()
            conn.close()
            return self._json(200, {"ok": True, "files": [dict(r) for r in rows]})

        if path == "/healthz":
            return self._json(200, {"ok": True, "service": "filetrail"})

        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        ip = client_ip(self)

        if path == "/api/login":
            data = self._read_json()
            email = (data.get("email") or "").strip()
            password = data.get("password") or ""

            if not email or not password:
                return self._json(400, {"ok": False, "error": "Email and password are required."})

            if rate_limited(email, ip):
                return self._json(
                    429,
                    {"ok": False, "error": "Too many attempts. Please wait a few minutes and try again."},
                )

            conn = db()
            row = conn.execute(
                "SELECT id, email, full_name, role, password_hash, is_active "
                "FROM users WHERE email = ?", (email,)
            ).fetchone()
            conn.close()

            # Same message whether the account is missing or the password is wrong.
            if not row or not row["is_active"] or not verify_password(password, row["password_hash"]):
                record_attempt(email, ip, False)
                time.sleep(0.25)  # blunt the timing difference
                return self._json(401, {"ok": False, "error": "Invalid email or password."})

            record_attempt(email, ip, True)
            token, expires = create_session(
                row["id"], ip, self.headers.get("User-Agent", ""))
            cookie = (
                f"filetrail_session={token}; Path=/; HttpOnly; SameSite=Lax; "
                f"Expires={expires}"
                + ("; Secure" if os.environ.get("FILETRAIL_HTTPS") == "1" else "")
            )
            return self._json(
                200,
                {"ok": True, "redirect": "/dashboard",
                 "user": {"email": row["email"], "full_name": row["full_name"], "role": row["role"]}},
                {"Set-Cookie": cookie},
            )

        if path == "/api/logout":
            destroy_session(self._session_token())
            cookie = ("filetrail_session=; Path=/; HttpOnly; SameSite=Lax; "
                      "Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
            return self._json(200, {"ok": True}, {"Set-Cookie": cookie})

        self._json(404, {"ok": False, "error": "not found"})


def main() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"FileTrail running on http://{HOST}:{PORT}  (db: {DB_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
