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
import re
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
def password_problem(pw: str) -> str | None:
    """Return a human explanation, or None when the password is acceptable."""
    if len(pw) < 8:
        return "Use at least 8 characters."
    if pw.isdigit():
        return "Use something other than numbers only — a short phrase is stronger and easier to remember."
    if pw.lower() in {"password", "12345678", "11111111", "qwertyui", "admin123"}:
        return "That password is too common. Choose another."
    return None


from accounts import (  # noqa: E402
    VALID_ROLES,
    can_create,
    can_manage,
    generate_temp_password,
    rank,
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
    "role": "admin",
    "must_change_password": 0,   # demo account; real accounts are forced
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
                """INSERT INTO users (email, full_name, role, password_hash,
                                      must_change_password, office_id)
                   VALUES (?,?,?,?,?, (SELECT id FROM offices WHERE code='REG'))""",
                (
                    SEED_USER["email"],
                    SEED_USER["full_name"],
                    SEED_USER["role"],
                    hash_password(SEED_USER["password"]),
                    SEED_USER.get("must_change_password", 1),
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
        """SELECT u.id, u.email, u.full_name, u.role, u.office_id,
                  u.must_change_password, u.last_login_at, s.expires_at,
                  o.name AS office_name, o.code AS office_code
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             LEFT JOIN offices o ON o.id = u.office_id
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


def user_payload(row) -> dict:
    """The only shape of user data that ever leaves the server."""
    return {
        "id": row["id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "role": row["role"],
        "office": row["office_name"] if "office_name" in row.keys() else None,
        "office_code": row["office_code"] if "office_code" in row.keys() else None,
        "must_change_password": bool(row["must_change_password"])
        if "must_change_password" in row.keys() else False,
    }


def log_event(conn, actor_id, target_id, action, note=None) -> None:
    conn.execute(
        "INSERT INTO account_events (actor_id, target_id, action, note) VALUES (?,?,?,?)",
        (actor_id, target_id, action, note),
    )


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

    # ---- account helpers ------------------------------------------------
    def _user_hash(self, user_id: int) -> str:
        conn = db()
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return row["password_hash"] if row else ""

    def _user_action(self, target_id: int, action: str) -> None:
        actor = session_user(self._session_token())
        if not actor:
            return self._json(401, {"ok": False, "error": "not signed in"})
        if rank(actor["role"]) < 4:
            return self._json(403, {"ok": False, "error":
                                    "Only the Registrar's office can manage accounts."})

        conn = db()
        target = conn.execute(
            "SELECT id, email, full_name, role, is_active FROM users WHERE id = ?", (target_id,)
        ).fetchone()
        if not target:
            conn.close()
            return self._json(404, {"ok": False, "error": "No such account."})

        # locking yourself out is the mistake we refuse first, because the
        # error message should explain the real reason, not a side effect of it
        if target["id"] == actor["id"]:
            conn.close()
            return self._json(400, {"ok": False, "error":
                                    "You cannot do that to your own account — "
                                    "another admin must make this change."})

        # cannot act on someone at or above your own level
        if not can_manage(actor["role"], target["role"]):
            conn.close()
            return self._json(403, {"ok": False, "error":
                                    "You cannot manage an account at or above your own level."})

        if action == "reset":
            temp = generate_temp_password()
            with conn:
                conn.execute(
                    "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                    (hash_password(temp), target_id),
                )
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
                log_event(conn, actor["id"], target_id, "password_reset")
            conn.close()
            return self._json(200, {
                "ok": True,
                "temp_password": temp,
                "message": "Password reset. Their existing sessions were ended. "
                           "Give this temporary password to them directly — it will not be shown again.",
            })

        if action == "status":
            data = self._read_json()
            enable = bool(data.get("enable"))
            with conn:
                conn.execute("UPDATE users SET is_active = ? WHERE id = ?",
                             (1 if enable else 0, target_id))
                if not enable:
                    conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
                log_event(conn, actor["id"], target_id,
                          "enabled" if enable else "disabled")
            conn.close()
            return self._json(200, {"ok": True,
                                    "message": ("Account enabled." if enable
                                                else "Account disabled and signed out.")})

        if action == "role":
            data = self._read_json()
            new_role = (data.get("role") or "").strip()
            if new_role not in VALID_ROLES:
                conn.close()
                return self._json(400, {"ok": False, "error": "Unknown role."})
            if not can_create(actor["role"], new_role):
                conn.close()
                return self._json(403, {"ok": False, "error":
                                        f"You cannot assign the {new_role} role."})
            with conn:
                conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, target_id))
                log_event(conn, actor["id"], target_id, "role_changed", f"-> {new_role}")
            conn.close()
            return self._json(200, {"ok": True, "message": "Role updated."})

        conn.close()
        return self._json(400, {"ok": False, "error": "Unknown action."})

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

        if path == "/change-password":
            user = session_user(self._session_token())
            if not user:
                return self._redirect("/login")
            return self._static("change-password.html")

        if path == "/admin":
            user = session_user(self._session_token())
            if not user:
                return self._redirect("/login")
            if rank(user["role"]) < 3:
                return self._redirect("/dashboard")
            return self._static("admin.html")

        if path == "/dashboard":
            user = session_user(self._session_token())
            if not user:
                return self._redirect("/login")
            return self._static("dashboard.html")

        if path == "/api/me":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            return self._json(200, {"ok": True, "user": user_payload(user)})

        if path == "/api/offices":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            conn = db()
            rows = conn.execute(
                "SELECT id, code, name, kind FROM offices WHERE is_active = 1 ORDER BY id"
            ).fetchall()
            conn.close()
            return self._json(200, {"ok": True, "offices": [dict(r) for r in rows]})

        if path == "/api/users":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            if rank(user["role"]) < 3:
                return self._json(403, {"ok": False, "error":
                                        "Only Registry and above can view accounts."})
            conn = db()
            rows = conn.execute(
                """SELECT u.id, u.email, u.full_name, u.role, u.is_active,
                          u.must_change_password, u.last_login_at, u.created_at,
                          o.name AS office_name
                     FROM users u LEFT JOIN offices o ON o.id = u.office_id
                    ORDER BY u.is_active DESC, u.full_name COLLATE NOCASE"""
            ).fetchall()
            conn.close()
            accounts = [dict(r) for r in rows]
            for a in accounts:
                a["can_manage"] = can_manage(user["role"], a["role"])
            return self._json(200, {
                "ok": True,
                "users": accounts,
                "roles": list(VALID_ROLES),
                "you": {"role": user["role"], "rank": rank(user["role"])},
            })

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

        # /api/users/<id>/<action>
        m = re.fullmatch(r"/api/users/(\d+)/(reset|status|role)", path)
        if m:
            return self._user_action(int(m.group(1)), m.group(2))

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
                "SELECT id, email, full_name, role, password_hash, is_active, "
                "must_change_password FROM users WHERE email = ?", (email,)
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
                {"ok": True,
                 "redirect": "/change-password" if row["must_change_password"] else "/dashboard",
                 "must_change_password": bool(row["must_change_password"]),
                 "user": {"email": row["email"], "full_name": row["full_name"],
                          "role": row["role"]}},
                {"Set-Cookie": cookie},
            )

        # ---------------- change own password (also used by forced change) ----
        if path == "/api/account/password":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            data = self._read_json()
            current = data.get("current_password") or ""
            new = data.get("new_password") or ""

            if not verify_password(current, self._user_hash(user["id"])):
                return self._json(400, {"ok": False, "error": "Your current password is not correct."})
            problem = password_problem(new)
            if problem:
                return self._json(400, {"ok": False, "error": problem})
            if verify_password(new, self._user_hash(user["id"])):
                return self._json(400, {"ok": False, "error": "The new password must be different."})

            conn = db()
            with conn:
                conn.execute(
                    "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                    (hash_password(new), user["id"]),
                )
                log_event(conn, user["id"], user["id"], "password_changed")
            conn.close()
            return self._json(200, {"ok": True, "message": "Password updated."})

        # ---------------- admin: create an account ---------------------------
        if path == "/api/users":
            actor = session_user(self._session_token())
            if not actor:
                return self._json(401, {"ok": False, "error": "not signed in"})
            if rank(actor["role"]) < 4:
                return self._json(403, {"ok": False, "error":
                                        "Only the Registrar's office can create accounts."})

            data = self._read_json()
            email = (data.get("email") or "").strip().lower()
            full_name = (data.get("full_name") or "").strip()
            role = (data.get("role") or "staff").strip()
            office_id = data.get("office_id")

            if "@" not in email or len(email) < 6:
                return self._json(400, {"ok": False, "error": "Enter a valid email address."})
            if len(full_name) < 3:
                return self._json(400, {"ok": False, "error": "Enter the person's full name."})
            if role not in VALID_ROLES:
                return self._json(400, {"ok": False, "error": "Unknown role."})
            if not can_create(actor["role"], role):
                return self._json(403, {"ok": False, "error":
                                        f"A {actor['role']} cannot create a {role} account."})

            conn = db()
            exists = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if exists:
                conn.close()
                return self._json(409, {"ok": False, "error": "That email already has an account."})
            if office_id is not None:
                ok = conn.execute("SELECT id FROM offices WHERE id = ?", (office_id,)).fetchone()
                if not ok:
                    conn.close()
                    return self._json(400, {"ok": False, "error": "Unknown office."})

            temp = generate_temp_password()
            with conn:
                cur = conn.execute(
                    """INSERT INTO users (email, full_name, role, office_id, password_hash,
                                          must_change_password, created_by)
                       VALUES (?,?,?,?,?,1,?)""",
                    (email, full_name, role, office_id, hash_password(temp), actor["id"]),
                )
                new_id = cur.lastrowid
                log_event(conn, actor["id"], new_id, "created", f"role={role}")
            row = conn.execute(
                """SELECT u.id, u.email, u.full_name, u.role, u.is_active,
                          u.must_change_password, u.last_login_at, o.name AS office_name
                     FROM users u LEFT JOIN offices o ON o.id = u.office_id
                    WHERE u.id = ?""", (new_id,)
            ).fetchone()
            conn.close()
            # The temporary password is returned exactly once, in this response,
            # and is never recoverable afterwards.
            return self._json(201, {
                "ok": True,
                "user": dict(row),
                "temp_password": temp,
                "message": "Account created. Give this temporary password to the person "
                           "directly — it will not be shown again.",
            })

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
