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

import csv
import io
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
from urllib.parse import parse_qs, unquote, urlparse

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


def report_filters(query: dict) -> tuple[int, str | None]:
    """Read ?days= and ?office= defensively — this input comes from a URL."""
    try:
        min_days = max(0, min(365, int((query.get("days") or ["10"])[0])))
    except (TypeError, ValueError):
        min_days = 10
    office = (query.get("office") or [""])[0].strip().upper() or None
    if office and not re.fullmatch(r"[A-Z0-9]{1,10}", office):
        office = None
    return min_days, office


def aging_rows(min_days: int, office: str | None) -> list[dict]:
    conn = db()
    sql = """SELECT w.file_number, w.subject, w.subject_name, w.file_type,
                    w.current_office, w.current_office_code, w.status, w.days_held,
                    w.since, w.signature,
                    CASE WHEN w.days_held >= 30 THEN 'red'
                         WHEN w.days_held >= 10 THEN 'amber'
                         ELSE 'green' END AS flag
               FROM v_where_is w
              WHERE w.status NOT IN ('closed') AND w.days_held >= ?"""
    params: list = [min_days]
    if office:
        sql += " AND w.current_office_code = ?"
        params.append(office)
    sql += " ORDER BY w.days_held DESC, w.file_number"
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def aging_csv(rows: list[dict], min_days: int, office: str | None,
              prepared_by: str) -> bytes:
    """
    A report someone will email or print. Two deliberate choices:

      * utf-8-sig, so Excel on a Nigerian Windows machine shows the en-dashes
        and accents instead of mojibake.
      * three header lines of context (when, by whom, what filter) before the
        data — because a CSV detached from its email is otherwise unreadable.
    """
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    w.writerow(["FileTrail — aging report"])
    w.writerow(["Institution", "Emmanuel Alayande University of Education, Oyo"])
    w.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M")])
    w.writerow(["Prepared by", prepared_by])
    w.writerow(["Filter", f"sitting {min_days}+ days" +
                (f", office {office}" if office else ""), "Files", len(rows)])
    w.writerow([])
    w.writerow(["File number", "Subject", "Name on file", "Type",
                "Current office", "Held (days)", "Since", "Signed at receipt", "Flag"])
    for r in rows:
        w.writerow([
            r["file_number"], r["subject"], r["subject_name"] or "", r["file_type"],
            r["current_office"], r["days_held"], (r["since"] or "")[:10],
            r["signature"] or "", r["flag"],
        ])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")


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

    # ---- file movement ---------------------------------------------------
    def _file_action(self, number: str, action: str) -> None:
        """
        The heart of the system. Every change is a NEW movement row; nothing is
        ever updated or deleted, so the trail cannot be rewritten.

        Two operations:
          move  — the receiving office signs for the file. Closes any open
                  approval on the previous office and opens a new one here.
          close — the file leaves circulation (archived / completed).
        """
        actor = session_user(self._session_token())
        if not actor:
            return self._json(401, {"ok": False, "error": "not signed in"})

        conn = db()
        f = conn.execute("SELECT id, file_number, subject FROM files WHERE file_number = ?",
                         (number,)).fetchone()
        if not f:
            conn.close()
            return self._json(404, {"ok": False, "error": "No file with that number."})

        current = conn.execute(
            """SELECT m.*, o.code AS to_code, o.name AS to_name
                 FROM movements m LEFT JOIN offices o ON o.id = m.to_office_id
                WHERE m.file_id = ? ORDER BY m.id DESC LIMIT 1""", (f["id"],)
        ).fetchone()

        if action == "close":
            if current and current["status"] == "closed":
                conn.close()
                return self._json(400, {"ok": False, "error": "That file is already closed."})
            data = self._read_json()
            with conn:
                conn.execute(
                    """INSERT INTO movements (file_id, from_office_id, to_office_id, status,
                                              note, recorded_by, signature)
                       VALUES (?,?,NULL,'closed',?,?,?)""",
                    (f["id"], current["to_office_id"] if current else None,
                     (data.get("note") or "Closed").strip()[:200],
                     actor["id"], actor["full_name"]),
                )
                conn.execute("UPDATE files SET is_closed = 1 WHERE id = ?", (f["id"],))
            conn.close()
            return self._json(200, {"ok": True, "message": f"{number} closed."})

        # ---- move --------------------------------------------------------
        data = self._read_json()
        try:
            to_office_id = int(data.get("to_office_id"))
        except (TypeError, ValueError):
            conn.close()
            return self._json(400, {"ok": False, "error": "Choose the office receiving the file."})

        office = conn.execute("SELECT id, code, name FROM offices WHERE id = ? AND is_active = 1",
                              (to_office_id,)).fetchone()
        if not office:
            conn.close()
            return self._json(400, {"ok": False, "error": "Unknown office."})

        if current and current["status"] == "closed":
            conn.close()
            return self._json(400, {"ok": False, "error":
                                    "That file is closed. Opening a closed file needs the Registrar."})

        if current and current["to_office_id"] == to_office_id and current["status"] != "returned":
            conn.close()
            return self._json(400, {"ok": False, "error":
                                    f"{number} is already with {office['name']}."})

        note = (data.get("note") or "").strip()[:200] or None
        from_office_id = current["to_office_id"] if current else None

        with conn:
            conn.execute(
                """INSERT INTO movements (file_id, from_office_id, to_office_id, status,
                                          note, recorded_by, signature)
                   VALUES (?,?,?,'received',?,?,?)""",
                (f["id"], from_office_id, to_office_id, note,
                 actor["id"], actor["full_name"]),
            )
        row = conn.execute(
            """SELECT current_office, status, days_held
                 FROM v_where_is WHERE file_number = ?""", (number,)).fetchone()
        conn.close()
        return self._json(200, {
            "ok": True,
            "message": f"{number} signed for by {office['name']} — recorded as {actor['full_name']}.",
            "file": dict(row) if row else None,
        })

    # ---- register a new file --------------------------------------------
    def _register_file(self) -> None:
        actor = session_user(self._session_token())
        if not actor:
            return self._json(401, {"ok": False, "error": "not signed in"})

        data = self._read_json()
        number = (data.get("file_number") or "").strip()
        subject = (data.get("subject") or "").strip()
        ftype = (data.get("file_type") or "general").strip()
        subject_ref = (data.get("subject_ref") or "").strip() or None
        subject_name = (data.get("subject_name") or "").strip() or None
        office_id = data.get("office_id")

        if len(number) < 2:
            return self._json(400, {"ok": False, "error": "Enter the file number as written on the folder."})
        if len(subject) < 3:
            return self._json(400, {"ok": False, "error": "Say briefly what the file is about."})
        if ftype not in ("student", "result", "clearance", "transcript", "staff",
                         "procurement", "general"):
            return self._json(400, {"ok": False, "error": "Unknown file type."})
        try:
            office_id = int(office_id)
        except (TypeError, ValueError):
            return self._json(400, {"ok": False, "error": "Choose the office that starts with the file."})

        conn = db()
        if conn.execute("SELECT 1 FROM files WHERE file_number = ?", (number,)).fetchone():
            conn.close()
            return self._json(409, {"ok": False, "error": f"A file numbered {number} already exists."})
        office = conn.execute("SELECT id, name FROM offices WHERE id = ? AND is_active = 1",
                              (office_id,)).fetchone()
        if not office:
            conn.close()
            return self._json(400, {"ok": False, "error": "Unknown office."})

        with conn:
            cur = conn.execute(
                """INSERT INTO files (file_number, subject, file_type, subject_ref, subject_name)
                   VALUES (?,?,?,?,?)""",
                (number, subject, ftype, subject_ref, subject_name),
            )
            file_id = cur.lastrowid
            conn.execute(
                """INSERT INTO movements (file_id, from_office_id, to_office_id, status,
                                          note, recorded_by, signature)
                   VALUES (?,NULL,?,'received','Registered',?,?)""",
                (file_id, office_id, actor["id"], actor["full_name"]),
            )
        conn.close()
        return self._json(201, {"ok": True,
                                "message": f"{number} registered at {office['name']}.",
                                "file_number": number})

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
        try:
            self._route_get()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:                      # noqa: BLE001
            sys.stderr.write(f"ERROR in GET {self.path}: {exc!r}\n")
            try:
                self._json(500, {"ok": False, "error": "Internal error. Check the server log."})
            except Exception:
                pass

    def _route_get(self) -> None:
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

        if path == "/reports":
            user = session_user(self._session_token())
            if not user:
                return self._redirect("/login")
            return self._static("reports.html")

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
                """SELECT w.file_number, w.subject, w.file_type, w.subject_name,
                          w.current_office, w.current_office_code, w.status,
                          w.days_held, w.signature, w.since,
                          CASE WHEN w.days_held >= 30 THEN 'red'
                               WHEN w.days_held >= 10 THEN 'amber'
                               ELSE 'green' END AS flag,
                          f.id AS file_id
                     FROM v_where_is w
                     JOIN files f ON f.file_number = w.file_number
                    WHERE w.status NOT IN ('closed')
                    ORDER BY w.days_held DESC, w.file_number"""
            ).fetchall()
            conn.close()
            return self._json(200, {"ok": True, "files": [dict(r) for r in rows]})

        # ---- aging report (JSON) -----------------------------------------
        if path == "/api/reports/aging":
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            query = parse_qs(urlparse(self.path).query)
            min_days, office = report_filters(query)
            rows = aging_rows(min_days, office)
            return self._json(200, {"ok": True, "min_days": min_days,
                                    "office": office, "rows": rows})

        # ---- aging report (CSV download) ---------------------------------
        if path == "/api/reports/aging.csv":
            user = session_user(self._session_token())
            if not user:
                # A browser following a download link cannot show JSON, so send
                # a plain 401 body rather than a redirect into the login HTML.
                return self._send(401, b"You must sign in to download this report.\n",
                                  "text/plain; charset=utf-8")
            query = parse_qs(urlparse(self.path).query)
            min_days, office = report_filters(query)
            rows = aging_rows(min_days, office)
            data = aging_csv(rows, min_days, office, prepared_by=user["full_name"])
            stamp = datetime.now().strftime("%Y-%m-%d")
            filename = f"filetrail-aging-{stamp}.csv"
            return self._send(200, data, "text/csv; charset=utf-8", {
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            })

        # ---- full ledger export (CSV) ------------------------------------
        if path == "/api/reports/files.csv":
            user = session_user(self._session_token())
            if not user:
                return self._send(401, b"You must sign in to download this report.\n",
                                  "text/plain; charset=utf-8")
            rows = aging_rows(0, None)
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\r\n")
            w.writerow(["FileTrail — ledger export"])
            w.writerow(["Institution", "Emmanuel Alayande University of Education, Oyo"])
            w.writerow(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M")])
            w.writerow(["Prepared by", user["full_name"], "Files", len(rows)])
            w.writerow([])
            w.writerow(["File number", "Subject", "Name on file", "Type", "Current office",
                        "Held (days)", "Since", "Signed at receipt", "Flag"])
            for r in rows:
                w.writerow([r["file_number"], r["subject"], r["subject_name"] or "",
                            r["file_type"], r["current_office"], r["days_held"],
                            (r["since"] or "")[:10], r["signature"] or "", r["flag"]])
            data = ("\ufeff" + buf.getvalue()).encode("utf-8")
            stamp = datetime.now().strftime("%Y-%m-%d")
            return self._send(200, data, "text/csv; charset=utf-8", {
                "Content-Disposition": f'attachment; filename="filetrail-ledger-{stamp}.csv"',
                "Cache-Control": "no-store",
            })

        # ---- one file, with its full trail -------------------------------
        if (m := re.fullmatch(r"/api/files/([^/]+)", path)):
            user = session_user(self._session_token())
            if not user:
                return self._json(401, {"ok": False, "error": "not signed in"})
            number = unquote(m.group(1))
            conn = db()
            f = conn.execute(
                """SELECT f.id, f.file_number, f.subject, f.file_type, f.subject_ref,
                          f.subject_name, f.opened_on,
                          w.current_office, w.current_office_code, w.status,
                          w.days_held,
                          CASE WHEN w.days_held >= 30 THEN 'red'
                               WHEN w.days_held >= 10 THEN 'amber'
                               ELSE 'green' END AS flag
                     FROM files f JOIN v_where_is w ON w.file_number = f.file_number
                    WHERE f.file_number = ?""", (number,)
            ).fetchone()
            if not f:
                conn.close()
                return self._json(404, {"ok": False, "error": "No file with that number."})
            steps = conn.execute(
                """SELECT step, moved_at, from_code, to_code, status, signature, note,
                          recorded_by_name
                     FROM v_trail WHERE file_number = ? ORDER BY step""", (number,)
            ).fetchall()
            offices = conn.execute(
                "SELECT id, code, name, kind FROM offices WHERE is_active = 1 ORDER BY id"
            ).fetchall()
            conn.close()
            return self._json(200, {"ok": True, "file": dict(f),
                                    "trail": [dict(r) for r in steps],
                                    "offices": [dict(r) for r in offices]})

        if path == "/healthz":
            return self._json(200, {"ok": True, "service": "filetrail"})

        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:
        try:
            self._route_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:                      # noqa: BLE001
            sys.stderr.write(f"ERROR in POST {self.path}: {exc!r}\n")
            try:
                self._json(500, {"ok": False, "error": "Internal error. Check the server log."})
            except Exception:
                pass

    def _route_post(self) -> None:
        path = urlparse(self.path).path
        ip = client_ip(self)

        # /api/users/<id>/<action>
        m = re.fullmatch(r"/api/users/(\d+)/(reset|status|role)", path)
        if m:
            return self._user_action(int(m.group(1)), m.group(2))

        # /api/files/<number>/<action>
        mf = re.fullmatch(r"/api/files/([^/]+)/(move|close)", path)
        if mf:
            return self._file_action(unquote(mf.group(1)), mf.group(2))

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

        if path == "/api/files":
            return self._register_file()

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
