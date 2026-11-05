#!/usr/bin/env python3
"""
End-to-end auth tests. Boots the real server on a throwaway database and talks
to it over real HTTP, so we test the same path a browser takes.

Run:  python3 tests/test_auth.py
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

from security import hash_password, verify_password  # noqa: E402

PASS, FAIL = 0, 0
RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        RESULTS.append((True, name, detail))
    else:
        FAIL += 1
        RESULTS.append((False, name, detail))


# ---------------------------------------------------------------------------
# unit tests: hashing
# ---------------------------------------------------------------------------
def test_hashing() -> None:
    h = hash_password("111111111")
    check("hash does not contain the password", "111111111" not in h, h[:48] + "…")
    check("hash is self-describing", h.startswith("pbkdf2_sha256$200000$"))
    check("correct password verifies", verify_password("111111111", h))
    check("wrong password is rejected", not verify_password("111111112", h))
    check("empty password is rejected", not verify_password("", h))
    check("malformed hash is rejected", not verify_password("x", "not-a-hash"))
    check("two hashes of same password differ (salted)", hash_password("a") != hash_password("a"))


# ---------------------------------------------------------------------------
# http helper
# ---------------------------------------------------------------------------
def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Client:
    def __init__(self, base: str) -> None:
        self.base = base
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )

    def get(self, path: str):
        req = urllib.request.Request(self.base + path, method="GET")
        return self._do(req)

    def post(self, path: str, payload: dict | None = None):
        body = json.dumps(payload or {}).encode()
        req = urllib.request.Request(
            self.base + path, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        return self._do(req)

    def _do(self, req):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect
        )
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def cookie_names(self) -> list[str]:
        return [c.name for c in self.jar]


def test_http(base: str, db_path: Path) -> None:
    c = Client(base)

    # --- public pages reachable -------------------------------------------
    status, body, _ = c.get("/")
    check("GET / serves the index page", status == 200 and "FileTrail" in body)
    check("index links to /login", 'href="/login"' in body)

    status, body, _ = c.get("/login")
    check("GET /login serves the login page", status == 200 and "Sign in" in body)
    check("login page shows a demo hint", "main@gmail.com" in body)

    # --- protected redirects ---------------------------------------------
    status, _, headers = c.get("/dashboard")
    check("GET /dashboard without session redirects to /login",
          status == 302 and headers.get("Location") == "/login", f"got {status} {headers.get('Location')}")

    status, body, _ = c.get("/api/me")
    check("GET /api/me without session is 401", status == 401)

    status, body, _ = c.get("/api/files")
    check("GET /api/files without session is 401", status == 401)

    # --- rejection paths --------------------------------------------------
    status, body, _ = c.post("/api/login", {"email": "main@gmail.com", "password": "wrong"})
    check("wrong password is rejected with 401", status == 401, body[:120])
    check("wrong password message is generic", "Invalid email or password" in body)

    status, body, _ = c.post("/api/login", {"email": "nobody@x.com", "password": "111111111"})
    check("unknown email is rejected with 401", status == 401)
    check("unknown email message matches wrong-password message",
          "Invalid email or password" in body, "must not leak which accounts exist")

    status, body, _ = c.post("/api/login", {"email": "", "password": ""})
    check("empty credentials rejected with 400", status == 400)

    # --- the happy path ---------------------------------------------------
    c2 = Client(base)
    status, body, headers = c2.post(
        "/api/login", {"email": "main@gmail.com", "password": "111111111"}
    )
    data = json.loads(body) if body.strip().startswith("{") else {}
    check("correct credentials return 200", status == 200, body[:120])
    check("login returns ok:true and a redirect", data.get("ok") is True and data.get("redirect") == "/dashboard")
    check("session cookie is set", "filetrail_session" in c2.cookie_names(), str(c2.cookie_names()))

    set_cookie = headers.get("Set-Cookie", "")
    check("session cookie is HttpOnly", "HttpOnly" in set_cookie)
    check("session cookie is SameSite=Lax", "SameSite=Lax" in set_cookie)

    # --- session actually works ------------------------------------------
    status, body, _ = c2.get("/api/me")
    me = json.loads(body) if body.strip().startswith("{") else {}
    check("GET /api/me works with session", status == 200 and me.get("ok") is True)
    check("session identifies the right user",
          me.get("user", {}).get("email") == "main@gmail.com", body[:160])
    check("user payload has no password field", "password" not in body.lower())

    status, body, _ = c2.get("/dashboard")
    check("GET /dashboard works with session", status == 200 and "Movement ledger" in body)

    status, body, _ = c2.get("/login")
    check("GET /login redirects to /dashboard when already signed in",
          status == 302 and {"Location": "/dashboard"}.get("Location") == "/dashboard")

    status, body, _ = c2.get("/api/files")
    files = json.loads(body) if body.strip().startswith("{") else {}
    check("GET /api/files returns the ledger", status == 200 and files.get("ok") is True)

    # --- logout kills the session server-side -----------------------------
    status, _, _ = c2.post("/api/logout")
    check("logout returns 200", status == 200)
    status, _, headers = c2.get("/api/me")
    check("session invalid after logout", status == 401)

    # a stolen copy of the old cookie must also fail (server-side session)
    stale = Client(base)
    stale.jar.set_cookie(
        __import__("http.cookiejar", fromlist=["Cookie"]).Cookie(
            0, "filetrail_session", "deadbeef" * 8, None, False,
            "127.0.0.1", False, False, "/", True, False, None, False, None, None, {}
        )
    )
    status, _, _ = stale.get("/api/me")
    check("forged session token is rejected", status == 401)

    # --- rate limiting ----------------------------------------------------
    c3 = Client(base)
    for i in range(5):
        c3.post("/api/login", {"email": "brute@test.com", "password": f"bad{i}"})
    status, body, _ = c3.post("/api/login", {"email": "brute@test.com", "password": "bad5"})
    check("6th failed attempt is rate limited (429)", status == 429, body[:120])
    check("rate-limit message is helpful", "Too many attempts" in body)

    # --- storage: no plain-text password anywhere -------------------------
    conn = sqlite3.connect(db_path)
    stored = conn.execute(
        "SELECT password_hash FROM users WHERE email='main@gmail.com'"
    ).fetchone()[0]
    conn.close()
    check("database does not store the literal password", stored != "111111111")
    check("database stores a pbkdf2 hash", stored.startswith("pbkdf2_sha256$"))
    check("stored hash verifies against the password", verify_password("111111111", stored))

    raw = db_path.read_bytes()
    check("password absent from the raw database file",
          b"111111111" not in raw, "searched the whole .db file for the literal string")


# ---------------------------------------------------------------------------
def main() -> int:
    port = free_port()
    tmpdir = tempfile.mkdtemp()
    db_path = Path(tmpdir) / "test.db"
    env = {**os.environ, "FILETRAIL_DB": str(db_path), "PORT": str(port), "HOST": "127.0.0.1"}

    print("── unit: password hashing ──")
    test_hashing()

    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "server" / "app.py")],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            out = proc.stdout.read() if proc.stdout else ""
            print("server failed to start:\n", out)
            return 1

        print("── http: end to end ──")
        test_http(base, db_path)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    for ok, name, detail in RESULTS:
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if not ok and detail:
            line += f"   → {detail}"
        print(line)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
