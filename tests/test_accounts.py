#!/usr/bin/env python3
"""
Tests for office accounts, roles and the hierarchy rules.

Run:  python3 tests/test_accounts.py

The three rules that matter most, and are tested here:

  1. An admin creates one account per PERSON, per office, with a generated
     temporary password that is shown once and must be changed at first sign-in.
  2. Nobody can create or manage an account at or above their own level.
  3. Nobody can disable themselves — that would lock the institution out.
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

from accounts import HIERARCHY, can_create, can_manage, generate_temp_password, rank  # noqa: E402
from security import verify_password  # noqa: E402

PASS = FAIL = 0
RESULTS: list[tuple[bool, str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        RESULTS.append((True, name, detail))
    else:
        FAIL += 1
        RESULTS.append((False, name, detail))


# ---------------------------------------------------------------- unit rules
def test_hierarchy_units() -> None:
    check("admin outranks registrar", rank("admin") > rank("registrar"))
    check("registrar outranks registry clerk", rank("registrar") > rank("registry"))
    check("registry clerk outranks department officer", rank("registry") > rank("department"))
    check("admin can create a registrar", can_create("admin", "registrar"))
    check("registrar cannot create another registrar", not can_create("registrar", "registrar"))
    check("registrar cannot create an admin", not can_create("registrar", "admin"))
    check("department officer cannot create anyone privileged",
          not can_create("department", "registry"))
    check("nobody manages their own rank", not can_manage("registrar", "registrar"))
    check("admin manages registrar", can_manage("admin", "registrar"))
    check("unknown role has rank 0", rank("ghost") == 0)

    pw = generate_temp_password()
    check("temp password is 3 groups of 4", len(pw) == 14 and pw.count("-") == 2, pw)
    check("temp password avoids ambiguous characters",
          not any(c in pw for c in "0O1lI"), pw)
    check("temp passwords are distinct", generate_temp_password() != generate_temp_password())


# ---------------------------------------------------------------- http client
def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Client:
    def __init__(self, base: str) -> None:
        self.base = base
        self.jar = CookieJar()

    def _open(self, req):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect
        )
        try:
            with op.open(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

    def get(self, path):
        return self._open(urllib.request.Request(self.base + path, method="GET"))

    def post(self, path, payload=None):
        return self._open(urllib.request.Request(
            self.base + path, data=json.dumps(payload or {}).encode(), method="POST",
            headers={"Content-Type": "application/json"}))

    def login(self, email, password):
        status, body, _ = self.post("/api/login", {"email": email, "password": password})
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {}


# ---------------------------------------------------------------- http tests
def test_http(base: str, db_path: Path) -> None:
    admin = Client(base)

    # ---- must be signed in ------------------------------------------------
    status, _, _ = admin.get("/api/users")
    check("account list requires a session", status == 401)
    status, _, headers = admin.get("/admin")
    check("/admin page redirects when signed out",
          status == 302 and headers.get("Location") == "/login")

    # ---- the seeded account is an admin ----------------------------------
    status, data = admin.login("main@gmail.com", "111111111")
    check("seeded account signs in", status == 200 and data.get("ok") is True)
    check("seeded account is an admin", data.get("user", {}).get("role") == "admin",
          str(data.get("user")))
    check("seeded account is not forced to change password",
          data.get("must_change_password") is False)

    status, data = admin.login("main@gmail.com", "111111111")
    check("admin lands on the dashboard", data.get("redirect") == "/dashboard")

    status, body, _ = admin.get("/admin")
    check("admin can open the accounts page", status == 200 and "Office accounts" in body)
    status, _, _ = admin.get("/dashboard")
    check("admin can still open the ledger", status == 200)

    # ---- offices are available to pick from ------------------------------
    status, body, _ = admin.get("/api/offices")
    offices = json.loads(body)["offices"]
    check("offices list is served", status == 200 and len(offices) >= 5, str(len(offices)))
    by_code = {o["code"]: o["id"] for o in offices}
    check("expected offices present",
          {"REG", "CSC", "EXAM", "DEAN", "BURS"} <= set(by_code), str(list(by_code)))

    # ---- create an office account ----------------------------------------
    status, body, _ = admin.post("/api/users", {
        "full_name": "Musa Ibrahim",
        "email": "m.ibrahim@eauedoyo.edu.ng",
        "role": "exams",
        "office_id": by_code["EXAM"],
    })
    created = json.loads(body)
    check("admin can create an office account", status == 201 and created.get("ok") is True, body[:160])
    temp = created.get("temp_password", "")
    check("a temporary password is returned once", bool(temp), str(temp))
    check("created account carries the office",
          created.get("user", {}).get("office_name") == "Exams & Records",
          str(created.get("user")))
    check("created account must change password at first sign-in",
          bool(created.get("user", {}).get("must_change_password")))

    # duplicate email rejected
    status, body, _ = admin.post("/api/users", {
        "full_name": "Musa Again", "email": "m.ibrahim@eauedoyo.edu.ng",
        "role": "exams", "office_id": by_code["EXAM"]})
    check("duplicate email is rejected with 409", status == 409, body[:120])

    # bad input rejected
    status, body, _ = admin.post("/api/users", {"full_name": "X", "email": "nope", "role": "exams"})
    check("invalid email rejected", status == 400)
    status, body, _ = admin.post("/api/users", {
        "full_name": "Valid Name", "email": "v@x.com", "role": "wizard"})
    check("unknown role rejected", status == 400)

    # ---- the new user's first sign-in forces a password change -----------
    mib = Client(base)
    status, data = mib.login("m.ibrahim@eauedoyo.edu.ng", temp)
    check("temporary password works", status == 200 and data.get("ok") is True)
    check("first sign-in is redirected to /change-password",
          data.get("redirect") == "/change-password", str(data.get("redirect")))

    status, _, headers = mib.get("/dashboard")
    check("temp user can reach the dashboard page (guarded in the client)", status == 200)

    # weak new passwords rejected
    status, body, _ = mib.post("/api/account/password",
                               {"current_password": temp, "new_password": "123"})
    check("short password rejected", status == 400)
    status, body, _ = mib.post("/api/account/password",
                               {"current_password": temp, "new_password": "12345678901"})
    check("numbers-only password rejected", status == 400)
    status, body, _ = mib.post("/api/account/password",
                               {"current_password": "wrong", "new_password": "Registry 2026!"})
    check("wrong current password rejected", status == 400)

    status, body, _ = mib.post("/api/account/password",
                               {"current_password": temp, "new_password": "Registry 2026!"})
    check("valid new password accepted", status == 200, body[:120])

    status, data = Client(base).login("m.ibrahim@eauedoyo.edu.ng", temp)
    check("temporary password no longer works", status == 401)
    status, data = Client(base).login("m.ibrahim@eauedoyo.edu.ng", "Registry 2026!")
    check("new password works", status == 200 and data.get("ok") is True)
    check("after changing, sign-in goes to the dashboard",
          data.get("redirect") == "/dashboard")

    # ---- privilege: an exams officer cannot manage accounts --------------
    mib2 = Client(base)
    mib2.login("m.ibrahim@eauedoyo.edu.ng", "Registry 2026!")
    status, body, _ = mib2.get("/api/users")
    check("exams officer cannot list accounts", status == 403, body[:120])
    status, _, headers = mib2.get("/admin")
    check("exams officer is redirected away from /admin",
          status == 302 and headers.get("Location") == "/dashboard")
    status, body, _ = mib2.post("/api/users", {
        "full_name": "Sneaky Admin", "email": "sneaky@x.com", "role": "admin"})
    check("exams officer cannot create an account", status == 403)
    status, body, _ = mib2.post("/api/users/1/status", {"enable": False})
    check("exams officer cannot disable the admin", status == 403)

    # ---- privilege: a registrar cannot create an equal or stronger -------
    status, body, _ = admin.post("/api/users", {
        "full_name": "Mrs. Asunmo", "email": "registrar@eauedoyo.edu.ng",
        "role": "registrar", "office_id": by_code["REG"]})
    reg = json.loads(body)
    check("admin can create a registrar", status == 201, body[:160])
    reg_temp = reg.get("temp_password", "")

    regc = Client(base)
    regc.login("registrar@eauedoyo.edu.ng", reg_temp)
    regc.post("/api/account/password",
              {"current_password": reg_temp, "new_password": "Registry Office 26"})

    status, body, _ = regc.post("/api/users", {
        "full_name": "Another Registrar", "email": "reg2@x.com", "role": "registrar"})
    check("registrar cannot create another registrar", status == 403, body[:120])

    status, body, _ = regc.post("/api/users", {
        "full_name": "New Clerk", "email": "clerk@eauedoyo.edu.ng", "role": "registry",
        "office_id": by_code["REG"]})
    check("registrar can create a registry clerk", status == 201, body[:160])
    clerk_temp = json.loads(body).get("temp_password", "")

    admin_id = created["user"]["id"]  # not used for ranking; fetched below
    status, body, _ = regc.get("/api/users")
    users = json.loads(body)["users"]
    admin_row = [u for u in users if u["email"] == "main@gmail.com"][0]
    check("registrar sees the admin row", admin_row["email"] == "main@gmail.com")
    check("registrar is told they cannot manage the admin",
          admin_row["can_manage"] is False)

    status, body, _ = regc.post(f"/api/users/{admin_row['id']}/status", {"enable": False})
    check("registrar cannot disable an admin", status == 403, body[:140])

    # ---- nobody can disable themselves -----------------------------------
    status, body, _ = admin.post("/api/users/1/status", {"enable": False})
    check("admin cannot disable their own account", status == 400, body[:140])

    # ---- reset password kills existing sessions --------------------------
    status, body, _ = admin.post(f"/api/users/{created['user']['id']}/reset")
    check("admin can reset an office account", status == 200, body[:120])
    new_temp = json.loads(body).get("temp_password", "")
    check("reset returns a new temporary password", bool(new_temp))

    status, _, _ = mib2.get("/api/me")
    check("reset ends the target's existing sessions", status == 401)

    # ---- disable / enable ------------------------------------------------
    status, body, _ = admin.post(f"/api/users/{created['user']['id']}/status", {"enable": False})
    check("admin can disable an account", status == 200, body[:120])
    status, _ = Client(base).login("m.ibrahim@eauedoyo.edu.ng", new_temp)
    check("disabled account cannot sign in", status == 401)

    status, body, _ = admin.post(f"/api/users/{created['user']['id']}/status", {"enable": True})
    check("admin can re-enable an account", status == 200)
    status, data = Client(base).login("m.ibrahim@eauedoyo.edu.ng", new_temp)
    check("re-enabled account signs in with the temp password", status == 200)

    # ---- storage guarantees ----------------------------------------------
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT email, password_hash, must_change_password, office_id FROM users").fetchall()
    events = conn.execute("SELECT action FROM account_events").fetchall()
    conn.close()

    check("every account stores a pbkdf2 hash",
          all(r["password_hash"].startswith("pbkdf2_sha256$") for r in rows))
    check("no account stores a plain-text password",
          all(r["password_hash"] not in ("111111111", temp) for r in rows))
    check("the temporary password is not stored anywhere",
          not any(temp and temp in (r["password_hash"] or "") for r in rows))
    check("created accounts are linked to an office",
          [r for r in rows if r["email"] == "m.ibrahim@eauedoyo.edu.ng"][0]["office_id"] is not None)
    actions = [e["action"] for e in events]
    check("account events are logged",
          {"created", "password_reset", "disabled"} <= set(actions), str(sorted(set(actions))))

    raw = db_path.read_bytes()
    check("temporary password absent from the raw database file",
          temp.encode() not in raw)

    conn = sqlite3.connect(db_path)
    stored = conn.execute(
        "SELECT password_hash FROM users WHERE email='registrar@eauedoyo.edu.ng'").fetchone()[0]
    conn.close()
    check("changed password verifies against stored hash",
          verify_password("Registry Office 26", stored))


def main() -> int:
    print("── unit: hierarchy rules ──")
    test_hierarchy_units()

    port = free_port()
    db_path = Path(tempfile.mkdtemp()) / "test.db"
    env = {**os.environ, "FILETRAIL_DB": str(db_path), "PORT": str(port), "HOST": "127.0.0.1"}
    proc = subprocess.Popen([sys.executable, str(ROOT / "server" / "app.py")],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(120):
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            print("server did not start:\n", proc.stdout.read() if proc.stdout else "")
            return 1
        print("── http: accounts and roles ──")
        test_http(base, db_path)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    for ok, name, detail in RESULTS:
        line = f"  [{'PASS' if ok else 'FAIL'}] {name}"
        if not ok and detail:
            line += f"   → {detail}"
        print(line)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
