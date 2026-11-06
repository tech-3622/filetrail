#!/usr/bin/env python3
"""
Tests for the part that matters most: registering files and recording movement.

Run:  python3 tests/test_files.py

The guarantees under test:

  1. Moving a file ADDS a movement. Nothing is updated or deleted.
  2. A file can never be "with" the office it is already with.
  3. History cannot be rewritten — the database itself refuses (triggers).
  4. Every movement is signed by a named person, not "the department".
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
            urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)
        try:
            with op.open(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def get(self, path):
        return self._open(urllib.request.Request(self.base + path, method="GET"))

    def post(self, path, payload=None):
        return self._open(urllib.request.Request(
            self.base + path, data=json.dumps(payload or {}).encode(), method="POST",
            headers={"Content-Type": "application/json"}))

    def j(self, method, path, payload=None):
        if method == "GET":
            status, body = self.get(path)
        else:
            status, body = self.post(path, payload)
        try:
            return status, json.loads(body)
        except json.JSONDecodeError:
            return status, {"raw": body}


def test_flow(base: str, db_path: Path) -> None:
    anon = Client(base)
    status, _ = anon.j("GET", "/api/files")
    check("ledger requires a session", status == 401)
    status, _ = anon.j("POST", "/api/files", {"file_number": "X/1", "subject": "sneaky"})
    check("registering requires a session", status == 401)

    clerk = Client(base)
    clerk.j("POST", "/api/login", {"email": "main@gmail.com", "password": "111111111"})

    status, d = clerk.j("GET", "/api/offices")
    by_code = {o["code"]: o["id"] for o in d["offices"]}

    # ---------------- register ----------------------------------------
    status, d = clerk.j("POST", "/api/files", {
        "file_number": "CSC/2025/9001",
        "subject": "PG transcript request",
        "file_type": "transcript",
        "office_id": by_code["REG"],
        "subject_ref": "CSC/15/0987",
        "subject_name": "Test Student",
    })
    check("a file can be registered", status == 201 and d.get("ok") is True, str(d)[:160])

    status, d = clerk.j("POST", "/api/files", {
        "file_number": "CSC/2025/9001", "subject": "duplicate", "office_id": by_code["REG"]})
    check("duplicate file numbers are rejected", status == 409, str(d)[:120])

    status, d = clerk.j("POST", "/api/files", {"file_number": "", "subject": "", "office_id": 1})
    check("bad registration input is rejected", status == 400)
    status, d = clerk.j("POST", "/api/files", {
        "file_number": "X/2", "subject": "no type", "file_type": "nonsense", "office_id": 1})
    check("unknown file type is rejected", status == 400)

    # new file appears in the ledger at its starting office
    status, d = clerk.j("GET", "/api/files")
    mine = [f for f in d["files"] if f["file_number"] == "CSC/2025/9001"]
    check("the new file appears in the ledger", len(mine) == 1, str(len(mine)))
    check("it starts at the office it was registered at",
          mine and mine[0]["current_office"] == "Registry", str(mine))
    check("a fresh file is 0 days old", mine and int(mine[0]["days_held"]) == 0, str(mine))

    # ---------------- move it -----------------------------------------
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/move",
                        {"to_office_id": by_code["CSC"], "note": "for verification"})
    check("a file can be moved to another office", status == 200 and d.get("ok") is True,
          str(d)[:160])

    status, d = clerk.j("GET", "/api/files/CSC%2F2025%2F9001")
    f = d["file"]
    check("the file's current office changed", f["current_office"] == "Dept. of Computer Science",
          str(f.get("current_office")))
    check("the trail now has 2 steps", len(d["trail"]) == 2, str(len(d["trail"])))
    check("the trail names the person who signed",
          d["trail"][1]["signature"] == "Registry Admin", str(d["trail"][1]))
    check("the note was kept", d["trail"][1]["note"] == "for verification")
    check("the movement records both offices",
          d["trail"][1]["from_code"] == "REG" and d["trail"][1]["to_code"] == "CSC",
          str(d["trail"][1]))

    # ---------------- refusals ----------------------------------------
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/move",
                        {"to_office_id": by_code["CSC"]})
    check("cannot move a file to the office already holding it", status == 400, str(d)[:140])

    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/move", {"to_office_id": 99999})
    check("unknown office is rejected", status == 400)
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/move", {})
    check("missing office is rejected", status == 400)
    status, d = clerk.j("POST", "/api/files/NOPE%2F000/move", {"to_office_id": by_code["CSC"]})
    check("moving an unknown file is a 404", status == 404)

    # ---------------- the append-only guarantee -----------------------
    # autocommit: a failed UPDATE must not leave a write transaction open and
    # block the server's own writes (this was a real bug in the first test run)
    conn = sqlite3.connect(db_path, timeout=5)
    conn.isolation_level = None
    before = conn.execute(
        "SELECT COUNT(*), MAX(id) FROM movements").fetchone()
    try:
        conn.execute("UPDATE movements SET to_office_id = 5 WHERE id = 1")
        updated = True
    except sqlite3.IntegrityError:
        updated = False
    check("the database refuses to edit history", updated is False)
    try:
        conn.execute("DELETE FROM movements WHERE id = 1")
        deleted = True
    except sqlite3.IntegrityError:
        deleted = False
    check("the database refuses to delete history", deleted is False)
    after = conn.execute("SELECT COUNT(*), MAX(id) FROM movements").fetchone()
    conn.close()
    check("history is intact after the attempts", before == after, f"{before} vs {after}")

    # ---------------- closing -----------------------------------------
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/close", {"note": "collected"})
    check("a file can be closed", status == 200, str(d)[:140])
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/close", {})
    check("closing twice is refused", status == 400)
    status, d = clerk.j("GET", "/api/files")
    check("closed files drop out of the circulating list",
          not [x for x in d["files"] if x["file_number"] == "CSC/2025/9001"])
    status, d = clerk.j("GET", "/api/files/CSC%2F2025%2F9001")
    check("the closed file keeps its full history", len(d["trail"]) == 3, str(len(d["trail"])))
    check("the last step is the closure", d["trail"][-1]["status"] == "closed")
    status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9001/move",
                        {"to_office_id": by_code["REG"]})
    check("a closed file cannot be moved", status == 400, str(d)[:140])

    # ---------------- a full walk, as a story --------------------------
    clerk.j("POST", "/api/files", {"file_number": "CSC/2025/9002",
                                   "subject": "Clearance — final year",
                                   "file_type": "clearance", "office_id": by_code["REG"],
                                   "subject_name": "Fatima Suleiman"})
    for office, note in [("CSC", "for departmental verification"),
                         ("EXAM", "results check"),
                         ("DEAN", "faculty approval"),
                         ("REG", "final stamping")]:
        status, d = clerk.j("POST", "/api/files/CSC%2F2025%2F9002/move",
                            {"to_office_id": by_code[office], "note": note})
        check(f"walk: moved to {office}", status == 200, str(d)[:120])

    status, d = clerk.j("GET", "/api/files/CSC%2F2025%2F9002")
    codes = [s["to_code"] for s in d["trail"]]
    check("the walk produced the expected route",
          codes == ["REG", "CSC", "EXAM", "DEAN", "REG"], str(codes))
    check("all five steps are signed",
          all(s["signature"] for s in d["trail"]), str([s["signature"] for s in d["trail"]]))
    check("the file is back at Registry", d["file"]["current_office"] == "Registry")

    # ---------------- validation limits -------------------------------
    status, d = clerk.j("POST", "/api/files", {
        "file_number": "X/3", "subject": "long note test", "office_id": by_code["REG"]})
    status, d = clerk.j("POST", "/api/files/X%2F3/move",
                        {"to_office_id": by_code["CSC"], "note": "n" * 500})
    check("an over-long note is truncated, not rejected", status == 200, str(d)[:120])
    status, d = clerk.j("GET", "/api/files/X%2F3")
    check("the stored note is capped",
          len(d["trail"][-1]["note"] or "") <= 200, str(len(d["trail"][-1]["note"] or "")))


def main() -> int:
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
        test_flow(base, db_path)
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
