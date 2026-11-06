#!/usr/bin/env python3
"""
Tests for the aging report and the CSV exports.

Run:  python3 tests/test_reports.py

A report is only useful if it is right *and* openable. So we check both:
the numbers, and the bytes that land in Excel.
"""

from __future__ import annotations

import csv
import io
import json
import os
import socket
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
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def get(self, path):
        return self._open(urllib.request.Request(self.base + path, method="GET"))

    def post(self, path, payload=None):
        return self._open(urllib.request.Request(
            self.base + path, data=json.dumps(payload or {}).encode(), method="POST",
            headers={"Content-Type": "application/json"}))

    def jget(self, path):
        status, body, _ = self.get(path)
        return status, json.loads(body)


def test_reports(base: str) -> None:
    anon = Client(base)
    status, body, _ = anon.get("/api/reports/aging")
    check("aging API requires a session", status == 401)
    status, body, _ = anon.get("/api/reports/aging.csv")
    check("aging CSV requires a session", status == 401)
    check("unauthenticated CSV says so in plain text", b"must sign in" in body.lower())
    status, _, headers = anon.get("/reports")
    check("/reports redirects when signed out",
          status == 302 and headers.get("Location") == "/login")

    c = Client(base)
    c.post("/api/login", {"email": "main@gmail.com", "password": "111111111"})

    status, body, _ = c.get("/reports")
    check("signed-in user gets the report page", status == 200 and b"Aging report" in body)

    # seed data: CSC/2025/0414 has been at Exams & Records for 13 days
    status, d = c.jget("/api/reports/aging?days=10")
    check("aging report responds", status == 200 and d.get("ok") is True)
    rows = d["rows"]
    check("the 13-day file is in the 10-day report",
          any(r["file_number"] == "CSC/2025/0414" for r in rows), str([r["file_number"] for r in rows]))
    check("files under the threshold are excluded",
          all(int(r["days_held"]) >= 10 for r in rows),
          str([(r["file_number"], r["days_held"]) for r in rows]))
    check("worst first",
          rows == sorted(rows, key=lambda r: -int(r["days_held"])),
          str([r["days_held"] for r in rows]))
    check("rows carry a flag for the UI", all(r["flag"] in ("red", "amber", "green") for r in rows))

    status, d30 = c.jget("/api/reports/aging?days=30")
    check("a higher threshold returns fewer or equal rows", len(d30["rows"]) <= len(rows),
          f"{len(d30['rows'])} vs {len(rows)}")

    status, d0 = c.jget("/api/reports/aging?days=0")
    check("threshold 0 returns everything in circulation", len(d0["rows"]) >= len(rows))

    # hostile input must not crash or leak
    for probe in ["?days=abc", "?days=-5", "?days=99999", "?office=DROP%20TABLE", "?days=1e9"]:
        status, d = c.jget("/api/reports/aging" + probe)
        check(f"bad input is survived: {probe}", status == 200 and d.get("ok") is True, str(status))
    check("negative days is treated as 0", c.jget("/api/reports/aging?days=-5")[1]["min_days"] == 0)
    check("absurd days is capped", c.jget("/api/reports/aging?days=99999")[1]["min_days"] == 365)
    check("a nonsense office value is ignored",
          c.jget("/api/reports/aging?office=DROP%20TABLE")[1]["office"] is None)

    # office filter
    status, d = c.jget("/api/reports/aging?days=0&office=EXAM")
    check("office filter works",
          d["rows"] and all(r["current_office_code"] == "EXAM" for r in d["rows"]),
          str([r["current_office_code"] for r in d["rows"]]))

    # ---------------- CSV ------------------------------------------------
    status, body, headers = c.get("/api/reports/aging.csv?days=10")
    check("aging CSV downloads", status == 200)
    check("aging CSV has the right content type",
          "text/csv" in headers.get("Content-Type", ""), headers.get("Content-Type", ""))
    check("aging CSV is offered as a file attachment",
          "attachment" in headers.get("Content-Disposition", ""),
          headers.get("Content-Disposition", ""))
    check("aging CSV filename carries the date",
          "filetrail-aging-" in headers.get("Content-Disposition", ""))
    check("CSV starts with a BOM so Excel reads UTF-8",
          body.startswith(b"\xef\xbb\xbf"), repr(body[:6]))

    text = body.decode("utf-8-sig")
    check("CSV uses CRLF line endings", "\r\n" in text)
    parsed = list(csv.reader(io.StringIO(text)))
    check("CSV names the institution",
          any("Emmanuel Alayande University of Education" in cell for row in parsed for cell in row))
    check("CSV records who prepared it",
          any("Prepared by" in cell for row in parsed for cell in row))
    check("CSV records the filter used",
          any("sitting 10+ days" in cell for row in parsed for cell in row))
    header_row = [r for r in parsed if r and r[0] == "File number"]
    check("CSV has a data header row", len(header_row) == 1, str(header_row[:1]))
    data_rows = parsed[parsed.index(header_row[0]) + 1:] if header_row else []
    data_rows = [r for r in data_rows if r and r[0]]
    check("CSV row count matches the API row count",
          len(data_rows) == len(rows), f"{len(data_rows)} vs {len(rows)}")
    check("CSV columns are aligned",
          all(len(r) == 9 for r in data_rows), str([len(r) for r in data_rows]))

    status, body, headers = c.get("/api/reports/files.csv")
    check("full ledger CSV downloads", status == 200)
    check("ledger CSV filename is right",
          "filetrail-ledger-" in headers.get("Content-Disposition", ""))
    full = [r for r in csv.reader(io.StringIO(body.decode("utf-8-sig"))) if r and r[0]]
    check("ledger CSV contains more rows than the filtered report", len(full) > len(data_rows))

    check("CSV is not cached by a shared machine", headers.get("Cache-Control") == "no-store")


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
        test_reports(base)
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
