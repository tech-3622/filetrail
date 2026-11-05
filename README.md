# FileTrail

**Working title.** A file/movement tracking system for Nigerian institutions — starting with university registry flows (files, results, clearance, transcripts).

Status: 🧠 Pre-code. We are still deciding what to build. Nothing here is final until we agree on it together.

---

## Why this exists

In Nigerian universities, a physical file moves: Registry → Department → Exams & Records → HOD → Dean → Registry. Nobody can reliably answer *"where is it right now, and who has been holding it?"*

The cost is real and visible to students, not just institutions:

- Graduates losing admissions and jobs because a file "cannot be found"
- Transcripts taking 2–8 weeks, sometimes months
- Result files stalling silently in an office with no escalation
- No audit trail, so nobody is accountable, so nothing improves

## What we are NOT building

To stay honest, write down the traps:

1. **Not a free pilot.** Free pilots in education almost never convert to paying customers.
2. **Not a student project.** The moment it's "our student built this," there is no budget line for it. We build proof here, revenue elsewhere.
3. **Not a document management system (yet).** We track *movement and accountability*, not storage. Storage is a different, more crowded fight.
4. **Not a replacement for staff.** The system must make the clerk who holds the file look good, not expose them — otherwise they will quietly not use it.

## The one-sentence pitch

> "A dashboard that proves where every file is and who has been holding it — so the Registrar can defend the office when a student says *'I've been waiting three months.'*"

We sell **defensibility and audit trail** to one executive (Registrar / Bursar / VC), not "efficiency" to an institution.

## Who we sell to

**Destination (longer game, needs budget):** universities and polytechnics.

**First money (faster doors):** private universities and private polytechnics — one owner decides; microfinance banks — same physical-file flow, regulated, MD decides alone.

## Revenue model (draft)

| Line | Who pays | Price (draft) | Speed |
|---|---|---|---|
| Per-student transaction (clearance / transcript request tracking) | Student | ₦300 – ₦1,000 | Fast — existing fees already exist |
| Institution licence | Registrar / Bursar | ₦500k – ₦2.5m / year | Slow — committees, budget cycle |
| Setup + data migration | Institution | ₦150k – ₦500k | One-off |

The per-student line funds us while procurement crawls.

## Product scope — v0.1 (proposal, not decided)

The smallest thing that proves value:

1. **Register a file** — file ID, student/staff name, what it is, current office
2. **Check out / check in** — the receiving office signs for it (name + timestamp)
3. **Move to next office** — with an optional "awaiting approval by X"
4. **Where is it?** — search by file ID or student name, one answer, timestamped
5. **Aging view** — files sitting anywhere longer than N days, sorted by worst
6. **Audit log** — every movement, immutable, by who

Deliberately NOT in v0.1: file uploads/scans, SMS notifications, mobile app, integrations with school portals, analytics dashboards.

## Open questions (we answer these before writing code)

1. Public or private university? (Changes the entire sales motion.)
2. Which single flow do we map first — graduation clearance, result submission, or transcript?
3. Who is the champion inside the school — HOD? Faculty officer? Registrar's office?
4. Do we go per-transaction (students pay) or institution licence first?
5. Offline-tolerant? (Registry desktops, patchy power and network — this affects architecture.)
6. Who operates the pilot day to day — us, or a staff member we train?

## Running it

```bash
python3 server/app.py         # http://localhost:8000  (no pip install needed)
python3 tests/test_auth.py    # 39 checks, end to end over real HTTP
```

Seeded login (v0.1 only — remove before go-live): `main@gmail.com` / `111111111`

```
web/index.html      public landing page (EAUED branding, single self-contained file)
web/login.html      sign-in page
web/dashboard.html  the movement ledger, derived from v_aging
server/app.py       standard-library HTTP server + JSON API + session auth
server/security.py  PBKDF2 password hashing, session tokens
db/schema.sql       ledger tables + views
db/auth.sql         users, sessions, login_attempts
db/seed.sql         demo files (the real registry walk)
```

## Roadmap

- [ ] **Phase 0 — Recon.** Sit in a registry. Map one real flow end to end with numbers: steps, days, offices, stall points, missing-file frequency.
- [ ] **Phase 1 — One-pager.** Pilot proposal for a Registrar. One flow, one metric, a price.
- [ ] **Phase 2 — Clickable prototype.** Not production code. Show the flow, get reactions.
- [ ] **Phase 3 — Pilot build.** v0.1 scope above, one flow, one department.
- [ ] **Phase 4 — Reference.** Written permission to use the institution's name + first real payment.
- [ ] **Phase 5 — Sell outward.** Private institutions, then microfinance banks.

## Working agreement (us)

- We plan before we code. No building until the flow is mapped.
- Small steps, always shippable.
- Every decision gets written down here with a date and a reason.
- Nothing gets called "done" until it runs and someone else can use it.

---

## Decision log

_Format: date — decision — reason_

- **2026-11-05** — Project scaffolded locally as `filetrail/`. GitHub sync pending (see `docs/github-setup.md`). — Need a home for notes and code before the first commit.
- **2026-11-05** — Build proof at our own university, sell revenue outside it. — Avoids the "student project, no budget" trap.
- **2026-11-05** — Target institution named: **Emmanuel Alayande University of Education, Oyo (EAUED)**. — It is our own school; access is the moat.
- **2026-11-05** — Store movements, not documents (ADR 001). — A document store solves a pain nobody is paying for, and drags us into free archive scanning.
- **2026-11-05** — Passwords are stored as PBKDF2 hashes, never plain text, even for the demo account. — The moment a registry password sits readable in a DB, the product is a liability.
- **2026-11-05** — Server-side sessions in SQLite behind an HttpOnly cookie, 8-hour expiry. — Logout must really end the session; a stolen cookie should die with it.
- **2026-11-05** — No pricing on the public site yet. — Decision by the owner; sell the pilot, not the package.
