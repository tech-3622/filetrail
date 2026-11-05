# ADR 001 — Build the movement ledger, not the document store

**Date:** 2026-11-05
**Status:** Proposed (needs your sign-off)
**Decided by:** us two, before any code

---

## The question you asked

> "Let's build a DB that stores our documents first — or what do you think?"

Short answer: **build the database, yes. But store *movements*, not documents.**

## Why "store the documents first" is the wrong first move

**1. It solves the pain we're not being paid for.**
The complaint isn't "the file is not digitised." It's *"nobody knows where the file is, and
nobody is accountable for how long they held it."* A document store answers the first
question and leaves the second untouched. The Registrar we plan to sell to does not lose
sleep over storage. He loses sleep over a student on Twitter saying *"three months and
still counting."*

**2. It is the harder technical build, and the easier one to abandon.**
Storage means: file uploads, chunking, disk space, backups, virus scanning, access
control per document, and a scanning workflow that needs a physical scanner and a member
of staff who will actually use it. That's months, and it depends on hardware you don't
control. A movement ledger is a handful of tables and one query.

**3. It walks straight into the "free pilot" trap.**
The moment we say "we'll digitise your records," the institution hears "great, our student
will scan our archive for free." Two thousand student files, no contract, no money, and
we are now an unpaid scanning service. Document digitisation is the classic way this
project dies.

**4. The pain already exists without it.**
Files already exist on paper. Our system does not need the paper to be digital to know
where it is — it only needs someone to scan a short code or type a file number when the
file changes hands. **Cheap, instant value. No scanning project.**

**5. It's a much more crowded market.**
Document management is a mature, global category — SharePoint, Alfresco, M-Files,
OpenEduCat, and Nigerian vendors already sell it. "Where is file 4,213 and who has held
it for 19 days" is a narrower, sharper, less-contested question.

## What we build instead

A **movement ledger**: an append-only record of every handoff.

```
A file is registered once.
Every time it moves, one row is added.
Nobody ever edits a row.
The current location is not stored — it is derived from the last row.
```

That last line is the important one. If we store `current_office` as a column, it will one
day be wrong, and the whole system becomes untrustworthy. If we *derive* it from the
ledger, it cannot be wrong — it can only be out of date by the gap since the last scan,
which is visible and honest.

## The core schema (draft, 6 tables)

| Table | Purpose |
|---|---|
| `offices` | Departments, registry, dean's office, exams & records |
| `staff` | Who receives and signs for files |
| `files` | The physical item: number, subject, student, type |
| `movements` | **Append-only.** from_office → to_office, at, by, status |
| `holdings` | Open question: "is it still with this office?" — or derive it |
| `audit` | Who viewed/changed what, for the Registrar's defence |

Full workable SQL is in `db/schema.sql`. It runs. You can open it this minute.

## What we deliberately do NOT store in v0.1

- Scanned documents / PDFs
- Full student records
- Grades or results data
- Binaries of any kind

We store **pointers and accountability**, not content.

## The thing I need you to decide

Two options for tracking "is it here right now":

**Option A — derived location (my recommendation)**
`current location = the newest movement row for that file`.
Nothing to keep in sync, impossible to corrupt. Slightly more query work.

**Option B — a `holdings` table**
A row that says "file X is currently at office Y". Faster to query, but it is a cache of
the truth, and caches drift.

I lean hard to **A**, and if we ever need speed, we add B *as a read model* rebuilt from A.
Never the other way round.

## Consequences

- We can demo this in a week of work, not three months.
- It still works when the network is down and someone types a file number by hand.
- It sells as an audit trail, which is what a Registrar can defend with.
- If a client later insists on scanning documents, storage attaches *on top* of this —
  a `documents` table pointing at `files`. Nothing we build now gets thrown away.

**That ordering is the whole point: ledger first, storage later. Same schema either way.**
