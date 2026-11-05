-- ============================================================================
-- FileTrail — movement ledger schema (v0.1 draft)
-- SQLite. Runs as-is:  sqlite3 filetrail.db < db/schema.sql
--
-- DESIGN RULE: we track MOVEMENT and ACCOUNTABILITY, not document content.
--   * movements is append-only. Nothing is ever updated or deleted.
--   * a file's current location is DERIVED from its latest movement.
--     We do not store it in a column, because a stored location drifts and
--     then the whole system becomes untrustworthy.
-- ============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Offices: registry, departments, dean's office, exams & records, bursary...
CREATE TABLE IF NOT EXISTS offices (
  id            INTEGER PRIMARY KEY,
  code          TEXT NOT NULL UNIQUE,          -- 'REG', 'CSC', 'EXAM', 'DEAN'
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'office'
                CHECK (kind IN ('registry','department','faculty','exams','bursary','other')),
  is_active     INTEGER NOT NULL DEFAULT 1
);

-- Staff who physically receive and sign for a file.
CREATE TABLE IF NOT EXISTS staff (
  id            INTEGER PRIMARY KEY,
  full_name     TEXT NOT NULL,
  office_id     INTEGER NOT NULL REFERENCES offices(id),
  role          TEXT,                           -- 'registry clerk', 'HOD', 'exams officer'
  is_active     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_staff_office ON staff(office_id);

-- The physical file itself. One row per physical folder.
CREATE TABLE IF NOT EXISTS files (
  id             INTEGER PRIMARY KEY,
  file_number    TEXT NOT NULL UNIQUE,          -- whatever the registry already writes
  subject        TEXT NOT NULL,                 -- 'BSc Computer Science transcript 2019'
  file_type      TEXT NOT NULL DEFAULT 'general'
                 CHECK (file_type IN ('student','result','clearance','transcript',
                                      'staff','procurement','general')),
  -- who/what it relates to; deliberately loose, not a student records system
  subject_ref    TEXT,                          -- matric number, staff id, contract no.
  subject_name   TEXT,
  opened_on      TEXT NOT NULL DEFAULT (date('now')),
  is_closed      INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_files_number  ON files(file_number);
CREATE INDEX IF NOT EXISTS idx_files_subject ON files(subject_ref);

-- ============================================================================
-- movements — APPEND ONLY. The heart of the system.
--
--   * from_office_id NULL  => the file is being registered into the system
--   * to_office_id   NULL  => the file has left the institution / been archived
--   * status 'pending' means: it arrived, but an approval is awaited before it
--     can move again. This is the "wait for approval to go back" case.
-- ============================================================================
CREATE TABLE IF NOT EXISTS movements (
  id             INTEGER PRIMARY KEY,
  file_id        INTEGER NOT NULL REFERENCES files(id),
  from_office_id INTEGER REFERENCES offices(id),
  to_office_id   INTEGER REFERENCES offices(id),
  status         TEXT NOT NULL DEFAULT 'received'
                 CHECK (status IN ('received','pending_approval','approved',
                                   'rejected','returned','closed')),
  note           TEXT,                          -- 'awaiting HOD signature'
  moved_at       TEXT NOT NULL DEFAULT (datetime('now')),
  recorded_by    INTEGER REFERENCES staff(id),  -- who keyed it in (may differ from who signed)
  signature      TEXT,                          -- typed name / staff id of the person who took it
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_mov_file ON movements(file_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_mov_time ON movements(moved_at);

-- Guard the append-only rule. SQLite can't stop UPDATE at the engine level,
-- so we enforce it with triggers: any attempt to rewrite history aborts.
CREATE TRIGGER IF NOT EXISTS movements_no_update
BEFORE UPDATE ON movements
BEGIN
  SELECT RAISE(ABORT, 'movements is append-only: record a new movement instead of editing history');
END;

CREATE TRIGGER IF NOT EXISTS movements_no_delete
BEFORE DELETE ON movements
BEGIN
  SELECT RAISE(ABORT, 'movements is append-only: history cannot be deleted');
END;

-- ============================================================================
-- Views — the questions people actually ask out loud
-- ============================================================================

-- "Where is file 4192 right now, and who took it?"
DROP VIEW IF EXISTS v_where_is;
CREATE VIEW v_where_is AS
SELECT
  f.file_number,
  f.subject,
  f.file_type,
  f.subject_name,
  m.status,
  o.code                                   AS current_office_code,
  o.name                                   AS current_office,
  m.note,
  m.signature,
  m.moved_at                               AS since,
  CAST(julianday('now') - julianday(m.moved_at) AS INTEGER) AS days_held
FROM files f
JOIN movements m
  ON m.id = (SELECT MAX(id) FROM movements WHERE file_id = f.id)
LEFT JOIN offices o ON o.id = COALESCE(m.to_office_id, m.from_office_id);

-- "What is sitting too long, worst first?"  (the aging report that sells this)
DROP VIEW IF EXISTS v_aging;
CREATE VIEW v_aging AS
SELECT
  file_number,
  subject,
  subject_name,
  current_office,
  status,
  days_held,
  CASE
    WHEN days_held >= 30 THEN 'red'
    WHEN days_held >= 10 THEN 'amber'
    ELSE 'green'
  END AS flag
FROM v_where_is
WHERE status NOT IN ('closed','rejected')
ORDER BY days_held DESC;

-- "Who is holding the most?"  (accountability without naming-and-shaming
--  individuals — management uses this, not supervisors)
DROP VIEW IF EXISTS v_load_by_office;
CREATE VIEW v_load_by_office AS
SELECT
  current_office,
  COUNT(*)            AS files_in_hand,
  MAX(days_held)      AS worst_case_days,
  ROUND(AVG(days_held), 1) AS avg_days
FROM v_where_is
WHERE status NOT IN ('closed','rejected')
GROUP BY current_office
ORDER BY files_in_hand DESC;

-- "Show me everything that happened to this file" (the Registrar's defence)
DROP VIEW IF EXISTS v_trail;
CREATE VIEW v_trail AS
SELECT
  f.file_number,
  m.id            AS step,
  m.moved_at,
  fo.code         AS from_code,
  to_.code        AS to_code,
  m.status,
  m.signature,
  m.note,
  s.full_name     AS recorded_by_name
FROM files f
JOIN movements m ON m.file_id = f.id
LEFT JOIN offices fo ON fo.id = m.from_office_id
LEFT JOIN offices to_ ON to_.id = m.to_office_id
LEFT JOIN staff s    ON s.id  = m.recorded_by
ORDER BY f.file_number, m.moved_at;
