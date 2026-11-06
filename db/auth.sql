-- ============================================================================
-- FileTrail — accounts and roles
--
-- Model:
--   ONE admin (office of the Registrar) creates accounts for each office.
--   Every other account belongs to an office, and signs for files on its behalf.
--   Nobody can create an account that outranks themselves.
--
-- Password rules:
--   * only ever stored as PBKDF2 hashes
--   * an admin never types someone else's password. The server generates a
--     temporary one and shows it once; must_change_password forces the user to
--     replace it at first sign-in.
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
  id                   INTEGER PRIMARY KEY,
  email                TEXT NOT NULL UNIQUE COLLATE NOCASE,
  full_name            TEXT NOT NULL,
  role                 TEXT NOT NULL DEFAULT 'staff'
                       CHECK (role IN ('admin','registrar','registry','department',
                                       'exams','faculty','bursary','staff')),
  office_id            INTEGER REFERENCES offices(id),
  password_hash        TEXT NOT NULL,      -- pbkdf2_sha256$<iterations>$<salt>$<hash>
  must_change_password INTEGER NOT NULL DEFAULT 0,
  is_active            INTEGER NOT NULL DEFAULT 1,
  last_login_at        TEXT,
  created_at           TEXT NOT NULL DEFAULT (datetime('now')),
  created_by           INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_office ON users(office_id);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,          -- 256-bit random, hex encoded
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Login attempts: feed the rate limiter, and later let the Registrar see
-- that the door is being watched.
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INTEGER PRIMARY KEY,
  email        TEXT NOT NULL,
  ip           TEXT,
  success      INTEGER NOT NULL,
  attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attempts_email ON login_attempts(email, attempted_at);

-- Account management trail: who created, disabled, or reset whom. This is the
-- kind of thing an auditor asks for, and it is cheap to keep.
CREATE TABLE IF NOT EXISTS account_events (
  id          INTEGER PRIMARY KEY,
  actor_id    INTEGER REFERENCES users(id),
  target_id   INTEGER REFERENCES users(id),
  action      TEXT NOT NULL,   -- 'created','disabled','enabled','password_reset','password_changed'
  note        TEXT,
  at          TEXT NOT NULL DEFAULT (datetime('now'))
);
