-- ============================================================================
-- FileTrail — authentication tables
--   users    : accounts. Passwords are stored as PBKDF2-HMAC-SHA256 hashes.
--              A plain-text password is NEVER written to this table.
--   sessions : server-side session records behind an HttpOnly cookie.
--              Logging out deletes the row, so a stolen cookie dies with it.
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  full_name     TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'staff'
                CHECK (role IN ('staff','registry','registrar','admin')),
  password_hash TEXT NOT NULL,           -- pbkdf2_sha256$<iterations>$<salt>$<hash>
  is_active     INTEGER NOT NULL DEFAULT 1,
  last_login_at TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,          -- 256-bit random, hex encoded
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Simple audit of login attempts: useful for the rate limiter and, later,
-- for showing the Registrar that the door is being watched.
CREATE TABLE IF NOT EXISTS login_attempts (
  id          INTEGER PRIMARY KEY,
  email       TEXT NOT NULL,
  ip          TEXT,
  success     INTEGER NOT NULL,
  attempted_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attempts_email ON login_attempts(email, attempted_at);
