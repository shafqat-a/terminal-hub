-- Single-user M3 schema. Multi-user permissions/peers come in M4.

CREATE TABLE IF NOT EXISTS users (
  email          TEXT PRIMARY KEY,
  pubkey_openssh TEXT NOT NULL,                            -- raw ssh-ed25519 / ssh-rsa pubkey line
  passkey_creds  BLOB,                                     -- JSON-serialized Vec<Passkey>, null until first passkey registered
  role           TEXT NOT NULL CHECK(role IN ('primary','secondary')),
  enrolled_at    INTEGER NOT NULL                          -- unix seconds
);

CREATE TABLE IF NOT EXISTS bootstrap_tokens (
  token_hash   BLOB PRIMARY KEY,                           -- argon2 hash of the raw token (string)
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  consumed_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_user ON bootstrap_tokens(user_email);
CREATE INDEX IF NOT EXISTS idx_bootstrap_tokens_exp  ON bootstrap_tokens(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  cookie_hash  BLOB PRIMARY KEY,                           -- sha-256 of the cookie value
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  issued_at    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_email);
CREATE INDEX IF NOT EXISTS idx_sessions_exp  ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          INTEGER NOT NULL,
  user_email  TEXT,
  action      TEXT NOT NULL,
  details     TEXT                                         -- JSON blob
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
