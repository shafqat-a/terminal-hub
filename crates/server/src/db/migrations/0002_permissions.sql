-- M4: per-session ACLs for secondary users. All rows scoped to a (user, peer,
-- session) tuple; peer_id is the literal 'local' for sessions on this instance.
-- Federation (other peer_id values) lands in M5.

CREATE TABLE IF NOT EXISTS permissions (
  user_email   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  peer_id      TEXT NOT NULL,
  session_id   TEXT NOT NULL,
  capabilities INTEGER NOT NULL,              -- bitmask: 1=attach, 2=write, 4=manage
  granted_by   TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  granted_at   INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_permissions_session
  ON permissions(peer_id, session_id);

CREATE INDEX IF NOT EXISTS idx_permissions_user
  ON permissions(user_email);

CREATE TABLE IF NOT EXISTS peer_create_allowed (
  user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  peer_id    TEXT NOT NULL,
  granted_by TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_email, peer_id)
);

-- Extend audit_log with optional peer/session columns so M4 grant/attach events
-- carry their context. Old rows simply have NULL in these new columns.
ALTER TABLE audit_log ADD COLUMN peer_id    TEXT;
ALTER TABLE audit_log ADD COLUMN session_id TEXT;
