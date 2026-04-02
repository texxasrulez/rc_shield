CREATE TABLE IF NOT EXISTS rcs_cache (
  cache_key TEXT PRIMARY KEY,
  cache_scope TEXT NOT NULL,
  user_id INTEGER NOT NULL DEFAULT 0,
  mailbox TEXT NOT NULL DEFAULT '',
  message_uid INTEGER NOT NULL DEFAULT 0,
  identity_hash TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS rcs_cache_scope_exp_idx ON rcs_cache (cache_scope, expires_at);
CREATE INDEX IF NOT EXISTS rcs_cache_mail_uid_idx ON rcs_cache (mailbox, message_uid);
