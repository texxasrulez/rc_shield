CREATE TABLE IF NOT EXISTS rcs_cache (
  cache_key VARCHAR(190) PRIMARY KEY,
  cache_scope VARCHAR(32) NOT NULL,
  user_id INTEGER NOT NULL DEFAULT 0,
  mailbox VARCHAR(255) NOT NULL DEFAULT '',
  message_uid INTEGER NOT NULL DEFAULT 0,
  identity_hash VARCHAR(64) NOT NULL DEFAULT '',
  payload TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS rcs_cache_scope_exp_idx ON rcs_cache (cache_scope, expires_at);
CREATE INDEX IF NOT EXISTS rcs_cache_mail_uid_idx ON rcs_cache (mailbox, message_uid);
