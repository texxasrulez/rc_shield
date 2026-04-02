CREATE TABLE IF NOT EXISTS rcs_cache (
  cache_key VARCHAR(190) NOT NULL,
  cache_scope VARCHAR(32) NOT NULL,
  user_id INT NOT NULL DEFAULT 0,
  mailbox VARCHAR(255) NOT NULL DEFAULT '',
  message_uid INT NOT NULL DEFAULT 0,
  identity_hash VARCHAR(64) NOT NULL DEFAULT '',
  payload MEDIUMTEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (cache_key),
  KEY rcs_cache_scope_exp_idx (cache_scope, expires_at),
  KEY rcs_cache_mail_uid_idx (mailbox(100), message_uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
