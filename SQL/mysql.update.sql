ALTER TABLE rcs_cache
  ADD COLUMN identity_hash VARCHAR(64) NOT NULL DEFAULT '' AFTER message_uid;
