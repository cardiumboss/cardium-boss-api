USE cardium_boss;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS verified           TINYINT(1) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS verification_token VARCHAR(255);
