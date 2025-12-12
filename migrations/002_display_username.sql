BEGIN;

ALTER TABLE users ADD COLUMN display_name TEXT;

UPDATE users SET display_name = username WHERE display_name IS NULL;

CREATE INDEX idx_users_display_name ON users(display_name);

ALTER TABLE users ADD COLUMN avatar_url TEXT;
ALTER TABLE users ADD COLUMN bio TEXT;

COMMIT;
