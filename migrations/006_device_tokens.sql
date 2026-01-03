-- Device tokens for APNs push notifications
-- Supports Phase 1 (silent push) and Phase 2 (visible push with filters)

CREATE TABLE IF NOT EXISTS device_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- APNs device token (hexadecimal string, typically 64 characters)
    device_token TEXT NOT NULL,

    -- Device name/identifier for user to identify their devices
    device_name TEXT,

    -- Push notification preferences (Phase 2)
    -- 'silent' = Silent push only (Phase 1)
    -- 'visible_all' = All messages
    -- 'visible_dm' = Direct messages only
    -- 'visible_mentions' = Mentions only
    -- 'visible_contacts' = From contacts only
    notification_filter TEXT NOT NULL DEFAULT 'silent',

    -- Whether push notifications are enabled for this device
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure one user can't register same token multiple times
    UNIQUE(user_id, device_token)
);

-- Index for faster lookups by user_id
CREATE INDEX IF NOT EXISTS idx_device_tokens_user_id ON device_tokens(user_id);

-- Index for faster lookups by device_token
CREATE INDEX IF NOT EXISTS idx_device_tokens_token ON device_tokens(device_token);

-- Index for finding enabled devices
CREATE INDEX IF NOT EXISTS idx_device_tokens_enabled ON device_tokens(user_id, enabled) WHERE enabled = TRUE;

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_device_tokens_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER device_tokens_updated_at
    BEFORE UPDATE ON device_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_device_tokens_updated_at();
