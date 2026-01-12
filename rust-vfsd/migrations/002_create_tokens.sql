-- migrations/002_create_tokens.sql

CREATE TYPE permission_level AS ENUM ('readonly', 'readwrite', 'admin');

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    permission_level permission_level NOT NULL DEFAULT 'readwrite',
    path_permissions JSONB,
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_user_id ON api_tokens(user_id);
CREATE INDEX idx_tokens_hash ON api_tokens(token_hash);
CREATE INDEX idx_tokens_device_id ON api_tokens(device_id);
