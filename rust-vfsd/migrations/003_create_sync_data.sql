-- migrations/003_create_sync_data.sql

CREATE TYPE sync_operation AS ENUM (
    'create', 'update', 'delete', 'move', 'copy',
    'tag_add', 'tag_remove', 'metadata_update'
);

CREATE TABLE IF NOT EXISTS sync_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module_id VARCHAR(255) NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    operation sync_operation NOT NULL,
    path TEXT NOT NULL,
    previous_path TEXT,
    content_hash VARCHAR(64),
    size BIGINT,
    metadata JSONB,
    version BIGINT NOT NULL DEFAULT 0,
    vector_clock JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sync_logs_user_module ON sync_logs(user_id, module_id);
CREATE INDEX idx_sync_logs_node_id ON sync_logs(node_id);
CREATE INDEX idx_sync_logs_device_id ON sync_logs(device_id);
CREATE INDEX idx_sync_logs_created_at ON sync_logs(created_at);

CREATE TABLE IF NOT EXISTS sync_cursors (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    module_id VARCHAR(255) NOT NULL,
    last_log_id BIGINT NOT NULL DEFAULT 0,
    last_sync_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_content_hash VARCHAR(64),
    PRIMARY KEY (user_id, device_id, module_id)
);

CREATE TYPE conflict_type AS ENUM ('content', 'delete', 'move', 'metadata');
CREATE TYPE conflict_resolution AS ENUM ('local', 'remote', 'merged', 'skipped');

CREATE TABLE IF NOT EXISTS sync_conflicts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    local_change JSONB NOT NULL,
    remote_change JSONB NOT NULL,
    conflict_type conflict_type NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolution conflict_resolution,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_conflicts_user_id ON sync_conflicts(user_id);
CREATE INDEX idx_conflicts_resolved ON sync_conflicts(resolved);

-- 内容存储
CREATE TABLE IF NOT EXISTS content_store (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_hash VARCHAR(64) NOT NULL,
    data BYTEA NOT NULL,
    size BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, content_hash)
);

CREATE INDEX idx_content_hash ON content_store(content_hash);
