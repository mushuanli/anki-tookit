-- migrations/004_create_chunks.sql

CREATE TABLE IF NOT EXISTS file_chunks (
    id VARCHAR(255) PRIMARY KEY,  -- content_hash_index
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content_hash VARCHAR(64) NOT NULL,
    chunk_index INT NOT NULL,
    total_chunks INT NOT NULL,
    size BIGINT NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chunks_user_hash ON file_chunks(user_id, content_hash);
CREATE INDEX idx_chunks_content_hash ON file_chunks(content_hash);
