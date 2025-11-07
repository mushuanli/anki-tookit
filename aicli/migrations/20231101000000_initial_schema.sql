-- AICLI Initial Database Schema
-- Version 2.0 - Based on 'updated_at' timestamp for synchronization.
-- This schema is not backward compatible with previous versions.

-- Table for user management and authentication.
-- This table remains unchanged as it serves a separate, stable purpose.
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY NOT NULL,
    public_key      TEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    key_modified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at    DATETIME
);

-- Table for tracking AI chat sessions (tasks).
-- This is the core table, redesigned for timestamp-based synchronization.
CREATE TABLE IF NOT EXISTS chat_logs (
    -- Core Identifier
    uuid            TEXT PRIMARY KEY,

    -- Display and Metadata
    title           TEXT NOT NULL,
    model_used      TEXT NOT NULL,
    client_ip       TEXT NOT NULL,  -- For auditing

    -- State and Sync Management
    status          TEXT NOT NULL,  -- For UI display and filtering ('pending', 'processing', 'completed', 'failed').
    updated_at      DATETIME NOT NULL, -- The single source of truth for synchronization. Updated on ANY meaningful change.
    created_at      DATETIME NOT NULL, -- The immutable creation time of the session.

    -- Error Information
    error_message   TEXT -- Stores the reason for a 'failed' status.
);

-- Table for managing file attachments associated with a chat log.
-- This table also remains structurally the same.
CREATE TABLE IF NOT EXISTS attachments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    log_uuid              TEXT NOT NULL REFERENCES chat_logs(uuid) ON DELETE CASCADE,
    filename              TEXT NOT NULL,
    mime_type             TEXT NOT NULL,
    file_hash             TEXT, -- Optional: for deduplication or integrity checks
    file_path_on_server   TEXT NOT NULL
);

-- --- INDEXES FOR PERFORMANCE ---

-- Index for fast lookups and ordering of tasks by their last update time.
-- This is critical for the client's `list_tasks` polling.
CREATE INDEX IF NOT EXISTS idx_chat_logs_updated_at ON chat_logs (updated_at);

-- Index for efficient filtering of tasks by their status (e.g., for workers to find 'pending' tasks).
CREATE INDEX IF NOT EXISTS idx_chat_logs_status ON chat_logs (status);

-- Index on the foreign key in the attachments table for fast joins and cascading deletes.
CREATE INDEX IF NOT EXISTS idx_attachments_log_uuid ON attachments (log_uuid);