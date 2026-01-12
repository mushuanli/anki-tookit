// src/models/chunk.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct FileChunkRow {
    pub id: String,
    pub user_id: String,
    pub content_hash: String,
    pub chunk_index: i32,
    pub total_chunks: i32,
    pub size: i64,
    pub checksum: String,
    pub storage_path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub id: String,              // content_hash_index
    pub user_id: Uuid,
    pub content_hash: String,
    pub chunk_index: i32,
    pub total_chunks: i32,
    pub size: i64,
    pub checksum: String,
    pub storage_path: String,    // 存储位置
    pub created_at: DateTime<Utc>,
}

impl From<FileChunkRow> for FileChunk {
    fn from(row: FileChunkRow) -> Self {
        Self {
            id: row.id,
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            content_hash: row.content_hash,
            chunk_index: row.chunk_index,
            total_chunks: row.total_chunks,
            size: row.size,
            checksum: row.checksum,
            storage_path: row.storage_path,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkReference {
    pub content_hash: String,
    pub node_id: String,
    pub total_size: i64,
    pub total_chunks: i32,
    pub missing_chunks: Option<Vec<i32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkUploadRequest {
    pub content_hash: String,
    pub index: i32,
    pub total_chunks: i32,
    pub checksum: String,
}
