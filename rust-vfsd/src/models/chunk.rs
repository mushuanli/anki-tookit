// src/models/chunk.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
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
