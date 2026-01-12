// src/models/sync_log.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "sync_operation", rename_all = "lowercase")]
pub enum SyncOperation {
    Create,
    Update,
    Delete,
    Move,
    Copy,
    TagAdd,
    TagRemove,
    MetadataUpdate,
}

pub type VectorClock = HashMap<String, i64>;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SyncLog {
    pub id: i64,
    pub user_id: Uuid,
    pub module_id: String,
    pub node_id: String,
    pub device_id: String,
    pub operation: SyncOperation,
    pub path: String,
    pub previous_path: Option<String>,
    pub content_hash: Option<String>,
    pub size: Option<i64>,
    #[sqlx(json)]
    pub metadata: Option<serde_json::Value>,
    pub version: i64,
    #[sqlx(json)]
    pub vector_clock: VectorClock,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncChange {
    pub log_id: i64,
    pub node_id: String,
    pub operation: SyncOperation,
    pub timestamp: i64,
    pub path: String,
    pub previous_path: Option<String>,
    pub content_hash: Option<String>,
    pub size: Option<i64>,
    pub metadata: Option<serde_json::Value>,
    pub version: i64,
    pub base_version: Option<i64>,
    pub vector_clock: VectorClock,
}

impl From<SyncLog> for SyncChange {
    fn from(log: SyncLog) -> Self {
        Self {
            log_id: log.id,
            node_id: log.node_id,
            operation: log.operation,
            timestamp: log.created_at.timestamp_millis(),
            path: log.path,
            previous_path: log.previous_path,
            content_hash: log.content_hash,
            size: log.size,
            metadata: log.metadata,
            version: log.version,
            base_version: None,
            vector_clock: log.vector_clock,
        }
    }
}
