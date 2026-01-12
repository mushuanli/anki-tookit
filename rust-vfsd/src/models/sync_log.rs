// src/models/sync_log.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
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

impl std::fmt::Display for SyncOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncOperation::Create => write!(f, "create"),
            SyncOperation::Update => write!(f, "update"),
            SyncOperation::Delete => write!(f, "delete"),
            SyncOperation::Move => write!(f, "move"),
            SyncOperation::Copy => write!(f, "copy"),
            SyncOperation::TagAdd => write!(f, "tagadd"),
            SyncOperation::TagRemove => write!(f, "tagremove"),
            SyncOperation::MetadataUpdate => write!(f, "metadataupdate"),
        }
    }
}

impl std::str::FromStr for SyncOperation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(SyncOperation::Create),
            "update" => Ok(SyncOperation::Update),
            "delete" => Ok(SyncOperation::Delete),
            "move" => Ok(SyncOperation::Move),
            "copy" => Ok(SyncOperation::Copy),
            "tagadd" => Ok(SyncOperation::TagAdd),
            "tagremove" => Ok(SyncOperation::TagRemove),
            "metadataupdate" => Ok(SyncOperation::MetadataUpdate),
            _ => Err(format!("Unknown operation: {}", s)),
        }
    }
}

pub type VectorClock = HashMap<String, i64>;

/// 数据库行结构
#[derive(Debug, Clone, FromRow)]
pub struct SyncLogRow {
    pub id: i64,
    pub user_id: String,
    pub module_id: String,
    pub node_id: String,
    pub device_id: String,
    pub operation: String,
    pub path: String,
    pub previous_path: Option<String>,
    pub content_hash: Option<String>,
    pub size: Option<i64>,
    pub metadata: Option<String>,  // JSON string
    pub version: i64,
    pub vector_clock: String,  // JSON string
    pub created_at: String,
}

/// 业务对象
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub metadata: Option<serde_json::Value>,
    pub version: i64,
    pub vector_clock: VectorClock,
    pub created_at: DateTime<Utc>,
}

impl From<SyncLogRow> for SyncLog {
    fn from(row: SyncLogRow) -> Self {
        Self {
            id: row.id,
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            module_id: row.module_id,
            node_id: row.node_id,
            device_id: row.device_id,
            operation: row.operation.parse().unwrap_or(SyncOperation::Update),
            path: row.path,
            previous_path: row.previous_path,
            content_hash: row.content_hash,
            size: row.size,
            metadata: row.metadata.and_then(|s| serde_json::from_str(&s).ok()),
            version: row.version,
            vector_clock: serde_json::from_str(&row.vector_clock).unwrap_or_default(),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
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
