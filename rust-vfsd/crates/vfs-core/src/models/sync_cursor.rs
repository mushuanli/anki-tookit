// src/models/sync_cursor.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct SyncCursorRow {
    pub user_id: String,
    pub device_id: String,
    pub module_id: String,
    pub last_log_id: i64,
    pub last_sync_time: String,
    pub last_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCursor {
    pub user_id: Uuid,
    pub device_id: String,
    pub module_id: String,
    pub last_log_id: i64,
    pub last_sync_time: DateTime<Utc>,
    pub last_content_hash: Option<String>,
}

impl From<SyncCursorRow> for SyncCursor {
    fn from(row: SyncCursorRow) -> Self {
        Self {
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            device_id: row.device_id,
            module_id: row.module_id,
            last_log_id: row.last_log_id,
            last_sync_time: DateTime::parse_from_rfc3339(&row.last_sync_time)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_content_hash: row.last_content_hash,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateCursorRequest {
    pub module_id: String,
    pub last_log_id: i64,
    pub last_content_hash: Option<String>,
}
