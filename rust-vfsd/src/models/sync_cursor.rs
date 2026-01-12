// src/models/sync_cursor.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SyncCursor {
    pub user_id: Uuid,
    pub device_id: String,
    pub module_id: String,
    pub last_log_id: i64,
    pub last_sync_time: DateTime<Utc>,
    pub last_content_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCursorRequest {
    pub module_id: String,
    pub last_log_id: i64,
    pub last_content_hash: Option<String>,
}
