// src/models/conflict.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::SyncChange;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "conflict_type", rename_all = "lowercase")]
pub enum ConflictType {
    Content,
    Delete,
    Move,
    Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "conflict_resolution", rename_all = "lowercase")]
pub enum ConflictResolution {
    Local,
    Remote,
    Merged,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SyncConflict {
    pub id: Uuid,
    pub user_id: Uuid,
    pub node_id: String,
    pub path: String,
    #[sqlx(json)]
    pub local_change: SyncChange,
    #[sqlx(json)]
    pub remote_change: SyncChange,
    pub conflict_type: ConflictType,
    pub resolved: bool,
    pub resolution: Option<ConflictResolution>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub resolution: ConflictResolution,
    pub merged_content: Option<String>,  // Base64 encoded
}
