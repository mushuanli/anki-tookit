// src/models/conflict.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::SyncChange;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConflictType {
    Content,
    Delete,
    Move,
    Metadata,
}

impl std::fmt::Display for ConflictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictType::Content => write!(f, "content"),
            ConflictType::Delete => write!(f, "delete"),
            ConflictType::Move => write!(f, "move"),
            ConflictType::Metadata => write!(f, "metadata"),
        }
    }
}

impl std::str::FromStr for ConflictType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "content" => Ok(ConflictType::Content),
            "delete" => Ok(ConflictType::Delete),
            "move" => Ok(ConflictType::Move),
            "metadata" => Ok(ConflictType::Metadata),
            _ => Err(format!("Unknown conflict type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConflictResolution {
    Local,
    Remote,
    Merged,
    Skipped,
}

impl std::fmt::Display for ConflictResolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictResolution::Local => write!(f, "local"),
            ConflictResolution::Remote => write!(f, "remote"),
            ConflictResolution::Merged => write!(f, "merged"),
            ConflictResolution::Skipped => write!(f, "skipped"),
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct SyncConflictRow {
    pub id: String,
    pub user_id: String,
    pub node_id: String,
    pub path: String,
    pub local_change: String,   // JSON
    pub remote_change: String,  // JSON
    pub conflict_type: String,
    pub resolved: bool,
    pub resolution: Option<String>,
    pub resolved_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub id: Uuid,
    pub user_id: Uuid,
    pub node_id: String,
    pub path: String,
    pub local_change: SyncChange,
    pub remote_change: SyncChange,
    pub conflict_type: ConflictType,
    pub resolved: bool,
    pub resolution: Option<ConflictResolution>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<SyncConflictRow> for SyncConflict {
    fn from(row: SyncConflictRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            node_id: row.node_id,
            path: row.path,
            local_change: serde_json::from_str(&row.local_change).unwrap(),
            remote_change: serde_json::from_str(&row.remote_change).unwrap(),
            conflict_type: row.conflict_type.parse().unwrap_or(ConflictType::Content),
            resolved: row.resolved,
            resolution: row.resolution.and_then(|s| match s.as_str() {
                "local" => Some(ConflictResolution::Local),
                "remote" => Some(ConflictResolution::Remote),
                "merged" => Some(ConflictResolution::Merged),
                "skipped" => Some(ConflictResolution::Skipped),
                _ => None,
            }),
            resolved_at: row.resolved_at
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub resolution: ConflictResolution,
    pub merged_content: Option<String>,  // Base64 encoded
}
