// crates/vfs-core/src/models/stats.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_users: i64,
    pub active_users: i64,
    pub total_storage_used: i64,
    pub total_sync_logs: i64,
    pub active_connections: i64,
}
