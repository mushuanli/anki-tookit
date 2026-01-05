// src/types.rs
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use dashmap::DashMap;
use std::time::Instant;

pub const JWT_SECRET: &[u8] = b"your_super_secret_jwt_key_change_me_in_production"; // !! CHANGE THIS IN PRODUCTION !!
pub const DEFAULT_QUOTA_BYTES: i64 = 1024 * 1024 * 1024; // 1 GB default quota
pub const MAX_UPLOAD_MB: usize = 100; // Max upload size per request

pub type RequestUserId = Option<i64>;

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Sqlite>,
    // IP -> (Fail Count, Last Fail Time)
    pub login_attempts: Arc<DashMap<std::net::IpAddr, (u32, Instant)>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,      // Subject (usually username)
    pub uid: i64,         // User ID
    pub ver: i32,         // Token version (for session invalidation)
    pub exp: usize,       // Expiration time (Unix timestamp)
    
    #[serde(default)] 
    pub is_api_key: bool, // Flag to distinguish between JWT and API Key
    
    // --- Phase 1: New permission fields for API Keys ---
    #[serde(default = "default_scope")]
    pub scope: String,      // e.g., "/" or "/docs" - controls access path
    #[serde(default = "default_perm")]
    pub perm: String,       // "rw" (read-write) or "ro" (read-only)
}

fn default_scope() -> String { "/".to_string() }
fn default_perm() -> String { "rw".to_string() } // Default to read-write for API keys

#[derive(Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String, // JWT or API Key
}

// 修正：添加 Serialize
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileMeta {
    pub path: String,
    pub hash: String,
    pub mtime: i64,
    pub is_deleted: bool,
}

#[derive(Serialize, Debug)]
pub struct SyncDiff {
    pub files_to_upload: Vec<String>,      // Paths of files client needs to upload
    pub files_to_download: Vec<FileMeta>, // Metadata of files client needs to download
}