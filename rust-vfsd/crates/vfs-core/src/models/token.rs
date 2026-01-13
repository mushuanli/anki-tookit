// src/models/token.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Token 权限级别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    ReadOnly,
    ReadWrite,
    Admin,
}

impl Default for PermissionLevel {
    fn default() -> Self {
        Self::ReadOnly
    }
}

impl std::fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionLevel::ReadOnly => write!(f, "readonly"),
            PermissionLevel::ReadWrite => write!(f, "readwrite"),
            PermissionLevel::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for PermissionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "readonly" => Ok(PermissionLevel::ReadOnly),
            "readwrite" => Ok(PermissionLevel::ReadWrite),
            "admin" => Ok(PermissionLevel::Admin),
            _ => Err(format!("Unknown permission level: {}", s)),
        }
    }
}

/// 路径权限规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPermission {
    pub path: String,           // 路径模式，支持 glob
    pub permission: PermissionLevel,
}

/// API Token (数据库行)
#[derive(Debug, Clone, FromRow)]
pub struct ApiTokenRow {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub token_hash: String,
    pub permission_level: String,
    pub path_permissions: Option<String>,  // JSON string
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub is_revoked: bool,
    pub created_at: String,
}

/// API Token (业务对象)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub permission_level: PermissionLevel,
    pub path_permissions: Option<Vec<PathPermission>>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
}

impl From<ApiTokenRow> for ApiToken {
    fn from(row: ApiTokenRow) -> Self {
        Self {
            id: Uuid::parse_str(&row.id).unwrap_or_default(),
            user_id: Uuid::parse_str(&row.user_id).unwrap_or_default(),
            name: row.name,
            token_hash: row.token_hash,
            permission_level: row.permission_level.parse().unwrap_or_default(),
            path_permissions: row.path_permissions
                .and_then(|s| serde_json::from_str(&s).ok()),
            device_id: row.device_id,
            device_name: row.device_name,
            last_used_at: row.last_used_at
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            expires_at: row.expires_at
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
            is_revoked: row.is_revoked,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub permission_level: PermissionLevel,
    pub path_permissions: Option<Vec<PathPermission>>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token: String,  // 只在创建时返回明文
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub name: String,
    pub permission_level: PermissionLevel,
    pub path_permissions: Option<Vec<PathPermission>>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
}

impl From<ApiToken> for TokenInfo {
    fn from(token: ApiToken) -> Self {
        Self {
            id: token.id,
            name: token.name,
            permission_level: token.permission_level,
            path_permissions: token.path_permissions,
            device_id: token.device_id,
            device_name: token.device_name,
            last_used_at: token.last_used_at,
            expires_at: token.expires_at,
            is_revoked: token.is_revoked,
            created_at: token.created_at,
        }
    }
}
