// src/models/token.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Token 权限级别
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "permission_level", rename_all = "lowercase")]
pub enum PermissionLevel {
    ReadOnly,
    ReadWrite,
    Admin,
}

/// 路径权限规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPermission {
    pub path: String,           // 路径模式，支持 glob
    pub permission: PermissionLevel,
}

/// API Token
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub permission_level: PermissionLevel,
    #[sqlx(json)]
    pub path_permissions: Option<Vec<PathPermission>>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
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
