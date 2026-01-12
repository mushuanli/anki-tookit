// src/models/user.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,  // SQLite 使用 TEXT 存储 UUID
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub storage_quota: i64,
    pub storage_used: i64,
    pub is_active: bool,
    pub created_at: String,  // SQLite 使用 TEXT 存储时间
    pub updated_at: String,
}

impl User {
    pub fn id_as_uuid(&self) -> Uuid {
        Uuid::parse_str(&self.id).unwrap_or_default()
    }

    pub fn created_at_parsed(&self) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&self.created_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub storage_quota: i64,
    pub storage_used: i64,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        // 先调用方法获取需要的值，避免部分移动后的借用问题
        let id = user.id_as_uuid();
        let created_at = user.created_at_parsed();
        
        Self {
            id,
            username: user.username,
            email: user.email,
            display_name: user.display_name,
            storage_quota: user.storage_quota,
            storage_used: user.storage_used,
            created_at,
        }
    }
}
