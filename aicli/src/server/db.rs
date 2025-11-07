// src/server/db.rs

use crate::common::types::ChatLog;
use crate::error::{AppError, Result};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::{Row, FromRow};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct Database {
    // This field is private, so all database access must go through methods on this struct.
    pool: SqlitePool,
}

// Struct for listing users from the database.
#[derive(sqlx::FromRow)]
pub struct UserInfo {
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub key_modified_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

// REFACTOR: This struct is for sending task list data to the TUI client
#[derive(Debug, serde::Serialize, serde::Deserialize, FromRow)]
pub struct RemoteTaskInfo {
    pub uuid: Uuid,
    pub title: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>, // Make it optional for backward compatibility
    pub error_message: Option<String>,
}


impl Database {
    pub async fn connect(db_path: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(db_path)
                    .create_if_missing(true),
            )
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| AppError::DbError(format!("Migration failed: {}", e)))?;
        Ok(Database { pool })
    }


    // NEW HELPER FUNCTION
    pub async fn log_exists(&self, uuid: &Uuid) -> Result<bool> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_logs WHERE uuid = ?")
            .bind(uuid)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(count > 0)
    }

    pub async fn create_chat_log(&self, log: &ChatLog, client_ip: &str) -> Result<()> {
        let model_used = log.model.as_deref().unwrap_or_default();
        sqlx::query("INSERT INTO chat_logs (uuid, title, client_ip, status, model_used, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(log.uuid)
            .bind(&log.title)
            .bind(client_ip)
            .bind("pending")
            .bind(model_used)
            .bind(log.get_creation_time())
            .bind(log.updated_at) // Bind the new timestamp
            .execute(&self.pool)
            .await.map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_status(&self, uuid: &Uuid, status: &str, error_msg: Option<&str>, updated_at: DateTime<Utc>) -> Result<()> {
        let mut query_builder = sqlx::query_builder::QueryBuilder::new("UPDATE chat_logs SET status = ");
        query_builder.push_bind(status);
        query_builder.push(", updated_at = ").push_bind(updated_at); // Always update timestamp

        if status == "processing" {
            query_builder.push(", processing_at = ").push_bind(Utc::now());
        } else if status == "completed" || status == "failed" {
            query_builder.push(", finished_at = ").push_bind(Utc::now());
        }
        
        if let Some(msg) = error_msg {
            query_builder.push(", error_message = ").push_bind(msg);
        } else {
            query_builder.push(", error_message = NULL");
        }
        
        query_builder.push(" WHERE uuid = ").push_bind(uuid);
        query_builder.build().execute(&self.pool).await.map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }
    
    // --- NEW DB METHODS FOR TUI ---
    
    pub async fn list_all_tasks(&self) -> Result<Vec<RemoteTaskInfo>> {
        sqlx::query_as::<_, RemoteTaskInfo>("SELECT uuid, title, status, created_at, updated_at, error_message FROM chat_logs ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))
    }
    
    pub async fn delete_task(&self, uuid: &Uuid) -> Result<()> {
        // We'll also need to delete the file on disk, but that's a handler-level concern.
        sqlx::query("DELETE FROM chat_logs WHERE uuid = ?")
            .bind(uuid)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;

        Ok(())
    }

    // --- USER MANAGEMENT METHODS ---

    pub async fn add_user(&self, username: &str, public_key: &str) -> Result<()> {
        sqlx::query("INSERT INTO users (username, public_key) VALUES (?, ?)")
            .bind(username)
            .bind(public_key)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_user_key(&self, username: &str, public_key: &str) -> Result<()> {
        sqlx::query("UPDATE users SET public_key = ?, key_modified_at = ? WHERE username = ?")
            .bind(public_key)
            .bind(Utc::now())
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserInfo>> {
        sqlx::query_as::<_, UserInfo>("SELECT username, created_at, key_modified_at, last_seen_at FROM users ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))
    }

    pub async fn get_user_pubkey(&self, username: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT public_key FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(row.map(|r| r.get("public_key")))
    }

    pub async fn update_last_seen(&self, username: &str) -> Result<()> {
        sqlx::query("UPDATE users SET last_seen_at = ? WHERE username = ?")
            .bind(Utc::now())
            .bind(username)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DbError(e.to_string()))?;
        Ok(())
    }
}
