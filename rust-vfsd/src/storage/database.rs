// src/storage/database.rs

use chrono::{Utc};
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::error::{AppError, AppResult};
use crate::models::*;

#[derive(Clone)]
pub struct Database {
    pool: Pool<Postgres>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> AppResult<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.url)
            .await
            .map_err(|e| AppError::DatabaseError(e))?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> AppResult<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| AppError::InternalError(format!("Migration failed: {}", e)))?;
        Ok(())
    }

    // ==================== 用户相关 ====================

    pub async fn create_user(&self, user: &User) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, email, display_name, storage_quota, storage_used, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(&user.storage_quota)
        .bind(&user.storage_used)
        .bind(&user.is_active)
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn update_user_storage(&self, user_id: Uuid, delta: i64) -> AppResult<()> {
        sqlx::query(
            "UPDATE users SET storage_used = storage_used + $1, updated_at = $2 WHERE id = $3",
        )
        .bind(delta)
        .bind(Utc::now())
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ==================== Token 相关 ====================

    pub async fn create_token(&self, token: &ApiToken) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO api_tokens (id, user_id, name, token_hash, permission_level, path_permissions, device_id, device_name, expires_at, is_revoked, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&token.id)
        .bind(&token.user_id)
        .bind(&token.name)
        .bind(&token.token_hash)
        .bind(&token.permission_level)
        .bind(&serde_json::to_value(&token.path_permissions).ok())
        .bind(&token.device_id)
        .bind(&token.device_name)
        .bind(&token.expires_at)
        .bind(&token.is_revoked)
        .bind(&token.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_token_by_hash(&self, token_hash: &str) -> AppResult<Option<ApiToken>> {
        let token = sqlx::query_as::<_, ApiToken>(
            "SELECT * FROM api_tokens WHERE token_hash = $1 AND is_revoked = false",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(token)
    }

    pub async fn get_user_tokens(&self, user_id: Uuid) -> AppResult<Vec<ApiToken>> {
        let tokens = sqlx::query_as::<_, ApiToken>(
            "SELECT * FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(tokens)
    }

    pub async fn revoke_token(&self, token_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            "UPDATE api_tokens SET is_revoked = true WHERE id = $1 AND user_id = $2",
        )
        .bind(token_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_token_last_used(&self, token_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ==================== 同步日志相关 ====================

    pub async fn save_log(&self, log: &SyncLog) -> AppResult<i64> {
        let row = sqlx::query(
            r#"
            INSERT INTO sync_logs (user_id, module_id, node_id, device_id, operation, path, previous_path, content_hash, size, metadata, version, vector_clock, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id
            "#,
        )
        .bind(&log.user_id)
        .bind(&log.module_id)
        .bind(&log.node_id)
        .bind(&log.device_id)
        .bind(&log.operation)
        .bind(&log.path)
        .bind(&log.previous_path)
        .bind(&log.content_hash)
        .bind(&log.size)
        .bind(&log.metadata)
        .bind(&log.version)
        .bind(&serde_json::to_value(&log.vector_clock).ok())
        .bind(&log.created_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("id"))
    }

    pub async fn get_latest_log(
        &self,
        user_id: Uuid,
        module_id: &str,
        node_id: &str,
    ) -> AppResult<Option<SyncLog>> {
        let log = sqlx::query_as::<_, SyncLog>(
            r#"
            SELECT * FROM sync_logs 
            WHERE user_id = $1 AND module_id = $2 AND node_id = $3
            ORDER BY id DESC LIMIT 1
            "#,
        )
        .bind(user_id)
        .bind(module_id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(log)
    }

    pub async fn get_logs_after(
        &self,
        user_id: Uuid,
        module_id: &str,
        after_id: i64,
        limit: i64,
        exclude_device_id: &str,
    ) -> AppResult<Vec<SyncLog>> {
        let logs = sqlx::query_as::<_, SyncLog>(
            r#"
            SELECT * FROM sync_logs 
            WHERE user_id = $1 AND module_id = $2 AND id > $3 AND device_id != $4
            ORDER BY id ASC LIMIT $5
            "#,
        )
        .bind(user_id)
        .bind(module_id)
        .bind(after_id)
        .bind(exclude_device_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(logs)
    }

    // ==================== 游标相关 ====================

    pub async fn get_cursor(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
    ) -> AppResult<Option<SyncCursor>> {
        let cursor = sqlx::query_as::<_, SyncCursor>(
            "SELECT * FROM sync_cursors WHERE user_id = $1 AND device_id = $2 AND module_id = $3",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(module_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(cursor)
    }

    pub async fn update_cursor(&self, cursor: SyncCursor) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO sync_cursors (user_id, device_id, module_id, last_log_id, last_sync_time, last_content_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, device_id, module_id) 
            DO UPDATE SET last_log_id = $4, last_sync_time = $5, last_content_hash = $6
            "#,
        )
        .bind(&cursor.user_id)
        .bind(&cursor.device_id)
        .bind(&cursor.module_id)
        .bind(&cursor.last_log_id)
        .bind(&cursor.last_sync_time)
        .bind(&cursor.last_content_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ==================== 内容存储 ====================

    pub async fn save_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
        data: &[u8],
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO content_store (user_id, content_hash, data, size, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, content_hash) DO NOTHING
            "#,
        )
        .bind(user_id)
        .bind(content_hash)
        .bind(data)
        .bind(data.len() as i64)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_content(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Option<Vec<u8>>> {
        let row = sqlx::query(
            "SELECT data FROM content_store WHERE user_id = $1 AND content_hash = $2",
        )
        .bind(user_id)
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get("data")))
    }

    // ==================== 冲突相关 ====================

    pub async fn save_conflict(&self, conflict: &SyncConflict) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO sync_conflicts (id, user_id, node_id, path, local_change, remote_change, conflict_type, resolved, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&conflict.id)
        .bind(&conflict.user_id)
        .bind(&conflict.node_id)
        .bind(&conflict.path)
        .bind(&serde_json::to_value(&conflict.local_change).ok())
        .bind(&serde_json::to_value(&conflict.remote_change).ok())
        .bind(&conflict.conflict_type)
        .bind(&conflict.resolved)
        .bind(&conflict.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_unresolved_conflicts(&self, user_id: Uuid) -> AppResult<Vec<SyncConflict>> {
        let conflicts = sqlx::query_as::<_, SyncConflict>(
            "SELECT * FROM sync_conflicts WHERE user_id = $1 AND resolved = false ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(conflicts)
    }

    pub async fn resolve_conflict(
        &self,
        conflict_id: Uuid,
        user_id: Uuid,
        resolution: ConflictResolution,
    ) -> AppResult<bool> {
        let result = sqlx::query(
            "UPDATE sync_conflicts SET resolved = true, resolution = $1, resolved_at = $2 WHERE id = $3 AND user_id = $4",
        )
        .bind(&resolution)
        .bind(Utc::now())
        .bind(conflict_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ==================== 分片相关 ====================

    pub async fn save_chunk(&self, chunk: &FileChunk) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO file_chunks (id, user_id, content_hash, chunk_index, total_chunks, size, checksum, storage_path, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(&chunk.id)
        .bind(&chunk.user_id)
        .bind(&chunk.content_hash)
        .bind(&chunk.chunk_index)
        .bind(&chunk.total_chunks)
        .bind(&chunk.size)
        .bind(&chunk.checksum)
        .bind(&chunk.storage_path)
        .bind(&chunk.created_at)
                .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_chunk(
        &self,
        user_id: Uuid,
        content_hash: &str,
        index: i32,
    ) -> AppResult<Option<FileChunk>> {
        let chunk_id = format!("{}_{}", content_hash, index);
        let chunk = sqlx::query_as::<_, FileChunk>(
            "SELECT * FROM file_chunks WHERE id = $1 AND user_id = $2",
        )
        .bind(&chunk_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(chunk)
    }

    pub async fn get_chunks_by_hash(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Vec<FileChunk>> {
        let chunks = sqlx::query_as::<_, FileChunk>(
            "SELECT * FROM file_chunks WHERE user_id = $1 AND content_hash = $2 ORDER BY chunk_index",
        )
        .bind(user_id)
        .bind(content_hash)
        .fetch_all(&self.pool)
        .await?;
        Ok(chunks)
    }

    pub async fn delete_chunks_by_hash(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM file_chunks WHERE user_id = $1 AND content_hash = $2")
            .bind(user_id)
            .bind(content_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
