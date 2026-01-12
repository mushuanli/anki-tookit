// src/storage/database.rs

use chrono::Utc;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::path::Path;
use tokio::fs;
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::error::{AppError, AppResult};
use crate::models::*;

#[derive(Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> AppResult<Self> {
        // 确保数据库目录存在
        if let Some(parent) = Path::new(&config.path).parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                AppError::InternalError(format!("Failed to create database directory: {}", e))
            })?;
        }

        // 创建连接池
        let pool = SqlitePool::connect(&format!("sqlite:{}?mode=rwc", config.path))
            .await
            .map_err(|e| AppError::DatabaseError(e))?;

        // 启用 WAL 模式和外键约束
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&pool)
            .await?;

        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> AppResult<()> {
        // 创建表结构
        self.create_tables().await?;
        Ok(())
    }

    async fn create_tables(&self) -> AppResult<()> {
        // Users 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                display_name TEXT,
                storage_quota INTEGER NOT NULL DEFAULT 10737418240,
                storage_used INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // API Tokens 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS api_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                permission_level TEXT NOT NULL,
                path_permissions TEXT,
                device_id TEXT,
                device_name TEXT,
                last_used_at TEXT,
                expires_at TEXT,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Sync Logs 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sync_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                path TEXT NOT NULL,
                previous_path TEXT,
                content_hash TEXT,
                size INTEGER,
                metadata TEXT,
                version INTEGER NOT NULL,
                vector_clock TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Sync Cursors 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sync_cursors (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                last_log_id INTEGER NOT NULL,
                last_sync_time TEXT NOT NULL,
                last_content_hash TEXT,
                PRIMARY KEY (user_id, device_id, module_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Sync Conflicts 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sync_conflicts (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                path TEXT NOT NULL,
                local_change TEXT NOT NULL,
                remote_change TEXT NOT NULL,
                conflict_type TEXT NOT NULL,
                resolved INTEGER NOT NULL DEFAULT 0,
                resolution TEXT,
                resolved_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // File Chunks 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS file_chunks (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                total_chunks INTEGER NOT NULL,
                size INTEGER NOT NULL,
                checksum TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Content 索引表 (元数据，实际内容存储在文件系统)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS content_index (
                user_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                storage_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, content_hash),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // 创建索引
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sync_logs_user_module ON sync_logs(user_id, module_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sync_logs_node ON sync_logs(user_id, module_id, node_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_file_chunks_hash ON file_chunks(user_id, content_hash)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ==================== 用户相关 ====================

    pub async fn create_user(&self, user: &User) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, email, display_name, storage_quota, storage_used, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn update_user_storage(&self, user_id: Uuid, delta: i64) -> AppResult<()> {
        sqlx::query(
            "UPDATE users SET storage_used = storage_used + ?, updated_at = ? WHERE id = ?",
        )
        .bind(delta)
        .bind(Utc::now().to_rfc3339())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

pub async fn list_users(&self, limit: i64, offset: i64, search: Option<&str>) -> AppResult<(Vec<User>, i64)> {
    let search_term = search.map(|s| format!("%{}%", s));
    
    let count_query = "SELECT COUNT(*) FROM users WHERE (?1 IS NULL OR username LIKE ?1 OR display_name LIKE ?1)";
    let count: (i64,) = sqlx::query_as(count_query)
        .bind(search_term.clone())
        .fetch_one(&self.pool)
        .await?;

    let list_query = r#"
        SELECT * FROM users 
        WHERE (?1 IS NULL OR username LIKE ?1 OR display_name LIKE ?1)
        ORDER BY created_at DESC 
        LIMIT ?2 OFFSET ?3
    "#;
    
    let users = sqlx::query_as::<_, User>(list_query)
        .bind(search_term)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

    Ok((users, count.0))
}

pub async fn update_user(&self, user: &User) -> AppResult<()> {
    sqlx::query(
        "UPDATE users SET is_active = ?, storage_quota = ?, storage_used = ?, email = ?, display_name = ?, password_hash = ?, updated_at = ? WHERE id = ?"
    )
    .bind(user.is_active)
    .bind(user.storage_quota)
    .bind(user.storage_used)
    .bind(&user.email)
    .bind(&user.display_name)
    .bind(&user.password_hash)
    .bind(&user.updated_at)
    .bind(&user.id)
    .execute(&self.pool)
    .await?;
    Ok(())
}

pub async fn delete_user(&self, user_id: Uuid) -> AppResult<()> {
    // 依赖外键 CASCADE 删除相关数据
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;
    Ok(())
}


    // ==================== Token 相关 ====================

    pub async fn create_token(&self, token: &ApiToken) -> AppResult<()> {
        let path_perms_json = token.path_permissions
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default());

        sqlx::query(
            r#"
            INSERT INTO api_tokens (id, user_id, name, token_hash, permission_level, path_permissions, device_id, device_name, expires_at, is_revoked, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(token.id.to_string())
        .bind(token.user_id.to_string())
        .bind(&token.name)
        .bind(&token.token_hash)
        .bind(token.permission_level.to_string())
        .bind(path_perms_json)
        .bind(&token.device_id)
        .bind(&token.device_name)
        .bind(token.expires_at.map(|dt| dt.to_rfc3339()))
        .bind(token.is_revoked)
        .bind(token.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_token_by_hash(&self, token_hash: &str) -> AppResult<Option<ApiToken>> {
        let row = sqlx::query_as::<_, ApiTokenRow>(
            "SELECT * FROM api_tokens WHERE token_hash = ? AND is_revoked = 0",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(ApiToken::from))
    }

    pub async fn get_user_tokens(&self, user_id: Uuid) -> AppResult<Vec<ApiToken>> {
        let rows = sqlx::query_as::<_, ApiTokenRow>(
            "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(ApiToken::from).collect())
    }

    pub async fn revoke_token(&self, token_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        let result = sqlx::query(
            "UPDATE api_tokens SET is_revoked = 1 WHERE id = ? AND user_id = ?",
        )
        .bind(token_id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;
        
        Ok(result.rows_affected() > 0)
    }

    pub async fn update_token_last_used(&self, token_id: Uuid) -> AppResult<()> {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(Utc::now().to_rfc3339())
            .bind(token_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ==================== 同步日志相关 ====================
pub async fn get_system_stats(&self) -> AppResult<crate::handlers::admin::SystemStats> {
    let total_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users").fetch_one(&self.pool).await?;
    let active_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active = 1").fetch_one(&self.pool).await?;
    let total_storage: (Option<i64>,) = sqlx::query_as("SELECT SUM(storage_used) FROM users").fetch_one(&self.pool).await?;
    let total_logs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sync_logs").fetch_one(&self.pool).await?;
    
    Ok(crate::handlers::admin::SystemStats {
        total_users: total_users.0,
        active_users: active_users.0,
        total_storage_used: total_storage.0.unwrap_or(0),
        total_sync_logs: total_logs.0,
        active_connections: 0, // 这个数据需要在 Handler 层从 websocket state 获取，这里先填0
    })
}

    pub async fn save_log(&self, log: &SyncLog) -> AppResult<i64> {
        let metadata_json = log.metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());
        let vector_clock_json = serde_json::to_string(&log.vector_clock).unwrap_or_default();

        let result = sqlx::query(
            r#"
            INSERT INTO sync_logs (user_id, module_id, node_id, device_id, operation, path, previous_path, content_hash, size, metadata, version, vector_clock, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(log.user_id.to_string())
        .bind(&log.module_id)
        .bind(&log.node_id)
        .bind(&log.device_id)
        .bind(log.operation.to_string())
        .bind(&log.path)
        .bind(&log.previous_path)
        .bind(&log.content_hash)
        .bind(&log.size)
        .bind(metadata_json)
        .bind(&log.version)
        .bind(vector_clock_json)
        .bind(log.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_latest_log(
        &self,
        user_id: Uuid,
        module_id: &str,
        node_id: &str,
    ) -> AppResult<Option<SyncLog>> {
        let row = sqlx::query_as::<_, SyncLogRow>(
            r#"
            SELECT * FROM sync_logs 
            WHERE user_id = ? AND module_id = ? AND node_id = ?
            ORDER BY id DESC LIMIT 1
            "#,
        )
        .bind(user_id.to_string())
        .bind(module_id)
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(SyncLog::from))
    }

    pub async fn get_logs_after(
        &self,
        user_id: Uuid,
        module_id: &str,
        after_id: i64,
        limit: i64,
        exclude_device_id: &str,
    ) -> AppResult<Vec<SyncLog>> {
        let rows = sqlx::query_as::<_, SyncLogRow>(
            r#"
            SELECT * FROM sync_logs 
            WHERE user_id = ? AND module_id = ? AND id > ? AND device_id != ?
            ORDER BY id ASC LIMIT ?
            "#,
        )
        .bind(user_id.to_string())
        .bind(module_id)
        .bind(after_id)
        .bind(exclude_device_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(SyncLog::from).collect())
    }

    // ==================== 游标相关 ====================

    pub async fn get_cursor(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
    ) -> AppResult<Option<SyncCursor>> {
        let row = sqlx::query_as::<_, SyncCursorRow>(
            "SELECT * FROM sync_cursors WHERE user_id = ? AND device_id = ? AND module_id = ?",
        )
        .bind(user_id.to_string())
        .bind(device_id)
        .bind(module_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(SyncCursor::from))
    }

    pub async fn update_cursor(&self, cursor: SyncCursor) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO sync_cursors (user_id, device_id, module_id, last_log_id, last_sync_time, last_content_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (user_id, device_id, module_id) 
            DO UPDATE SET last_log_id = ?, last_sync_time = ?, last_content_hash = ?
            "#,
        )
        .bind(cursor.user_id.to_string())
        .bind(&cursor.device_id)
        .bind(&cursor.module_id)
        .bind(&cursor.last_log_id)
        .bind(cursor.last_sync_time.to_rfc3339())
        .bind(&cursor.last_content_hash)
        .bind(&cursor.last_log_id)
        .bind(cursor.last_sync_time.to_rfc3339())
        .bind(&cursor.last_content_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ==================== 冲突相关 ====================

    pub async fn save_conflict(&self, conflict: &SyncConflict) -> AppResult<()> {
        let local_json = serde_json::to_string(&conflict.local_change).unwrap_or_default();
        let remote_json = serde_json::to_string(&conflict.remote_change).unwrap_or_default();

        sqlx::query(
            r#"
            INSERT INTO sync_conflicts (id, user_id, node_id, path, local_change, remote_change, conflict_type, resolved, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(conflict.id.to_string())
        .bind(conflict.user_id.to_string())
        .bind(&conflict.node_id)
        .bind(&conflict.path)
        .bind(local_json)
        .bind(remote_json)
        .bind(conflict.conflict_type.to_string())
        .bind(conflict.resolved)
        .bind(conflict.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_unresolved_conflicts(&self, user_id: Uuid) -> AppResult<Vec<SyncConflict>> {
        let rows = sqlx::query_as::<_, SyncConflictRow>(
            "SELECT * FROM sync_conflicts WHERE user_id = ? AND resolved = 0 ORDER BY created_at DESC",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(SyncConflict::from).collect())
    }

    pub async fn resolve_conflict(
        &self,
        conflict_id: Uuid,
        user_id: Uuid,
        resolution: ConflictResolution,
    ) -> AppResult<bool> {
        let result = sqlx::query(
            "UPDATE sync_conflicts SET resolved = 1, resolution = ?, resolved_at = ? WHERE id = ? AND user_id = ?",
        )
        .bind(resolution.to_string())
        .bind(Utc::now().to_rfc3339())
        .bind(conflict_id.to_string())
        .bind(user_id.to_string())
        .execute(&self.pool)
        .await?;
        
        Ok(result.rows_affected() > 0)
    }

    // ==================== 分片相关 ====================

    pub async fn save_chunk(&self, chunk: &FileChunk) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO file_chunks (id, user_id, content_hash, chunk_index, total_chunks, size, checksum, storage_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&chunk.id)
        .bind(chunk.user_id.to_string())
        .bind(&chunk.content_hash)
        .bind(&chunk.chunk_index)
        .bind(&chunk.total_chunks)
        .bind(&chunk.size)
        .bind(&chunk.checksum)
        .bind(&chunk.storage_path)
        .bind(chunk.created_at.to_rfc3339())
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
        let row = sqlx::query_as::<_, FileChunkRow>(
            "SELECT * FROM file_chunks WHERE id = ? AND user_id = ?",
        )
        .bind(&chunk_id)
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(FileChunk::from))
    }

    pub async fn get_chunks_by_hash(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Vec<FileChunk>> {
        let rows = sqlx::query_as::<_, FileChunkRow>(
            "SELECT * FROM file_chunks WHERE user_id = ? AND content_hash = ? ORDER BY chunk_index",
        )
        .bind(user_id.to_string())
        .bind(content_hash)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(rows.into_iter().map(FileChunk::from).collect())
    }

    pub async fn delete_chunks_by_hash(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM file_chunks WHERE user_id = ? AND content_hash = ?")
            .bind(user_id.to_string())
            .bind(content_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ==================== 内容索引相关 ====================

    pub async fn save_content_index(
        &self,
        user_id: Uuid,
        content_hash: &str,
        size: i64,
        storage_path: &str,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO content_index (user_id, content_hash, size, storage_path, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(user_id.to_string())
        .bind(content_hash)
        .bind(size)
        .bind(storage_path)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_content_path(
        &self,
        user_id: Uuid,
        content_hash: &str,
    ) -> AppResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT storage_path FROM content_index WHERE user_id = ? AND content_hash = ?",
        )
        .bind(user_id.to_string())
        .bind(content_hash)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(row.map(|(path,)| path))
    }

    pub async fn delete_content_index(&self, user_id: Uuid, content_hash: &str) -> AppResult<()> {
        sqlx::query("DELETE FROM content_index WHERE user_id = ? AND content_hash = ?")
            .bind(user_id.to_string())
            .bind(content_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
