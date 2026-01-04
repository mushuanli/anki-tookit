// src/db.rs
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::str::FromStr;
use crate::types::DEFAULT_QUOTA_BYTES;

pub async fn init_db(db_url: &str) -> anyhow::Result<Pool<Sqlite>> {
    let opts = SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true)
        .foreign_keys(true); // <--- 显式开启外键支持

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .expect("Failed to connect to DB");

    // 1. Users Table
    let create_users_sql = format!("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, 
        username TEXT UNIQUE, 
        password_hash TEXT,
        token_version INTEGER DEFAULT 1,
        quota_bytes INTEGER DEFAULT {}
    )", DEFAULT_QUOTA_BYTES);
    sqlx::query(&create_users_sql).execute(&pool).await?;

    // 2. Files Table
    sqlx::query("CREATE TABLE IF NOT EXISTS files (user_id INTEGER, path TEXT, hash TEXT, mtime INTEGER, content BLOB, is_deleted BOOLEAN, PRIMARY KEY(user_id, path))")
        .execute(&pool).await?;
    
    // 3. IP Whitelist Table
    sqlx::query("CREATE TABLE IF NOT EXISTS user_ips (user_id INTEGER, ip_cidr TEXT, PRIMARY KEY(user_id, ip_cidr))")
        .execute(&pool).await?;

    // 4. API Keys Table (Updated for Phase 1)
    // 新增 scope_path 和 permission 字段
    sqlx::query("CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        note TEXT,
        prefix TEXT,
        key_hash TEXT,
        created_at INTEGER,
        scope_path TEXT DEFAULT '/', 
        permission TEXT DEFAULT 'rw',
        expires_at INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )").execute(&pool).await?;

    // 5. Access Logs Table (New)
    sqlx::query("CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY,
        timestamp INTEGER,
        remote_ip TEXT,
        method TEXT,
        path TEXT,
        status INTEGER,
        user_id INTEGER,
        latency_ms INTEGER
    )").execute(&pool).await?;
    
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_logs_ts ON access_logs(timestamp DESC)")
        .execute(&pool).await?;

    Ok(pool)
}
