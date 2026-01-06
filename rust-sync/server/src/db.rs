// file: rustSync/server/src/db.rs
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row, types::Json};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::service::proto::{FileMeta, ChunkInfo};

// 定义一个对应的 Rust 结构体用于 JSON 序列化存储到 DB
#[derive(Debug, Serialize, Deserialize)]
pub struct DbChunk {
    pub hash: String,
    pub offset: u64,
    pub length: u32,
}


#[derive(Clone)]
pub struct Db {
    pub pool: Pool<Sqlite>,
}

impl Db {
    pub async fn new(db_url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(db_url)
            .await?;
        
        let db = Db { pool };
        db.init().await?;
        Ok(db)
    }

    async fn init(&self) -> Result<()> {
        // 1. 创建 Users 表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            "#
        ).execute(&self.pool).await?;

        // 2. 创建 Devices 表
        // 支持一个用户多个设备
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                device_name TEXT,
                last_seen INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            "#
        ).execute(&self.pool).await?;

        // 新增: file_index 表
        // user_id: 隔离不同用户
        // path: 文件相对路径
        // chunks: 存储 JSON 格式的分片列表
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS file_index (
                user_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                file_hash TEXT,
                size INTEGER,
                mtime INTEGER,
                is_deleted BOOLEAN DEFAULT FALSE,
                chunks JSON, 
                updated_at INTEGER,
                PRIMARY KEY (user_id, path),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            "#
        ).execute(&self.pool).await?;

        // 4. 创建测试用户 (admin / admin)
        // [修复] 这段代码必须在 init 函数内部
        let count: i32 = sqlx::query("SELECT count(*) from users WHERE username = 'admin'")
            .fetch_one(&self.pool)
            .await?
            .get(0);
        
        if count == 0 {
            let hash = crate::auth::hash_password("admin")?;
            sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
                .bind("admin")
                .bind(hash)
                .execute(&self.pool)
                .await?;
            println!("Created default user: admin / admin");
        }
        Ok(())
    } // [修复] init 函数在这里结束

    // === 新增: 索引操作 ===

    pub async fn upsert_file_index(&self, user_id: i64, meta: &FileMeta) -> Result<()> {
        // 将 Proto 的 ChunkInfo 转换为内部结构以便序列化为 JSON
        let db_chunks: Vec<DbChunk> = meta.chunks.iter().map(|c| DbChunk {
            hash: c.hash.clone(),
            offset: c.offset,
            length: c.length,
        }).collect();

        sqlx::query(
            r#"
            INSERT INTO file_index (user_id, path, file_hash, size, mtime, is_deleted, chunks, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%s','now'))
            ON CONFLICT(user_id, path) DO UPDATE SET
                file_hash=excluded.file_hash,
                size=excluded.size,
                mtime=excluded.mtime,
                is_deleted=excluded.is_deleted,
                chunks=excluded.chunks,
                updated_at=strftime('%s','now')
            "#
        )
        .bind(user_id)
        .bind(&meta.path)
        .bind(&meta.file_hash)
        .bind(meta.size as i64)
        .bind(meta.mtime)
        .bind(meta.is_deleted)
        .bind(Json(db_chunks)) // 序列化为 JSON 存入 SQLite
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_by_name(&self, username: &str) -> Result<Option<(i64, String)>> {
        let row = sqlx::query("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(r) = row {
            Ok(Some((r.get("id"), r.get("password_hash"))))
        } else {
            Ok(None)
        }
    }

    pub async fn register_device(&self, user_id: i64, device_id: &str, device_name: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO devices (device_id, user_id, device_name, last_seen)
            VALUES (?, ?, ?, strftime('%s','now'))
            ON CONFLICT(device_id) DO UPDATE SET last_seen = strftime('%s','now')
            "#
        )
        .bind(device_id)
        .bind(user_id)
        .bind(device_name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_file_indexes(&self, user_id: i64, prefix: &str) -> Result<Vec<FileMeta>> {
        // 简单的前缀匹配
        let pattern = format!("{}%", prefix);
        
        let rows = sqlx::query(
            r#"
            SELECT path, file_hash, size, mtime, is_deleted, chunks 
            FROM file_index 
            WHERE user_id = ? AND path LIKE ?
            "#
        )
        .bind(user_id)
        .bind(pattern)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            // 反序列化 JSON chunks
            let chunks_json: Option<Json<Vec<DbChunk>>> = row.get("chunks");
            let chunks_proto = match chunks_json {
                Some(Json(list)) => list.into_iter().map(|c| ChunkInfo {
                    hash: c.hash,
                    offset: c.offset,
                    length: c.length,
                }).collect(),
                None => vec![],
            };

            results.push(FileMeta {
                path: row.get("path"),
                file_hash: row.get("file_hash"),
                size: row.get::<i64, _>("size") as u64,
                mtime: row.get("mtime"),
                is_deleted: row.get("is_deleted"),
                chunks: chunks_proto,
            });
        }
        Ok(results)
    }
}
