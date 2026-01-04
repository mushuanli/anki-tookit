// src/server/handlers.rs
use axum::{
    extract::{ConnectInfo, Multipart, State},
    response::{IntoResponse, Json},
    http::StatusCode,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use sqlx::Row;
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, EncodingKey, Header};
use sha2::{Digest, Sha256};
use crate::types::{AppState, AuthPayload, AuthResponse, Claims, FileMeta, SyncDiff, JWT_SECRET};

// 辅助：检查路径是否在 Token 的 Scope 内
fn is_path_allowed(scope: &str, path: &str) -> bool {
    if scope == "/" { return true; }
    let normalize_path = if !path.starts_with('/') { format!("/{}", path) } else { path.to_string() };
    normalize_path.starts_with(scope)
}

pub async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": "1.6.0" }))
}

pub async fn register_handler(State(state): State<Arc<AppState>>, Json(payload): Json<AuthPayload>) -> impl IntoResponse {
    let hash = hash(payload.password, DEFAULT_COST).unwrap();
    match sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(payload.username).bind(hash).execute(&state.db).await {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>, 
    Json(payload): Json<AuthPayload>
) -> impl IntoResponse {
    let ip = addr.ip();
    const LOGIN_FAIL_LIMIT: u32 = 5;
    const LOGIN_LOCKOUT_DURATION: u64 = 300; 

    if let Some(entry) = state.login_attempts.get(&ip) {
        if entry.0 >= LOGIN_FAIL_LIMIT && entry.1.elapsed() < Duration::from_secs(LOGIN_LOCKOUT_DURATION) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    let row = sqlx::query("SELECT id, password_hash, token_version FROM users WHERE username = ?")
        .bind(&payload.username).fetch_optional(&state.db).await.unwrap();

    if let Some(row) = row {
        // IP check is handled in middleware/auth extractor usually, but login is public.
        // We verify credentials first.
        if verify(payload.password, &row.get::<String,_>("password_hash")).unwrap_or(false) {
            state.login_attempts.remove(&ip);
            let id: i64 = row.get("id");
            let claims = Claims {
                sub: payload.username,
                uid: id,
                ver: row.get("token_version"),
                exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
                is_api_key: false,
                scope: "/".to_string(),
                perm: "rw".to_string(),
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap();
            return Ok(Json(AuthResponse { token }));
        }
    }

    let mut entry = state.login_attempts.entry(ip).or_insert((0, Instant::now()));
    entry.0 += 1;
    entry.1 = Instant::now();

    Err(StatusCode::UNAUTHORIZED)
}

pub async fn sync_check_handler(
    claims: Claims, 
    State(state): State<Arc<AppState>>, 
    Json(client_files): Json<Vec<FileMeta>>
) -> impl IntoResponse {
    // 即使是只读 Token，也允许 Check
    let server_rows = sqlx::query("SELECT path, hash, mtime, is_deleted FROM files WHERE user_id = ?")
        .bind(claims.uid).fetch_all(&state.db).await.unwrap();
    
    let mut server_map: HashMap<String, FileMeta> = HashMap::new();
    for row in server_rows {
        let path: String = row.get("path");
        // Phase 1: 过滤掉不在 Scope 内的文件，不告诉客户端这些文件的存在
        if is_path_allowed(&claims.scope, &path) {
            server_map.insert(path.clone(), FileMeta { 
                path, 
                hash: row.get("hash"), 
                mtime: row.get("mtime"), 
                is_deleted: row.get("is_deleted") 
            });
        }
    }

    let mut upload = Vec::new();
    let mut download = Vec::new();

    for c in &client_files {
        // 客户端请求的文件必须在 Scope 内
        if !is_path_allowed(&claims.scope, &c.path) { continue; }

        match server_map.get(&c.path) {
            Some(s) => {
                if s.hash != c.hash {
                    // 如果客户端要上传，必须检查 Write 权限
                    if c.mtime > s.mtime { 
                        if claims.perm == "rw" { upload.push(c.path.clone()); }
                    } 
                    else if s.mtime > c.mtime { 
                        download.push(FileMeta { path: s.path.clone(), hash: s.hash.clone(), mtime: s.mtime, is_deleted: s.is_deleted }); 
                    }
                }
                server_map.remove(&c.path);
            },
            None => { 
                // 新文件上传，检查 Write 权限
                if claims.perm == "rw" { upload.push(c.path.clone()); }
            }
        }
    }
    // 剩下的 Server 文件需要下载给客户端
    for (_, s) in server_map { 
        download.push(FileMeta { path: s.path, hash: s.hash, mtime: s.mtime, is_deleted: s.is_deleted }); 
    }
    
    Json(SyncDiff { files_to_upload: upload, files_to_download: download })
}

pub async fn upload_handler(
    claims: Claims, 
    State(state): State<Arc<AppState>>, 
    mut multipart: Multipart
) -> impl IntoResponse {
    // Phase 1: 权限检查 - 只读拒绝
    if claims.perm != "rw" {
        return (StatusCode::FORBIDDEN, "Read-only token").into_response();
    }

    let quota: i64 = sqlx::query("SELECT quota_bytes FROM users WHERE id = ?")
        .bind(claims.uid).fetch_one(&state.db).await.unwrap().get("quota_bytes");
    
    while let Some(field) = multipart.next_field().await.unwrap() {
        let path = field.name().unwrap().to_string();
        if path.contains("..") || path.starts_with("/") { continue; }
        
        // Phase 1: 权限检查 - Scope
        if !is_path_allowed(&claims.scope, &path) {
            return (StatusCode::FORBIDDEN, "Path outside token scope").into_response();
        }

        let data = field.bytes().await.unwrap();
        let new_size = data.len() as i64;
        
        let usage_row = sqlx::query("SELECT SUM(LENGTH(content)) as size FROM files WHERE user_id = ?")
            .bind(claims.uid).fetch_one(&state.db).await.unwrap();
        let current_total: i64 = usage_row.get::<Option<i64>,_>("size").unwrap_or(0);
        
        let file_row = sqlx::query("SELECT LENGTH(content) as size FROM files WHERE user_id = ? AND path = ?")
            .bind(claims.uid).bind(&path).fetch_optional(&state.db).await.unwrap();
        let old_size = file_row.map(|r| r.get::<i64, _>("size")).unwrap_or(0);

        if current_total.saturating_sub(old_size).saturating_add(new_size) > quota {
            return (StatusCode::INSUFFICIENT_STORAGE, "Quota Exceeded").into_response();
        }

        let hash = hex::encode(Sha256::digest(&data));
        let mtime = chrono::Utc::now().timestamp_millis();
        sqlx::query("INSERT OR REPLACE INTO files (user_id, path, hash, mtime, content, is_deleted) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(claims.uid).bind(path).bind(hash).bind(mtime).bind(data.to_vec()).bind(false)
            .execute(&state.db).await.unwrap();
    }
    StatusCode::OK.into_response()
}

pub async fn download_handler(
    claims: Claims, 
    State(state): State<Arc<AppState>>, 
    Json(payload): Json<serde_json::Value>
) -> impl IntoResponse {
    let path = payload["path"].as_str().unwrap();
    if path.contains("..") { return StatusCode::BAD_REQUEST.into_response(); }
    
    // Phase 1: 权限检查 - Scope
    if !is_path_allowed(&claims.scope, path) {
        return StatusCode::FORBIDDEN.into_response();
    }

    match sqlx::query("SELECT content FROM files WHERE user_id = ? AND path = ?")
        .bind(claims.uid).bind(path).fetch_optional(&state.db).await.unwrap() {
        Some(r) => (StatusCode::OK, r.get::<Vec<u8>, _>("content")).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
