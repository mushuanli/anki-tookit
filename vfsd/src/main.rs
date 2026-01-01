// vfs-sync-server/src/main.rs
use axum::{
    extract::{State, Multipart},
    http::{StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, Row};
use std::{sync::Arc, collections::HashMap};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use sha2::{Sha256, Digest};
use hex;

// --- Config ---
const JWT_SECRET: &[u8] = b"secret_key_change_me_production";
const MAX_UPLOAD_MB: usize = 100;
const SERVER_VERSION: &str = "1.0.0";

// --- State ---
#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
}

// --- Types ---
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // username
    uid: i64,    // user_id
    exp: usize,
}

#[derive(Deserialize)]
struct AuthPayload { username: String, password: String }

#[derive(Serialize)]
struct AuthResponse { token: String }

#[derive(Debug, Deserialize, Serialize)]
struct FileMeta {
    path: String,
    hash: String,
    mtime: i64,
    is_deleted: bool,
}

#[derive(Serialize)]
struct SyncDiff {
    files_to_upload: Vec<String>,
    files_to_download: Vec<FileMeta>,
}

// --- Main ---
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Database Setup
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:sync.db".to_string());
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to DB");

    // Init Tables
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)")
        .execute(&pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS files (user_id INTEGER, path TEXT, hash TEXT, mtime INTEGER, content BLOB, is_deleted BOOLEAN, PRIMARY KEY(user_id, path))")
        .execute(&pool).await?;

    let state = Arc::new(AppState { db: pool });

    // Router
    let app = Router::new()
        .route("/api/version", get(version_handler))
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/sync/check", post(sync_check_handler))
        .route("/api/sync/upload", post(upload_handler))
        .route("/api/sync/download", post(download_handler))
        .layer(CorsLayer::permissive())
        .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_MB * 1024 * 1024))
        .with_state(state);

    println!("Listening on 0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// --- Handlers ---

async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": SERVER_VERSION }))
}

async fn register_handler(State(state): State<Arc<AppState>>, Json(payload): Json<AuthPayload>) -> impl IntoResponse {
    let hash = hash(payload.password, DEFAULT_COST).unwrap();
    match sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(payload.username)
        .bind(hash)
        .execute(&state.db)
        .await {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

async fn login_handler(State(state): State<Arc<AppState>>, Json(payload): Json<AuthPayload>) -> impl IntoResponse {
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&state.db)
        .await.unwrap();

    if let Some(row) = row {
        let id: i64 = row.get("id");
        let hash_str: String = row.get("password_hash");
        if verify(payload.password, &hash_str).unwrap_or(false) {
            let claims = Claims {
                sub: payload.username,
                uid: id,
                exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap();
            return Ok(Json(AuthResponse { token }));
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// Compare client files with server files
async fn sync_check_handler(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(client_files): Json<Vec<FileMeta>>
) -> impl IntoResponse {
    let server_rows = sqlx::query("SELECT path, hash, mtime, is_deleted FROM files WHERE user_id = ?")
        .bind(claims.uid)
        .fetch_all(&state.db)
        .await.unwrap();

    let mut server_map: HashMap<String, FileMeta> = HashMap::new();
    for row in server_rows {
        let path: String = row.get("path");
        server_map.insert(path.clone(), FileMeta {
            path,
            hash: row.get("hash"),
            mtime: row.get("mtime"),
            is_deleted: row.get("is_deleted"),
        });
    }

    let mut upload = Vec::new();
    let mut download = Vec::new();

    // Check Client Files
    for c in &client_files {
        match server_map.get(&c.path) {
            Some(s) => {
                if s.hash != c.hash {
                    // Conflict: Last Write Wins
                    if c.mtime > s.mtime {
                        upload.push(c.path.clone());
                    } else if s.mtime > c.mtime {
                        download.push(FileMeta { path: s.path.clone(), hash: s.hash.clone(), mtime: s.mtime, is_deleted: s.is_deleted });
                    }
                }
                server_map.remove(&c.path);
            },
            None => {
                upload.push(c.path.clone());
            }
        }
    }

    // Remaining in server_map are files client doesn't have
    for (_, s) in server_map {
        download.push(FileMeta { path: s.path, hash: s.hash, mtime: s.mtime, is_deleted: s.is_deleted });
    }

    Json(SyncDiff { files_to_upload: upload, files_to_download: download })
}

// Handle multipart upload: Field name is "path", value is content
async fn upload_handler(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart
) -> impl IntoResponse {
    while let Some(field) = multipart.next_field().await.unwrap() {
        let path = field.name().unwrap().to_string();
        let data = field.bytes().await.unwrap();
        
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let hash = hex::encode(hasher.finalize());
        let mtime = chrono::Utc::now().timestamp_millis();

        sqlx::query("INSERT OR REPLACE INTO files (user_id, path, hash, mtime, content, is_deleted) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(claims.uid)
            .bind(path)
            .bind(hash)
            .bind(mtime)
            .bind(data.to_vec())
            .bind(false)
            .execute(&state.db)
            .await.unwrap();
    }
    StatusCode::OK
}

async fn download_handler(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>
) -> impl IntoResponse {
    let path = payload["path"].as_str().unwrap();
    let row = sqlx::query("SELECT content FROM files WHERE user_id = ? AND path = ?")
        .bind(claims.uid)
        .bind(path)
        .fetch_optional(&state.db)
        .await.unwrap();

    match row {
        Some(r) => {
            let content: Vec<u8> = r.get("content");
            (StatusCode::OK, content).into_response()
        },
        None => StatusCode::NOT_FOUND.into_response()
    }
}

// Auth Extractor
#[axum::async_trait]
impl<S> FromRequestParts<S> for Claims
where S: Send + Sync {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let header = parts.headers.get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        
        if !header.starts_with("Bearer ") { return Err(StatusCode::UNAUTHORIZED); }
        let token = &header[7..];
        
        decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::default())
            .map(|d| d.claims)
            .map_err(|_| StatusCode::UNAUTHORIZED)
    }
}
