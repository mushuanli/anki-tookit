// vfs-sync-server/src/main.rs
use axum::{
    extract::{ConnectInfo, FromRequestParts, Multipart, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rcgen::generate_simple_self_signed;
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteConnectOptions, sqlite::SqlitePoolOptions, Pool, Row, Sqlite};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer};
use bcrypt::{hash, verify, DEFAULT_COST};
use sha2::{Digest, Sha256};

// --- Config ---
const JWT_SECRET: &[u8] = b"secret_key_change_me_production_random_string";
const MAX_UPLOAD_MB: usize = 100;
const SERVER_VERSION: &str = "1.2.0";
const DEFAULT_QUOTA_BYTES: i64 = 1024 * 1024 * 1024; // 1GB default
const LOGIN_FAIL_LIMIT: u32 = 5;
const LOGIN_LOCKOUT_DURATION: u64 = 300; // 5 minutes

// --- CLI Definitions ---
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Secure VFS Sync Server (TLS)
    Serve {
        #[arg(long, default_value = "cert.pem")]
        cert: String,
        #[arg(long, default_value = "key.pem")]
        key: String,
        #[arg(long, default_value = "3443")]
        port: u16,
    },
    /// Generate self-signed certs for testing
    GenCert,
    User {
        #[command(subcommand)]
        action: UserAction,
    },
    /// Show server status and statistics
    Status,
}

#[derive(Subcommand)]
enum UserAction {
    /// List all users
    List,
    /// Add a new user
    Add { username: String, pass: String },
    /// Reset user password
    Passwd { username: String, pass: String },
    /// Set storage quota (in MB)
    Quota { username: String, mb: i64 },
    /// Force logout (invalidates all existing tokens)
    Kick { username: String },
    Del { username: String },
    /// Manage IP Whitelist
    Ip {
        #[command(subcommand)]
        action: IpAction,
    },
}

#[derive(Subcommand)]
enum IpAction {
    /// List allowed IPs for a user
    List { username: String },
    /// Add an allowed IP CIDR (e.g., 192.168.1.0/24)
    Add { username: String, cidr: String },
    /// Remove an allowed IP CIDR
    Del { username: String, cidr: String },
}

// --- State ---
#[derive(Clone)]
struct AppState {
    db: Pool<Sqlite>,
    // IP -> (Fail Count, Last Fail Time)
    login_attempts: Arc<DashMap<std::net::IpAddr, (u32, Instant)>>,
}

// --- Types ---
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    uid: i64,
    ver: i32, // Token Version for Revocation
    exp: usize,
}

#[derive(Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
}

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
    // 1. Parse CLI Args
    let cli = Cli::parse();

    // Generate Certs Helper
    if let Some(Commands::GenCert) = cli.command {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        fs::write("cert.pem", cert.serialize_pem()?)?;
        fs::write("key.pem", cert.serialize_private_key_pem())?;
        println!("Generated cert.pem and key.pem");
        return Ok(());
    }

    // Database Setup
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:sync.db".to_string());
    
    // 关键修复：设置如果文件不存在则自动创建
    let opts = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await
        .expect("Failed to connect to DB");

    // Init Tables (Updated Schema)
    // token_version: used to invalidate old tokens
    // quota_bytes: max storage per user
    let create_users_sql = format!("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, 
        username TEXT UNIQUE, 
        password_hash TEXT,
        token_version INTEGER DEFAULT 1,
        quota_bytes INTEGER DEFAULT {}
    )", DEFAULT_QUOTA_BYTES);

    sqlx::query(&create_users_sql).execute(&pool).await?;


    sqlx::query("CREATE TABLE IF NOT EXISTS files (user_id INTEGER, path TEXT, hash TEXT, mtime INTEGER, content BLOB, is_deleted BOOLEAN, PRIMARY KEY(user_id, path))")
        .execute(&pool).await?;
    // IP Whitelist table (New)
    sqlx::query("CREATE TABLE IF NOT EXISTS user_ips (user_id INTEGER, ip_cidr TEXT, PRIMARY KEY(user_id, ip_cidr))")
        .execute(&pool).await?;

    let state = Arc::new(AppState { 
        db: pool.clone(),
        login_attempts: Arc::new(DashMap::new())
    });

    // 3. Dispatch Commands
    match cli.command {
        Some(Commands::User { action }) => handle_user_cli(action, &pool).await?,
        Some(Commands::Status) => handle_status_cli(&pool).await?,
        Some(Commands::Serve { cert, key, port }) => run_server(state, cert, key, port).await?,
        _ => run_server(state, "cert.pem".to_string(), "key.pem".to_string(), 3443).await?,
    }

    Ok(())
}

// --- CLI Handlers ---

async fn handle_user_cli(action: UserAction, pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    match action {
        UserAction::List => {
            let rows = sqlx::query("SELECT id, username, quota_bytes FROM users").fetch_all(pool).await?;
            println!("{:<5} | {:<20} | Quota (MB)", "ID", "Username");
            println!("{:-<40}", "");
            for row in rows {
                let q: i64 = row.get("quota_bytes");
                println!("{:<5} | {:<20} | {:.2}", row.get::<i64, _>("id"), row.get::<String, _>("username"), q as f64 / 1024.0 / 1024.0);
            }
        }
        UserAction::Add { username, pass } => {
            let hash = hash(pass, DEFAULT_COST)?;
            match sqlx::query("INSERT INTO users (username, password_hash, quota_bytes) VALUES (?, ?, ?)")
                .bind(&username).bind(hash).bind(DEFAULT_QUOTA_BYTES).execute(pool).await {
                Ok(_) => println!("User '{}' created.", username),
                Err(_) => println!("Error creating user (likely exists)."),
            }
        }
        UserAction::Passwd { username, pass } => {
            let hash = hash(pass, DEFAULT_COST)?;
            let res = sqlx::query("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE username = ?")
                .bind(hash).bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 {
                println!("Password updated for '{}'. Sessions revoked.", username);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Kick { username } => {
            let res = sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE username = ?")
                .bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 {
                println!("User '{}' forced logout (sessions revoked).", username);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Quota { username, mb } => {
            let bytes = mb * 1024 * 1024;
            let res = sqlx::query("UPDATE users SET quota_bytes = ? WHERE username = ?")
                .bind(bytes).bind(&username).execute(pool).await?;
            if res.rows_affected() > 0 {
                println!("Quota updated for '{}'.", username);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Del { username } => {
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                let uid: i64 = r.get("id");
                sqlx::query("DELETE FROM files WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM user_ips WHERE user_id = ?").bind(uid).execute(pool).await?;
                sqlx::query("DELETE FROM users WHERE id = ?").bind(uid).execute(pool).await?;
                println!("User '{}' deleted.", username);
            } else {
                println!("User '{}' not found.", username);
            }
        }
        UserAction::Ip { action } => handle_ip_cli(action, pool).await?,
    }
    Ok(())
}

async fn handle_ip_cli(action: IpAction, pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    match action {
        IpAction::List { username } => {
             let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
             if let Some(r) = row {
                 let uid: i64 = r.get("id");
                 let ips = sqlx::query("SELECT ip_cidr FROM user_ips WHERE user_id = ?").bind(uid).fetch_all(pool).await?;
                 if ips.is_empty() {
                     println!("User '{}' has NO IP restrictions (Allowed from anywhere).", username);
                 } else {
                     println!("Allowed IPs for '{}':", username);
                     for ip_row in ips {
                         println!(" - {}", ip_row.get::<String, _>("ip_cidr"));
                     }
                 }
             } else {
                 println!("User not found.");
             }
        }
        IpAction::Add { username, cidr } => {
            // Validate CIDR format
            if cidr.parse::<IpNetwork>().is_err() {
                println!("Error: Invalid CIDR format (e.g., 192.168.1.1/32)");
                return Ok(());
            }
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                sqlx::query("INSERT OR IGNORE INTO user_ips (user_id, ip_cidr) VALUES (?, ?)").bind(r.get::<i64,_>("id")).bind(&cidr).execute(pool).await?;
                println!("IP CIDR {} added for user {}.", cidr, username);
            } else {
                println!("User not found.");
            }
        }
        IpAction::Del { username, cidr } => {
            let row = sqlx::query("SELECT id FROM users WHERE username = ?").bind(&username).fetch_optional(pool).await?;
            if let Some(r) = row {
                sqlx::query("DELETE FROM user_ips WHERE user_id = ? AND ip_cidr = ?").bind(r.get::<i64,_>("id")).bind(cidr).execute(pool).await?;
                println!("IP removed.");
            }
        }
    }
    Ok(())
}

async fn handle_status_cli(pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    let u: i64 = sqlx::query("SELECT COUNT(*) as c FROM users").fetch_one(pool).await?.get("c");
    let f: i64 = sqlx::query("SELECT COUNT(*) as c FROM files").fetch_one(pool).await?.get("c");
    let size: Option<i64> = sqlx::query("SELECT SUM(LENGTH(content)) as size FROM files").fetch_one(pool).await?.get("size");
    println!("--- Secure VFS Status ---");
    println!("Users:   {}", u);
    println!("Files:   {}", f);
    println!("Storage: {:.2} MB", size.unwrap_or(0) as f64 / 1024.0 / 1024.0);
    Ok(())
}

// --- Server & Handlers ---

async fn run_server(state: Arc<AppState>, cert: String, key: String, port: u16) -> anyhow::Result<()> {
    // Check files
    if !Path::new(&cert).exists() || !Path::new(&key).exists() {
        return Err(anyhow::anyhow!("Certificate files not found: {} or {}. Run 'cargo run -- gen-cert' to create test certs.", cert, key));
    }

    let config = RustlsConfig::from_pem_file(&cert, &key).await?;

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

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    // 修改日志输出，提示正确的客户端连接地址
    println!("HTTPS Server listening on internal interface: https://{}", addr);
    println!("-------------------------------------------------------");
    println!("For Client/Browser connection, please use:");
    println!("  -> https://127.0.0.1:{}", port);
    println!("  -> https://localhost:{}", port);
    println!("(Note: You must visit the URL in browser first to accept the self-signed certificate)");
    println!("-------------------------------------------------------");
    
    // Use axum_server for TLS
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    
    Ok(())
}

// --- HTTP Handlers ---
async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": SERVER_VERSION }))
}

async fn register_handler(State(state): State<Arc<AppState>>, Json(payload): Json<AuthPayload>) -> impl IntoResponse {
    let hash = hash(payload.password, DEFAULT_COST).unwrap();
    match sqlx::query("INSERT INTO users (username, password_hash, quota_bytes) VALUES (?, ?, ?)")
        .bind(payload.username).bind(hash).bind(DEFAULT_QUOTA_BYTES).execute(&state.db).await {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

async fn login_handler(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>, 
    Json(payload): Json<AuthPayload>
) -> impl IntoResponse {
    let ip = addr.ip();

    // 1. Rate Limit Check
    if let Some(entry) = state.login_attempts.get(&ip) {
        let (count, last_time) = *entry;
        if count >= LOGIN_FAIL_LIMIT {
            if last_time.elapsed() < Duration::from_secs(LOGIN_LOCKOUT_DURATION) {
                return Err(StatusCode::TOO_MANY_REQUESTS);
            } else {
                state.login_attempts.remove(&ip); // Reset after lockout
            }
        }
    }

    // 2. Auth
    let row = sqlx::query("SELECT id, password_hash, token_version FROM users WHERE username = ?")
        .bind(&payload.username).fetch_optional(&state.db).await.unwrap();

    if let Some(row) = row {
        let id: i64 = row.get("id");
        
        // Check IP Whitelist
        if !check_ip_allowed(&state.db, id, addr.ip()).await {
             return Err(StatusCode::FORBIDDEN);
        }

        let hash_str: String = row.get("password_hash");
        if verify(payload.password, &hash_str).unwrap_or(false) {
            // Success: Reset rate limit
            state.login_attempts.remove(&ip);

            // Generate Token with Version
            let ver: i32 = row.get("token_version");
            let claims = Claims {
                sub: payload.username,
                uid: id,
                ver, // Important
                exp: (chrono::Utc::now() + chrono::Duration::days(30)).timestamp() as usize,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET)).unwrap();
            return Ok(Json(AuthResponse { token }));
        }
    }

    // Fail: Increment rate limit
    let mut entry = state.login_attempts.entry(ip).or_insert((0, Instant::now()));
    entry.0 += 1;
    entry.1 = Instant::now();

    Err(StatusCode::UNAUTHORIZED)
}

async fn sync_check_handler(claims: Claims, State(state): State<Arc<AppState>>, Json(client_files): Json<Vec<FileMeta>>) -> impl IntoResponse {
    let server_rows = sqlx::query("SELECT path, hash, mtime, is_deleted FROM files WHERE user_id = ?").bind(claims.uid).fetch_all(&state.db).await.unwrap();
    
    let mut server_map: HashMap<String, FileMeta> = HashMap::new();
    for row in server_rows {
        let path: String = row.get("path");
        server_map.insert(path.clone(), FileMeta { path, hash: row.get("hash"), mtime: row.get("mtime"), is_deleted: row.get("is_deleted") });
    }

    let mut upload = Vec::new();
    let mut download = Vec::new();

    for c in &client_files {
        match server_map.get(&c.path) {
            Some(s) => {
                if s.hash != c.hash {
                    if c.mtime > s.mtime { upload.push(c.path.clone()); } 
                    else if s.mtime > c.mtime { download.push(FileMeta { path: s.path.clone(), hash: s.hash.clone(), mtime: s.mtime, is_deleted: s.is_deleted }); }
                }
                server_map.remove(&c.path);
            },
            None => { upload.push(c.path.clone()); }
        }
    }
    for (_, s) in server_map { download.push(FileMeta { path: s.path, hash: s.hash, mtime: s.mtime, is_deleted: s.is_deleted }); }
    Json(SyncDiff { files_to_upload: upload, files_to_download: download })
}

async fn upload_handler(claims: Claims, State(state): State<Arc<AppState>>, mut multipart: Multipart) -> impl IntoResponse {
    // Get Quota Info
    let user_row = sqlx::query("SELECT quota_bytes FROM users WHERE id = ?").bind(claims.uid).fetch_one(&state.db).await.unwrap();
    let quota: i64 = user_row.get("quota_bytes");

    while let Some(field) = multipart.next_field().await.unwrap() {
        let path = field.name().unwrap().to_string();
        
        // 1. Path Traversal & Sanity Check
        if path.contains("..") || path.starts_with("/") || path.contains("\\") {
            continue; // Skip dangerous paths
        }

        let data = field.bytes().await.unwrap();
        let new_size = data.len() as i64;
        
        // 2. Quota Check (Calculated smartly to allow overwrites)
        // Check current total usage
        let usage_row = sqlx::query("SELECT SUM(LENGTH(content)) as size FROM files WHERE user_id = ?").bind(claims.uid).fetch_one(&state.db).await.unwrap();
        let current_total: i64 = usage_row.get::<Option<i64>,_>("size").unwrap_or(0);
        
        // Check if this specific file exists to subtract its old size
        let file_row = sqlx::query("SELECT LENGTH(content) as size FROM files WHERE user_id = ? AND path = ?")
            .bind(claims.uid).bind(&path).fetch_optional(&state.db).await.unwrap();
        
        let old_size = file_row.map(|r| r.get::<i64, _>("size")).unwrap_or(0);

        // Logic: (Current Total - Old File Size) + New File Size <= Quota
        // We use saturate_sub to prevent underflow if DB is inconsistent
        let projected_usage = current_total.saturating_sub(old_size).saturating_add(new_size);

        if projected_usage > quota {
            return (StatusCode::INSUFFICIENT_STORAGE, "Quota Exceeded").into_response();
        }

        let hash = hex::encode(Sha256::digest(&data));
        let mtime = chrono::Utc::now().timestamp_millis();

        sqlx::query("INSERT OR REPLACE INTO files (user_id, path, hash, mtime, content, is_deleted) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(claims.uid).bind(path).bind(hash).bind(mtime).bind(data.to_vec()).bind(false).execute(&state.db).await.unwrap();
    }
    StatusCode::OK.into_response()
}

async fn download_handler(claims: Claims, State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let path = payload["path"].as_str().unwrap();
    // Path check again just in case
    if path.contains("..") { return StatusCode::BAD_REQUEST.into_response(); }

    let row = sqlx::query("SELECT content FROM files WHERE user_id = ? AND path = ?").bind(claims.uid).bind(path).fetch_optional(&state.db).await.unwrap();
    match row {
        Some(r) => (StatusCode::OK, r.get::<Vec<u8>, _>("content")).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// --- Auth & Security Helpers ---

// Logic: If user has ANY entries in user_ips, current IP must match one.
// If table has NO entries for user, allow all.
async fn check_ip_allowed(db: &Pool<Sqlite>, user_id: i64, user_ip: std::net::IpAddr) -> bool {
    let rows = sqlx::query("SELECT ip_cidr FROM user_ips WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();

    if rows.is_empty() {
        return true; // No restrictions
    }

    for row in rows {
        let cidr_str: String = row.get("ip_cidr");
        if let Ok(net) = cidr_str.parse::<IpNetwork>() {
            if net.contains(user_ip) {
                return true;
            }
        }
    }
    false // Restricted, and no match found
}

// Custom Extractor: Validates JWT AND IP Address
#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        // 1. Extract Token
        let header = parts.headers.get("Authorization").and_then(|v| v.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
        if !header.starts_with("Bearer ") { return Err(StatusCode::UNAUTHORIZED); }
        let token = &header[7..];

        // 2. Decode Token
        let claims = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::default())
            .map(|d| d.claims)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // 3. Extract IP
        let connect_info = parts.extensions.get::<ConnectInfo<SocketAddr>>().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let ip = connect_info.0.ip();

        // Check IP
        if !check_ip_allowed(&state.db, claims.uid, ip).await { return Err(StatusCode::FORBIDDEN); }

        // Check Token Version (Revocation)
        let row = sqlx::query("SELECT token_version FROM users WHERE id = ?").bind(claims.uid).fetch_optional(&state.db).await.unwrap();
        if let Some(r) = row {
            let current_ver: i32 = r.get("token_version");
            if claims.ver != current_ver { return Err(StatusCode::UNAUTHORIZED); } // Token is old
        } else {
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(claims)
    }
}