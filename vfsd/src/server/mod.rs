// src/server/mod.rs
pub mod handlers;
pub mod auth;
pub mod logger; // Added logger module

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use axum::middleware;
use std::sync::Arc;
use std::net::SocketAddr;
use std::path::Path;
use axum_server::tls_rustls::RustlsConfig;
use crate::types::{AppState, MAX_UPLOAD_MB};
use handlers::*;
use logger::access_log_middleware;

pub async fn run_server(state: Arc<AppState>, cert: String, key: String, port: u16) -> anyhow::Result<()> {
    if !Path::new(&cert).exists() || !Path::new(&key).exists() {
        // Check for default certs first, then error out if missing
        if !Path::new("cert.pem").exists() || !Path::new("key.pem").exists() {
             return Err(anyhow::anyhow!("TLS certificates (cert.pem and key.pem) not found. Please run 'gen-cert' first or provide them via --cert and --key arguments."));
        }
        // If default certs exist but were not explicitly passed, use them.
        // This block is mainly for the default case.
    }

    let cert_path = Path::new(&cert);
    let key_path = Path::new(&key);

    if !cert_path.exists() || !key_path.exists() {
         return Err(anyhow::anyhow!("Specified TLS certificates not found: cert='{}', key='{}'", cert, key));
    }

    let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

    // Initialize the Axum router
    let app = Router::new()
        .route("/api/version", get(version_handler))
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/sync/check", post(sync_check_handler))
        .route("/api/sync/upload", post(upload_handler))
        .route("/api/sync/download", post(download_handler))
        
        // Middleware Stack (执行顺序是 从下往上 / 从外向内)
        // 1. CORS 必须在最外层，处理 OPTIONS 请求，不通过 Auth
        .layer(CorsLayer::permissive()) 
        // 2. BodyLimit
        .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_MB * 1024 * 1024))
        // 3. 日志记录
        .layer(middleware::from_fn_with_state(state.clone(), access_log_middleware))
        
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    println!("Starting HTTPS server on port {}...", port);
    println!("TLS certificates used: cert='{}', key='{}'", cert, key);
    
    // Start the HTTPS server
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    
    Ok(())
}
