// src/server/listener.rs

use crate::common::config::CONFIG;
use crate::error::{AppError, Result};
use crate::server::db::Database;
use crate::server::handler;
use crate::server::worker::AiTask;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// TLS related imports
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::TlsAcceptor;

// 辅助函数：从文件加载 TLS 配置
fn load_tls_config() -> Result<Arc<ServerConfig>> {
    let cert_path = CONFIG.server.ssl_cert.as_ref().ok_or_else(|| {
        AppError::ConfigError("ssl_cert path is missing in config, but TLS is implied".into())
    })?;
    let key_path = CONFIG.server.ssl_key.as_ref().ok_or_else(|| {
        AppError::ConfigError("ssl_key path is missing in config, but TLS is implied".into())
    })?;

    // Load certificate chain
    let cert_file = File::open(cert_path).map_err(|e| AppError::ConfigError(format!("Failed to open cert file '{}': {}", cert_path, e)))?;
    let mut reader = BufReader::new(cert_file);
    let cert_chain = certs(&mut reader)
        .map_err(|e| AppError::ConfigError(format!("Failed to parse cert file '{}': {}", cert_path, e)))?
        .into_iter()
        .map(Certificate)
        .collect();

    // Load private key
    let key_file = File::open(key_path).map_err(|e| AppError::ConfigError(format!("Failed to open key file '{}': {}", key_path, e)))?;
    let mut reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut reader)
        .map_err(|e| AppError::ConfigError(format!("Failed to parse key file '{}': {}", key_path, e)))?;
    if keys.is_empty() {
        return Err(AppError::ConfigError(format!("No PKCS8 private key found in '{}'", key_path)));
    }
    let private_key = PrivateKey(keys.remove(0));

    // Create ServerConfig
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| AppError::ConfigError(format!("Failed to create TLS config: {}", e)))?;

    Ok(Arc::new(config))
}


pub async fn run(db: Arc<Database>, tx: mpsc::Sender<AiTask>) -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:9501").await?;

    if CONFIG.server.ssl_cert.is_some() && CONFIG.server.ssl_key.is_some() {
        // --- TLS Mode ---
        info!("TLS is enabled. Loading certificate and key...");
        let tls_config = load_tls_config()?;
        let acceptor = TlsAcceptor::from(tls_config);
        info!("Server listening with TLS on 0.0.0.0:9501");

        loop {
            let (stream, addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            debug!("Accepted raw connection from: {}, performing TLS handshake...", addr);

            let db_clone = db.clone();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        info!("TLS handshake successful for {}", addr);
                        if let Err(e) =
                            handler::handle_connection(tls_stream, addr, db_clone, tx_clone).await
                        {
                            error!("Error handling TLS connection from {}: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        warn!("TLS handshake error from {}: {}", addr, e);
                    }
                }
            });
        }
    } else {
        // --- Plain TCP Mode ---
        info!("TLS is not configured. Server listening without encryption on 0.0.0.0:9501");
        loop {
            let (stream, addr) = listener.accept().await?;
            info!("Accepted TCP connection from: {}", addr);

            let db_clone = db.clone();
            let tx_clone = tx.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handler::handle_connection(stream, addr, db_clone, tx_clone).await
                {
                    error!("Error handling TCP connection from {}: {}", addr, e);
                }
            });
        }
    }
}
