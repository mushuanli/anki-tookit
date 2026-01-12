// src/config.rs

use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub sync: SyncConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub jwt_expiry_hours: i64,
    pub refresh_expiry_days: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    pub max_packet_size: usize,
    pub chunk_size: usize,
    pub chunk_threshold: usize,
    pub max_file_size: usize,
    pub allowed_extensions: Option<Vec<String>>,
    pub blocked_extensions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub storage_type: StorageType,
    pub local_path: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    Local,
    S3,
}

impl Config {
    pub fn load() -> anyhow::Result<Arc<Self>> {
        dotenvy::dotenv().ok();
        
        let config = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(config::Environment::with_prefix("VFS"))
            .build()?;
        
        let config: Config = config.try_deserialize()?;
        Ok(Arc::new(config))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                workers: None,
            },
            database: DatabaseConfig {
                url: "sqlite:vfs_sync.db".to_string(),
                max_connections: 10,
            },
            auth: AuthConfig {
                jwt_secret: "change-me-in-production".to_string(),
                jwt_expiry_hours: 24,
                refresh_expiry_days: 30,
            },
            sync: SyncConfig {
                max_packet_size: 10 * 1024 * 1024, // 10MB
                chunk_size: 1024 * 1024,           // 1MB
                chunk_threshold: 5 * 1024 * 1024,  // 5MB
                max_file_size: 100 * 1024 * 1024,  // 100MB
                allowed_extensions: None,
                blocked_extensions: None,
            },
            storage: StorageConfig {
                storage_type: StorageType::Local,
                local_path: Some("./data".to_string()),
                s3_bucket: None,
                s3_region: None,
            },
        }
    }
}
