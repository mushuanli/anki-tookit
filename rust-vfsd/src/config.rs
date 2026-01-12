// src/config.rs

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_url")]
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
    #[serde(default = "default_jwt_expiry")]
    pub jwt_expiry_hours: i64,
    #[serde(default = "default_refresh_expiry")]
    pub refresh_expiry_days: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    #[serde(default = "default_chunk_threshold")]
    pub chunk_threshold: usize,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    pub allowed_extensions: Option<Vec<String>>,
    pub blocked_extensions: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    #[default]
    Local,
    S3,
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageType::Local => write!(f, "local"),
            StorageType::S3 => write!(f, "s3"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub storage_type: StorageType,
    #[serde(default = "default_local_path")]
    pub local_path: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: Option<String>,
    pub s3_prefix: Option<String>,
}

// 默认值函数
fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_db_url() -> String {
    "postgres://postgres:password@localhost:5432/vfs_sync".to_string()
}
fn default_max_connections() -> u32 {
    10
}
fn default_jwt_secret() -> String {
    "change-this-secret-in-production".to_string()
}
fn default_jwt_expiry() -> i64 {
    24
}
fn default_refresh_expiry() -> i64 {
    30
}
fn default_max_packet_size() -> usize {
    10 * 1024 * 1024
}
fn default_chunk_size() -> usize {
    1024 * 1024
}
fn default_chunk_threshold() -> usize {
    5 * 1024 * 1024
}
fn default_max_file_size() -> usize {
    100 * 1024 * 1024
}
fn default_local_path() -> Option<String> {
    Some("./data".to_string())
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            workers: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: default_db_url(),
            max_connections: default_max_connections(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: default_jwt_secret(),
            jwt_expiry_hours: default_jwt_expiry(),
            refresh_expiry_days: default_refresh_expiry(),
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            max_packet_size: default_max_packet_size(),
            chunk_size: default_chunk_size(),
            chunk_threshold: default_chunk_threshold(),
            max_file_size: default_max_file_size(),
            allowed_extensions: None,
            blocked_extensions: Some(vec!["exe".to_string(), "dll".to_string()]),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::Local,
            local_path: default_local_path(),
            s3_bucket: None,
            s3_region: None,
            s3_prefix: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            sync: SyncConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl Config {
    pub fn load() -> AppResult<Arc<Self>> {
        // 加载 .env 文件
        dotenvy::dotenv().ok();

        let config = config::Config::builder()
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false))
            .add_source(
                config::Environment::with_prefix("VFS")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()
            .map_err(|e| AppError::ConfigError(e.to_string()))?;

        let cfg: Config = config
            .try_deserialize()
            .map_err(|e| AppError::ConfigError(e.to_string()))?;

        Ok(Arc::new(cfg))
    }
}
