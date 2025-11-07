// src/common/config.rs

use serde::Deserialize;
use crate::error::{AppError, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use once_cell::sync::Lazy;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub concurrency: ConcurrencyConfig,
}

// NEW: Represents a single AI provider's configuration
#[derive(Debug, Deserialize, Clone)]
pub struct AiServerDetail {
    #[serde(rename = "type")]
    pub server_type: String, // "openai", "gemini", etc.
    pub url: String,
    pub token: String,
    #[serde(default)]
    pub model_list: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    // MODIFIED: Top-level `type` is removed
    pub servers: HashMap<String, AiServerDetail>,
    pub default: String, 
    
    pub ssl_cert: Option<String>,
    pub ssl_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub chat_dir: String,
    pub attachment_dir: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ConcurrencyConfig {
    pub max_concurrent_tasks: usize,
}

// Global static config, loaded once.
pub static CONFIG: Lazy<Config> = Lazy::new(|| {
    Config::from_file("data/config.yaml").expect("Failed to load configuration from data/config.yaml.")
});

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| AppError::ConfigError(format!("Failed to read config file '{}': {}", path.as_ref().display(), e)))?;
        
        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| AppError::ConfigError(format!("Failed to parse config file '{}': {}", path.as_ref().display(), e)))?;

        // Create data directories if they don't exist
        fs::create_dir_all(&config.storage.chat_dir)?;
        fs::create_dir_all(&config.storage.attachment_dir)?;
        if let Some(parent) = Path::new(&config.database.path).parent() {
             fs::create_dir_all(parent)?;
        }
            
        Ok(config)
    }
}
