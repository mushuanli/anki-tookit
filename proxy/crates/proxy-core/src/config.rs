use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_api_target")]
    pub api_target: String,
    #[serde(default = "default_request_capacity")]
    pub request_store_capacity: usize,
    #[serde(default = "default_mcp_capacity")]
    pub mcp_store_capacity: usize,
    #[serde(default = "default_hook_capacity")]
    pub hook_store_capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_mcp_proxy_port")]
    pub mcp_proxy_port: u16,
    #[serde(default = "default_listen_addr")]
    pub listen_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_api_target() -> String {
    "https://api.anthropic.com".into()
}
fn default_request_capacity() -> usize {
    1000
}
fn default_mcp_capacity() -> usize {
    500
}
fn default_hook_capacity() -> usize {
    1000
}
fn default_http_port() -> u16 {
    5000
}
fn default_proxy_port() -> u16 {
    8888
}
fn default_mcp_proxy_port() -> u16 {
    9999
}
fn default_listen_addr() -> String {
    "127.0.0.1".into()
}
fn default_log_level() -> String {
    "info".into()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig {
                api_target: default_api_target(),
                request_store_capacity: default_request_capacity(),
                mcp_store_capacity: default_mcp_capacity(),
                hook_store_capacity: default_hook_capacity(),
            },
            server: ServerConfig {
                http_port: default_http_port(),
                proxy_port: default_proxy_port(),
                mcp_proxy_port: default_mcp_proxy_port(),
                listen_address: default_listen_addr(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
            },
        }
    }
}
