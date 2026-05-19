use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
}

/// A named upstream API target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTarget {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    // legacy field — migrated into upstreams on startup
    #[serde(default)]
    pub api_target: String,

    #[serde(default)]
    pub active_upstream: String,

    #[serde(default)]
    pub upstreams: Vec<UpstreamTarget>,

    #[serde(default = "default_request_capacity")]
    pub request_store_capacity: usize,
    #[serde(default = "default_mcp_capacity")]
    pub mcp_store_capacity: usize,
    #[serde(default = "default_hook_capacity")]
    pub hook_store_capacity: usize,
}

impl ProxyConfig {
    /// Run once at startup: migrate legacy `api_target` into the upstreams list.
    pub fn migrate(&mut self) {
        if self.upstreams.is_empty() && !self.api_target.is_empty() {
            self.upstreams.push(UpstreamTarget {
                name: "default".into(),
                url: self.api_target.trim_end_matches('/').to_string(),
                token: None,
            });
            self.active_upstream = "default".into();
            self.api_target.clear();
        }
        // Ensure active_upstream points to a valid upstream
        if !self.upstreams.iter().any(|u| u.name == self.active_upstream) {
            self.active_upstream = self
                .upstreams
                .first()
                .map(|u| u.name.clone())
                .unwrap_or_default();
        }
    }

    pub fn active_upstream_url(&self) -> String {
        self.upstreams
            .iter()
            .find(|u| u.name == self.active_upstream)
            .map(|u| u.url.clone())
            .unwrap_or_default()
    }
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
                api_target: String::new(),
                active_upstream: String::new(),
                upstreams: Vec::new(),
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
