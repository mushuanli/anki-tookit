use serde::{Deserialize, Serialize};

/// A cloud provider: URL, auth token, and available model IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Model IDs available on this provider (used for UI suggestions).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
}

/// A tier routing rule: when the request model name contains any keyword (case-insensitive),
/// route to the given provider and substitute the given model ID.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TierRule {
    /// Trigger keywords (case-insensitive substring match).
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Provider name (references a Provider in the providers list).
    #[serde(default)]
    pub provider: String,
    /// Model ID to use on that provider.
    #[serde(default)]
    pub model: String,
}

impl TierRule {
    pub fn is_active(&self) -> bool {
        !self.provider.is_empty() && !self.model.is_empty()
    }

    fn matches(&self, model_lower: &str) -> bool {
        self.is_active()
            && self
                .keywords
                .iter()
                .any(|kw| !kw.is_empty() && model_lower.contains(kw.to_lowercase().as_str()))
    }
}

/// A named upstream configuration.
/// Defines tier-based routing to providers: high → mid → low, then default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    /// High tier (e.g. opus-class). Checked first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high: Option<TierRule>,
    /// Mid tier (e.g. sonnet-class). Checked second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mid: Option<TierRule>,
    /// Low tier (e.g. haiku-class). Checked third.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low: Option<TierRule>,
    /// Fallback provider when no tier keyword matches.
    #[serde(default)]
    pub default_provider: String,
    /// Fallback model when no tier keyword matches.
    #[serde(default)]
    pub default_model: String,
}

impl UpstreamConfig {
    /// Resolve (provider_name, target_model) for a given request model name.
    /// Returns empty strings if nothing is configured.
    pub fn resolve(&self, request_model: &str) -> (String, String) {
        let lower = request_model.to_lowercase();
        for rule in [&self.high, &self.mid, &self.low].into_iter().flatten() {
            if rule.matches(&lower) {
                return (rule.provider.clone(), rule.model.clone());
            }
        }
        (self.default_provider.clone(), self.default_model.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Currently active upstream name.
    #[serde(default)]
    pub active_upstream: String,

    /// Provider definitions (URL, token, models).
    #[serde(default)]
    pub providers: Vec<Provider>,

    /// Upstream routing configurations.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    #[serde(default = "default_retry_count")]
    pub retry_count: u32,
    #[serde(default = "default_request_capacity")]
    pub request_store_capacity: usize,
    #[serde(default = "default_mcp_capacity")]
    pub mcp_store_capacity: usize,
    #[serde(default = "default_hook_capacity")]
    pub hook_store_capacity: usize,
}

impl ProxyConfig {
    /// Ensure active_upstream points to an existing upstream.
    pub fn migrate(&mut self) {
        if !self.upstreams.iter().any(|u| u.name == self.active_upstream) {
            self.active_upstream = self
                .upstreams
                .first()
                .map(|u| u.name.clone())
                .unwrap_or_default();
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub proxy: ProxyConfig,
    pub server: ServerConfig,
    pub logging: LoggingConfig,
}

fn default_retry_count() -> u32 { 3 }
fn default_request_capacity() -> usize { 1000 }
fn default_mcp_capacity() -> usize { 500 }
fn default_hook_capacity() -> usize { 1000 }
fn default_http_port() -> u16 { 5000 }
fn default_proxy_port() -> u16 { 8888 }
fn default_mcp_proxy_port() -> u16 { 9999 }
fn default_listen_addr() -> String { "127.0.0.1".into() }
fn default_log_level() -> String { "info".into() }

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig {
                active_upstream: String::new(),
                providers: Vec::new(),
                upstreams: Vec::new(),
                retry_count: default_retry_count(),
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
