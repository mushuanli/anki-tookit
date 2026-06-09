use serde::de;
use serde::{Deserialize, Serialize};

/// Price and metadata for a single model on a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    /// Input token price in CNY per million tokens. Defaults to 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_per_million_input: Option<f64>,
    /// Output token price in CNY per million tokens. Defaults to 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_per_million_output: Option<f64>,
}

impl ModelInfo {
    pub fn new(id: String) -> Self {
        Self { id, price_per_million_input: None, price_per_million_output: None }
    }
}

/// A cloud provider: URL, auth token, and available model definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Model definitions. Deserialization accepts both strings (old format) and
    /// full `{id, price_per_million_input, price_per_million_output}` objects.
    #[serde(default, deserialize_with = "deserialize_models", skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<ModelInfo>,
}

/// Accepts either `"model-id"` (string) or `{id = "model-id", ...}` (object).
fn deserialize_models<'de, D: de::Deserializer<'de>>(d: D) -> Result<Vec<ModelInfo>, D::Error> {
    let raw: Vec<serde_json::Value> = Vec::deserialize(d)?;
    raw.into_iter()
        .map(|v| match v {
            serde_json::Value::String(s) => Ok(ModelInfo::new(s)),
            _ => serde_json::from_value(v).map_err(de::Error::custom),
        })
        .collect()
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
    /// A tier is active only if a provider is selected AND at least one
    /// non-empty keyword is configured.
    pub fn is_active(&self) -> bool {
        !self.provider.is_empty()
            && self.keywords.iter().any(|kw| !kw.is_empty())
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
    /// If a tier matches but its `model` is empty, the original request model
    /// is passed through unchanged (useful when only routing to a different
    /// provider without renaming the model).
    /// Returns empty strings if nothing is configured.
    pub fn resolve(&self, request_model: &str) -> (String, String) {
        let lower = request_model.to_lowercase();
        for rule in [&self.high, &self.mid, &self.low].into_iter().flatten() {
            if rule.matches(&lower) {
                let target = if rule.model.is_empty() {
                    request_model.to_string()
                } else {
                    rule.model.clone()
                };
                tracing::info!(
                    target = %target,
                    provider = %rule.provider,
                    request_model = %request_model,
                    "upstream tier matched"
                );
                return (rule.provider.clone(), target);
            }
        }
        tracing::info!(
            provider = %self.default_provider,
            model = %self.default_model,
            request_model = %request_model,
            has_high = self.high.is_some(),
            has_mid = self.mid.is_some(),
            has_low = self.low.is_some(),
            "upstream fallback to default"
        );
        (self.default_provider.clone(), self.default_model.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Currently active upstream name.
    #[serde(default)]
    pub active_upstream: String,

    /// Effort level override injected into proxied requests.
    /// "auto" means pass through the original value unchanged.
    #[serde(default = "default_effort")]
    pub active_effort: String,

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
    /// Max sessions to keep. Oldest deleted when exceeded. 0 = unlimited.
    #[serde(default = "default_max_sessions")]
    pub session_max_count: u32,
    /// Delete requests older than this many hours. 0 = never clean.
    #[serde(default = "default_request_retention_hours")]
    pub request_retention_hours: u32,
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

/// Runtime retention settings (mirrors ProxyConfig fields, but kept in a RwLock).
#[derive(Debug, Clone)]
pub struct Retention {
    pub session_max_count: u32,
    pub request_retention_hours: u32,
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

fn default_effort() -> String { "auto".into() }
fn default_retry_count() -> u32 { 3 }
fn default_request_capacity() -> usize { 1000 }
fn default_mcp_capacity() -> usize { 500 }
fn default_hook_capacity() -> usize { 1000 }
fn default_max_sessions() -> u32 { 20 }
fn default_request_retention_hours() -> u32 { 8 }
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
                active_effort: default_effort(),
                providers: Vec::new(),
                upstreams: Vec::new(),
                retry_count: default_retry_count(),
                request_store_capacity: default_request_capacity(),
                mcp_store_capacity: default_mcp_capacity(),
                hook_store_capacity: default_hook_capacity(),
                session_max_count: default_max_sessions(),
                request_retention_hours: default_request_retention_hours(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_config_toml_roundtrip() {
        // Simulate the exact format persist_config() writes via toml::Value API
        let cfg = UpstreamConfig {
            name: "production".into(),
            high: Some(TierRule {
                keywords: vec!["opus".into()],
                provider: "deepseek".into(),
                model: "".into(),
            }),
            mid: Some(TierRule {
                keywords: vec!["sonnet".into()],
                provider: "deepseek".into(),
                model: "deepseek-v4-pro".into(),
            }),
            low: None,
            default_provider: "deepseek".into(),
            default_model: "deepseek-v4-pro".into(),
        };

        // Round 1: serde serialize → toml string
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        println!("=== Serde TOML ===\n{}", toml_str);

        // Round 2: parse back with serde
        let cfg2: UpstreamConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(cfg2.name, "production");
        assert!(cfg2.high.is_some());
        assert_eq!(cfg2.high.as_ref().unwrap().keywords, vec!["opus"]);
        assert!(cfg2.high.as_ref().unwrap().model.is_empty());
        assert!(cfg2.mid.is_some());
        assert_eq!(cfg2.mid.as_ref().unwrap().model, "deepseek-v4-pro");
        assert!(cfg2.low.is_none());

        // Round 3: build via toml::Value API (simulating persist_config)
        fn tier_rule_to_toml_value(rule: &TierRule) -> toml::Value {
            let mut t = toml::value::Table::new();
            t.insert("keywords".into(), toml::Value::Array(
                rule.keywords.iter().map(|s| toml::Value::String(s.clone())).collect()
            ));
            t.insert("provider".into(), toml::Value::String(rule.provider.clone()));
            t.insert("model".into(), toml::Value::String(rule.model.clone()));
            toml::Value::Table(t)
        }

        let mut upstream_table = toml::value::Table::new();
        upstream_table.insert("name".into(), toml::Value::String("production".into()));
        upstream_table.insert("high".into(), tier_rule_to_toml_value(cfg.high.as_ref().unwrap()));
        upstream_table.insert("mid".into(), tier_rule_to_toml_value(cfg.mid.as_ref().unwrap()));
        upstream_table.insert("default_provider".into(), toml::Value::String("deepseek".into()));
        upstream_table.insert("default_model".into(), toml::Value::String("deepseek-v4-pro".into()));

        let mut doc = toml::value::Table::new();
        let mut proxy = toml::value::Table::new();
        proxy.insert("upstreams".into(), toml::Value::Array(vec![toml::Value::Table(upstream_table)]));
        doc.insert("proxy".into(), toml::Value::Table(proxy));

        let toml_str2 = toml::to_string_pretty(&doc).unwrap();
        println!("=== Value-API TOML ===\n{}", toml_str2);

        // Parse back via wrapper structs (same as main.rs Config → ProxyConfig)
        #[derive(Deserialize)]
        struct DocProxy { upstreams: Vec<UpstreamConfig> }
        #[derive(Deserialize)]
        struct Doc { proxy: DocProxy }
        let doc3: Doc = toml::from_str(&toml_str2).unwrap();
        assert_eq!(doc3.proxy.upstreams.len(), 1);
        let u = &doc3.proxy.upstreams[0];
        assert_eq!(u.name, "production");
        assert!(u.high.is_some());
        assert_eq!(u.high.as_ref().unwrap().keywords, vec!["opus"]);
        assert!(u.mid.is_some());
        assert!(u.low.is_none());
    }

    #[test]
    fn tier_matching_works() {
        let cfg = UpstreamConfig {
            name: "test".into(),
            high: Some(TierRule {
                keywords: vec!["opus".into()],
                provider: "p-high".into(),
                model: "m-high".into(),
            }),
            mid: Some(TierRule {
                keywords: vec!["sonnet".into()],
                provider: "p-mid".into(),
                model: "m-mid".into(),
            }),
            low: None,
            default_provider: "p-default".into(),
            default_model: "m-default".into(),
        };
        assert_eq!(cfg.resolve("sonnet-v4-pro"), ("p-mid".into(), "m-mid".into()));
        assert_eq!(cfg.resolve("opus-v4-pro[1m]"), ("p-high".into(), "m-high".into()));
        assert_eq!(cfg.resolve("gpt-4"), ("p-default".into(), "m-default".into()));
    }

    #[test]
    fn tier_pass_through_model() {
        let cfg = UpstreamConfig {
            name: "test".into(),
            high: Some(TierRule {
                keywords: vec!["opus".into()],
                provider: "p-high".into(),
                model: "".into(),
            }),
            mid: None,
            low: None,
            default_provider: "".into(),
            default_model: "".into(),
        };
        assert_eq!(cfg.resolve("opus-v4-pro[1m]"), ("p-high".into(), "opus-v4-pro[1m]".into()));
    }
}
