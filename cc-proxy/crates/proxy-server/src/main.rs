mod api;
mod mcp;
mod proxy;
mod tee;
mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tracing_subscriber::EnvFilter;

use proxy_core::config::{AppConfig, Provider, TierRule, UpstreamConfig};
use proxy_core::models::{ProviderInfo, TierRuleInfo, UpstreamInfo, WsMessage};
use proxy_core::Database;
use tee::TeeWriter;

pub struct AppState {
    pub config: AppConfig,
    pub config_path: String,
    pub db: Database,
    pub mcp_destination: RwLock<Option<String>>,
    pub providers: RwLock<Vec<Provider>>,
    pub upstreams: RwLock<Vec<UpstreamConfig>>,
    pub active_upstream: RwLock<String>,
    pub tee_writer: TeeWriter,
    pub broadcaster: broadcast::Sender<WsMessage>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig, config_path: String) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        let enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let providers = config.proxy.providers.clone();
        let upstreams = config.proxy.upstreams.clone();
        let active_name = config.proxy.active_upstream.clone();

        let db_path = PathBuf::from("data.db");
        let db = Database::open(db_path.to_str().unwrap())
            .expect("Failed to open SQLite database");

        Self {
            db,
            mcp_destination: RwLock::new(None),
            providers: RwLock::new(providers),
            upstreams: RwLock::new(upstreams),
            active_upstream: RwLock::new(active_name),
            tee_writer: TeeWriter::new(enabled, PathBuf::from("captures")),
            broadcaster: tx,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .expect("Failed to create reqwest client"),
            config,
            config_path,
        }
    }

    pub fn broadcast_send(
        &self,
        msg: WsMessage,
    ) -> Result<usize, broadcast::error::SendError<WsMessage>> {
        self.broadcaster.send(msg)
    }

    pub fn broadcast_subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.broadcaster.subscribe()
    }

    pub async fn provider_info_list(&self) -> Vec<ProviderInfo> {
        self.providers
            .read()
            .await
            .iter()
            .map(|p| ProviderInfo {
                name: p.name.clone(),
                url: p.url.clone(),
                has_token: p.token.is_some(),
                models: p.models.clone(),
            })
            .collect()
    }

    pub async fn upstream_info_list(&self) -> Vec<UpstreamInfo> {
        let active = self.active_upstream.read().await.clone();
        self.upstreams
            .read()
            .await
            .iter()
            .map(|u| UpstreamInfo {
                name: u.name.clone(),
                active: u.name == active,
                high: u.high.as_ref().map(tier_rule_to_info),
                mid: u.mid.as_ref().map(tier_rule_to_info),
                low: u.low.as_ref().map(tier_rule_to_info),
                default_provider: u.default_provider.clone(),
                default_model: u.default_model.clone(),
            })
            .collect()
    }

    pub async fn upstream_changed_msg(&self) -> WsMessage {
        WsMessage::UpstreamChanged {
            active_upstream: self.active_upstream.read().await.clone(),
            upstreams: self.upstream_info_list().await,
            providers: self.provider_info_list().await,
        }
    }

    /// Persist providers and upstreams to config.toml.
    pub async fn persist_config(&self) {
        let providers = self.providers.read().await.clone();
        let upstreams = self.upstreams.read().await.clone();
        let active = self.active_upstream.read().await.clone();

        let content = match std::fs::read_to_string(&self.config_path) {
            Ok(c) => c,
            Err(_) => {
                tracing::error!("Failed to read config.toml for persistence");
                return;
            }
        };
        let mut doc: toml::Value = match toml::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Failed to parse config.toml: {}", e);
                return;
            }
        };
        let proxy = doc
            .get_mut("proxy")
            .and_then(|v| v.as_table_mut())
            .expect("config.toml missing [proxy] section");

        // Persist providers
        let prov_arr: Vec<toml::Value> = providers.iter().map(provider_to_toml).collect();
        proxy.insert("providers".into(), toml::Value::Array(prov_arr));

        // Persist upstreams
        let up_arr: Vec<toml::Value> = upstreams.iter().map(upstream_to_toml).collect();
        proxy.insert("upstreams".into(), toml::Value::Array(up_arr));
        proxy.insert("active_upstream".into(), toml::Value::String(active));

        // Remove legacy fields
        proxy.remove("api_target");

        match toml::to_string_pretty(&doc) {
            Ok(out) => {
                if let Err(e) = std::fs::write(&self.config_path, out) {
                    tracing::error!("Failed to write config.toml: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize config.toml: {}", e),
        }
    }
}

fn tier_rule_to_info(rule: &TierRule) -> TierRuleInfo {
    TierRuleInfo {
        keywords: rule.keywords.clone(),
        provider: rule.provider.clone(),
        model: rule.model.clone(),
    }
}

fn provider_to_toml(p: &Provider) -> toml::Value {
    let mut t = toml::value::Table::new();
    t.insert("name".into(), toml::Value::String(p.name.clone()));
    t.insert("url".into(), toml::Value::String(p.url.clone()));
    if let Some(ref token) = p.token {
        t.insert("token".into(), toml::Value::String(token.clone()));
    }
    if !p.models.is_empty() {
        // If any model has pricing, write all as array of tables;
        // otherwise write as plain strings for compactness.
        let has_pricing = p.models.iter().any(|m| {
            m.price_per_million_input.is_some() || m.price_per_million_output.is_some()
        });
        if has_pricing {
            let arr: Vec<toml::Value> = p.models.iter().map(model_to_toml).collect();
            t.insert("models".into(), toml::Value::Array(arr));
        } else {
            let arr: Vec<toml::Value> = p
                .models
                .iter()
                .map(|m| toml::Value::String(m.id.clone()))
                .collect();
            t.insert("models".into(), toml::Value::Array(arr));
        }
    }
    toml::Value::Table(t)
}

fn model_to_toml(m: &proxy_core::config::ModelInfo) -> toml::Value {
    let mut t = toml::value::Table::new();
    t.insert("id".into(), toml::Value::String(m.id.clone()));
    if let Some(v) = m.price_per_million_input {
        t.insert("price_per_million_input".into(), toml::Value::Float(v));
    }
    if let Some(v) = m.price_per_million_output {
        t.insert("price_per_million_output".into(), toml::Value::Float(v));
    }
    toml::Value::Table(t)
}

fn tier_rule_to_toml(rule: &TierRule) -> toml::Value {
    let mut t = toml::value::Table::new();
    t.insert(
        "keywords".into(),
        toml::Value::Array(rule.keywords.iter().map(|s| toml::Value::String(s.clone())).collect()),
    );
    t.insert("provider".into(), toml::Value::String(rule.provider.clone()));
    t.insert("model".into(), toml::Value::String(rule.model.clone()));
    toml::Value::Table(t)
}

fn upstream_to_toml(u: &UpstreamConfig) -> toml::Value {
    let mut t = toml::value::Table::new();
    t.insert("name".into(), toml::Value::String(u.name.clone()));
    if let Some(ref h) = u.high {
        t.insert("high".into(), tier_rule_to_toml(h));
    }
    if let Some(ref m) = u.mid {
        t.insert("mid".into(), tier_rule_to_toml(m));
    }
    if let Some(ref l) = u.low {
        t.insert("low".into(), tier_rule_to_toml(l));
    }
    if !u.default_provider.is_empty() {
        t.insert("default_provider".into(), toml::Value::String(u.default_provider.clone()));
    }
    if !u.default_model.is_empty() {
        t.insert("default_model".into(), toml::Value::String(u.default_model.clone()));
    }
    toml::Value::Table(t)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());
    let mut config: AppConfig = match std::fs::read_to_string(&config_path) {
        Ok(content) => toml::from_str(&content)?,
        Err(_) => {
            tracing::warn!("Config file '{}' not found, using defaults", config_path);
            AppConfig::default()
        }
    };
    config.proxy.migrate();

    let state = Arc::new(AppState::new(config.clone(), config_path));

    // ── Startup diagnostics ──
    tracing::info!("{} provider(s) configured", config.proxy.providers.len());
    for p in &config.proxy.providers {
        tracing::info!(
            "  provider '{}' → {} (models: {})",
            p.name,
            p.url,
            p.models.len()
        );
    }
    tracing::info!(
        "{} upstream(s) configured, active = '{}'",
        config.proxy.upstreams.len(),
        config.proxy.active_upstream,
    );
    for u in &config.proxy.upstreams {
        let tier_info = |rule: &Option<TierRule>| -> String {
            match rule {
                Some(r) => {
                    let active = if r.is_active() { "" } else { " (inactive)" };
                    format!("{}→{}/{}{}", r.keywords.join(","), r.provider, r.model, active)
                }
                None => "-".into(),
            }
        };
        tracing::info!(
            "  upstream '{}' H:[{}] M:[{}] L:[{}] default→{}/{}",
            u.name,
            tier_info(&u.high),
            tier_info(&u.mid),
            tier_info(&u.low),
            u.default_provider,
            u.default_model,
        );
    }

    let listen_addr = &config.server.listen_address;

    let dashboard_router = api::build_router(state.clone());
    let proxy_router = proxy::build_router(state.clone());
    let mcp_router = mcp::build_router(state.clone());

    let dashboard_addr: SocketAddr =
        format!("{}:{}", listen_addr, config.server.http_port).parse()?;
    let proxy_addr: SocketAddr =
        format!("{}:{}", listen_addr, config.server.proxy_port).parse()?;
    let mcp_addr: SocketAddr =
        format!("{}:{}", listen_addr, config.server.mcp_proxy_port).parse()?;

    tracing::info!("Dashboard: http://{}", dashboard_addr);
    tracing::info!("Anthropic proxy: http://{}", proxy_addr);
    tracing::info!("MCP proxy: http://{}", mcp_addr);

    let dashboard_listener = TcpListener::bind(dashboard_addr).await?;
    let proxy_listener = TcpListener::bind(proxy_addr).await?;
    let mcp_listener = TcpListener::bind(mcp_addr).await?;

    let d_handle = tokio::spawn(async move {
        axum::serve(dashboard_listener, dashboard_router)
            .await
            .expect("Dashboard server failed");
    });
    let p_handle = tokio::spawn(async move {
        axum::serve(proxy_listener, proxy_router)
            .await
            .expect("Proxy server failed");
    });
    let m_handle = tokio::spawn(async move {
        axum::serve(mcp_listener, mcp_router)
            .await
            .expect("MCP proxy server failed");
    });

    tokio::try_join!(d_handle, p_handle, m_handle)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!(e))
}
