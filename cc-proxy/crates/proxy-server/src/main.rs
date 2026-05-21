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

use proxy_core::config::{AppConfig, UpstreamTarget};
use proxy_core::models::{HookEvent, ProxiedRequest, Session, UpstreamInfo, WsMessage};
use proxy_core::RingBuffer;
use tee::TeeWriter;

pub struct AppState {
    pub config: AppConfig,
    pub config_path: String,
    pub request_store: RingBuffer<ProxiedRequest>,
    pub hook_store: RingBuffer<HookEvent>,
    pub mcp_store: RingBuffer<ProxiedRequest>,
    pub mcp_destination: RwLock<Option<String>>,
    pub upstream_target: RwLock<String>,
    pub upstreams: RwLock<Vec<UpstreamTarget>>,
    pub active_upstream: RwLock<String>,
    pub sessions: RwLock<Vec<Session>>,
    pub tee_writer: TeeWriter,
    pub broadcaster: broadcast::Sender<WsMessage>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig, config_path: String) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        let enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let active_url = config.proxy.active_upstream_url();
        let upstreams = config.proxy.upstreams.clone();
        let active_name = config.proxy.active_upstream.clone();
        Self {
            request_store: RingBuffer::new(config.proxy.request_store_capacity),
            hook_store: RingBuffer::new(config.proxy.hook_store_capacity),
            mcp_store: RingBuffer::new(config.proxy.mcp_store_capacity),
            mcp_destination: RwLock::new(None),
            upstream_target: RwLock::new(active_url),
            upstreams: RwLock::new(upstreams),
            active_upstream: RwLock::new(active_name),
            sessions: RwLock::new(Vec::new()),
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

    pub fn broadcast_send(&self, msg: WsMessage) -> Result<usize, broadcast::error::SendError<WsMessage>> {
        self.broadcaster.send(msg)
    }

    pub fn broadcast_subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.broadcaster.subscribe()
    }

    /// Build the full UpstreamInfo list for broadcasting to frontend.
    pub async fn upstream_info_list(&self) -> Vec<UpstreamInfo> {
        let upstreams = self.upstreams.read().await.clone();
        let active_url = self.upstream_target.read().await.clone();
        upstreams
            .iter()
            .map(|u| UpstreamInfo {
                name: u.name.clone(),
                url: u.url.clone(),
                active: u.url == active_url,
                has_token: u.token.is_some(),
                model_map: u.model_map.clone(),
            })
            .collect()
    }

    /// Persist upstreams to config.toml.
    pub async fn persist_upstreams(&self) {
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

        let arr: Vec<toml::Value> = upstreams
            .iter()
            .map(|u| {
                let mut t = toml::value::Table::new();
                t.insert("name".into(), toml::Value::String(u.name.clone()));
                t.insert("url".into(), toml::Value::String(u.url.clone()));
                if let Some(ref token) = u.token {
                    t.insert("token".into(), toml::Value::String(token.clone()));
                }
                toml::Value::Table(t)
            })
            .collect();
        proxy.insert("upstreams".into(), toml::Value::Array(arr));
        proxy.insert("active_upstream".into(), toml::Value::String(active));
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Load config
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

    let listen_addr = &config.server.listen_address;

    // Build routers for each port
    let dashboard_router = api::build_router(state.clone());
    let proxy_router = proxy::build_router(state.clone());
    let mcp_router = mcp::build_router(state.clone());

    // Bind listeners
    let dashboard_addr: SocketAddr = format!("{}:{}", listen_addr, config.server.http_port).parse()?;
    let proxy_addr: SocketAddr = format!("{}:{}", listen_addr, config.server.proxy_port).parse()?;
    let mcp_addr: SocketAddr = format!("{}:{}", listen_addr, config.server.mcp_proxy_port).parse()?;

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
