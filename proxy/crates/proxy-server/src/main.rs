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

use proxy_core::config::AppConfig;
use proxy_core::models::{HookEvent, ProxiedRequest, Session, WsMessage};
use proxy_core::RingBuffer;
use tee::TeeWriter;

pub struct AppState {
    pub config: AppConfig,
    pub request_store: RingBuffer<ProxiedRequest>,
    pub hook_store: RingBuffer<HookEvent>,
    pub mcp_store: RingBuffer<ProxiedRequest>,
    pub mcp_destination: RwLock<Option<String>>,
    pub upstream_target: RwLock<String>,
    pub sessions: RwLock<Vec<Session>>,
    pub tee_writer: TeeWriter,
    pub broadcaster: broadcast::Sender<WsMessage>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        let enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let upstream = config.proxy.api_target.clone();
        Self {
            request_store: RingBuffer::new(config.proxy.request_store_capacity),
            hook_store: RingBuffer::new(config.proxy.hook_store_capacity),
            mcp_store: RingBuffer::new(config.proxy.mcp_store_capacity),
            mcp_destination: RwLock::new(None),
            upstream_target: RwLock::new(upstream),
            sessions: RwLock::new(Vec::new()),
            tee_writer: TeeWriter::new(enabled, PathBuf::from("captures")),
            broadcaster: tx,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .expect("Failed to create reqwest client"),
            config,
        }
    }

    pub fn broadcast_send(&self, msg: WsMessage) -> Result<usize, broadcast::error::SendError<WsMessage>> {
        self.broadcaster.send(msg)
    }

    pub fn broadcast_subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.broadcaster.subscribe()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // Load config
    let config: AppConfig = {
        let cfg_path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "config.toml".to_string());
        match std::fs::read_to_string(&cfg_path) {
            Ok(content) => toml::from_str(&content)?,
            Err(_) => {
                tracing::warn!("Config file '{}' not found, using defaults", cfg_path);
                AppConfig::default()
            }
        }
    };

    let state = Arc::new(AppState::new(config.clone()));

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
