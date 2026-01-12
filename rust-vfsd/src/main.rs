// src/main.rs

use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod error;
mod handlers;
mod models;
mod storage;
mod sync;
mod utils;

use auth::{AuthState, JwtService};
use config::Config;
use handlers::{admin, health, rest, websocket};
use storage::Database;
use sync::SyncEngine;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vfs_sync_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 加载配置
    let config = Config::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config, using defaults: {}", e);
        Arc::new(Config::default())
    });

    tracing::info!("Starting VFS Sync Server v{}", env!("CARGO_PKG_VERSION"));

    // 初始化数据库
    let db = Database::new(&config.database).await?;
    db.run_migrations().await?;
    tracing::info!("Database connected and migrations complete");

    // 初始化同步引擎
    let sync_engine = Arc::new(SyncEngine::new(db.clone(), config.clone()));

    // 创建应用状态
    let app_state = rest::AppState {
        db: db.clone(),
        sync_engine: sync_engine.clone(),
    };

    let ws_state = websocket::WsState {
        config: config.clone(),
        sync_engine: sync_engine.clone(),
    };

    let auth_state = AuthState {
        jwt_service: Arc::new(JwtService::new(&config.auth)),
    };

    // 构建路由
    let app = Router::new()
        // 健康检查（无需认证）
        .route("/health", get(health::health_check))
        .route("/ready", get(health::ready_check))
        // 认证相关（无需认证）
        .route("/api/v1/auth/login", post(rest::login))
        .route("/api/v1/auth/register", post(rest::register))
        // WebSocket（在查询参数中传递 token）
        .route("/ws", get(websocket::websocket_handler))
        .with_state(ws_state)
        // 需要认证的路由
        .nest(
            "/api/v1",
            Router::new()
                // 用户相关
                .route("/me", get(rest::get_current_user).put(rest::update_current_user))
                .route("/me/tokens", get(rest::list_tokens).post(rest::create_token))
                .route("/me/tokens/:token_id", delete(rest::revoke_token))
                .route("/me/devices", get(rest::list_devices))
                // 同步相关
                .route("/sync/changes", get(rest::get_pending_changes))
                .route("/sync/content/:content_hash", get(rest::get_content))
                .route("/sync/conflicts", get(rest::list_conflicts))
                .route("/sync/conflicts/:conflict_id", post(rest::resolve_conflict))
                // 管理员路由
                .nest(
                    "/admin",
                    Router::new()
                        .route("/users", get(admin::list_users))
                        .route("/users/:user_id", get(admin::get_user)
                            .put(admin::update_user_admin)
                            .delete(admin::delete_user))
                        .route("/stats", get(admin::get_system_stats)),
                )
                .layer(middleware::from_fn_with_state(
                    auth_state.clone(),
                    auth::auth_middleware,
                )),
        )
        .with_state(app_state)
        // 全局中间件
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    // 启动服务器
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
