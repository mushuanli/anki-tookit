// src/main.rs

use clap::Parser;
use std::sync::Arc;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use axum::{middleware, routing::{delete, get, post}, Router};

mod auth;
mod config;
mod error;
mod handlers;
mod metrics;
mod models;
mod storage;
mod sync;
mod utils;
mod cli; // 引入 CLI 模块

use auth::{
    rate_limit::{RateLimitConfig, RateLimiter, RateLimitState, rate_limit_middleware},
    AuthState, JwtService,
};
use config::Config;
use handlers::{admin, health, rest, websocket};
use metrics::{init_metrics, metrics_handler, metrics_middleware};
use storage::{Database, FileStore, CacheService, CacheServiceConfig};
use sync::SyncEngine;
use cli::{Cli, Commands, CliHandler}; // 使用 CLI

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

    // 初始化指标
    init_metrics();

    // 加载配置
    let config = Config::load().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config, using defaults: {}", e);
        Arc::new(Config::default())
    });

    tracing::info!("Starting VFS Sync Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Server configuration: {}:{}", config.server.host, config.server.port);
    tracing::info!("Database path: {}", config.database.path);
    tracing::info!("Data directory: {:?}", config.storage.data_dir);

    // 初始化数据库
    let db = Database::new(&config.database).await?;
    db.run_migrations().await?;

    // 4. 解析命令行参数
    let cli = Cli::parse();

    // 5. 根据命令分发
    match cli.command {
        // 如果是用户管理命令
        Some(Commands::User(user_cmd)) => {
            let handler = CliHandler::new(db);
            handler.handle_user_command(user_cmd).await?;
            return Ok(()); // 执行完命令后直接退出
        }
        
        // 如果是 Server 或者没有输入命令 (默认)
        Some(Commands::Server) | None => {
            run_server(config, db).await?;
        }
    }

    Ok(())
}

// 将原有的 Web 服务器启动逻辑抽取出来
async fn run_server(config: Arc<Config>, db: Database) -> anyhow::Result<()> {
    init_metrics();

    tracing::info!("Starting VFS Sync Server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Server mode: Active");

    // 初始化文件存储
    let file_store = Arc::new(FileStore::new(&config.storage).await?);
    tracing::info!("File store initialized");

    // 初始化缓存服务
    let cache_service = Arc::new(CacheService::new(CacheServiceConfig::default()));
    tracing::info!("Cache service initialized");

    // 初始化同步引擎（添加缓存参数）
    let sync_engine = Arc::new(
        SyncEngine::new(
            db.clone(),
            file_store.clone(),
            cache_service.clone(),  // 添加这行
            config.clone(),
        ).await?
    );
    tracing::info!("Sync engine initialized");

    // 初始化速率限制
    let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
    rate_limiter.clone().start_cleanup_task();

    // 创建应用状态
    let app_state = rest::AppState {
        db: db.clone(),
        file_store: file_store.clone(),
        sync_engine: sync_engine.clone(),
    };

    let ws_state = websocket::WsState {
        config: config.clone(),
        sync_engine: sync_engine.clone(),
    };

    // 修改 AuthState，添加 db
    let auth_state = AuthState {
        jwt_service: Arc::new(JwtService::new(&config.auth)),
        db: db.clone(),  // 添加这行
    };

    let rate_limit_state = RateLimitState {
        limiter: rate_limiter,
    };

    // 构建路由
    let app = Router::new()
        // 健康检查和指标（无需认证）
        .route("/health", get(health::health_check))
        .route("/ready", get(health::ready_check))
        .route("/metrics", get(metrics_handler))
        // 认证相关（无需认证，但需要速率限制）
        .nest(
            "/api/v1/auth",
            Router::new()
                .route("/login", post(rest::login))
                .route("/register", post(rest::register))
                .with_state(app_state.clone())
                .layer(middleware::from_fn_with_state(
                    rate_limit_state.clone(),
                    rate_limit_middleware,
                )),
        )
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
                        .route(
                            "/users/:user_id",
                            get(admin::get_user)
                                .put(admin::update_user_admin)
                                .delete(admin::delete_user),
                        )
                        .route("/stats", get(admin::get_system_stats)),
                )
                .with_state(app_state.clone())
                .layer(middleware::from_fn_with_state(
                    auth_state.clone(),
                    auth::auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    rate_limit_state,
                    rate_limit_middleware,
                )),
        )
        // 全局中间件
        .layer(middleware::from_fn(metrics_middleware))
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

    // 优雅关闭
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Shutdown signal received, starting graceful shutdown...");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    tracing::info!("Server shutdown complete");
    Ok(())
}
