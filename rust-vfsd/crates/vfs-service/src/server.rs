// crates/vfs-service/src/server.rs

use std::sync::Arc;
use axum::{middleware, routing::{delete, get, post}, Router};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::auth::{
    rate_limit::{RateLimitConfig, RateLimiter, RateLimitState, rate_limit_middleware},
    AuthState, JwtService,
};
use crate::handlers::{admin, health, rest, websocket};
use crate::metrics::{init_metrics, metrics_handler, metrics_middleware};
use crate::services::ServiceContainer;

use vfs_core::config::Config;
use vfs_core::error::AppResult;
use vfs_storage::{Database, FileStore, CacheService, CacheServiceConfig, CachedDatabase};
use vfs_sync::SyncEngine;

/// 服务器配置
pub struct ServerConfig {
    pub config: Arc<Config>,
}

/// 服务器构建器
pub struct ServerBuilder {
    config: Option<Arc<Config>>,
    db: Option<Database>,
}

impl ServerBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            db: None,
        }
    }

    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_database(mut self, db: Database) -> Self {
        self.db = Some(db);
        self
    }

    pub async fn build(self) -> AppResult<Server> {
        let config = self.config.unwrap_or_else(|| Arc::new(Config::default()));
        
        let db = match self.db {
            Some(db) => db,
            None => {
                let db = Database::new(&config.database).await?;
                db.run_migrations().await?;
                db
            }
        };

        Server::new(config, db).await
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// VFS 服务器
pub struct Server {
    config: Arc<Config>,
    router: Router,
}

impl Server {
    pub async fn new(config: Arc<Config>, db: Database) -> AppResult<Self> {
        init_metrics();

        tracing::info!("Initializing VFS Server v{}", env!("CARGO_PKG_VERSION"));

        // 初始化文件存储
        let file_store = Arc::new(FileStore::new(&config.storage).await?);
        tracing::info!("File store initialized");

        // 初始化缓存服务
        let cache_service = Arc::new(CacheService::new(CacheServiceConfig::default()));
        tracing::info!("Cache service initialized");

        // 包装为缓存数据库
        let cached_db = CachedDatabase::new(db.clone(), cache_service.clone());

        // 初始化同步引擎
        let sync_engine = Arc::new(
            SyncEngine::new(
                db.clone(),
                file_store.clone(),
                cache_service.clone(),
                config.clone(),
            ).await?
        );
        tracing::info!("Sync engine initialized");

        // 初始化速率限制
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        rate_limiter.clone().start_cleanup_task();

        // 创建服务容器
        let services = ServiceContainer::new(
            cached_db.clone(),
            file_store.clone(),
            sync_engine.clone(),
            config.clone(),
        );

        // 创建应用状态
        let app_state = rest::AppState {
            services,
            db: cached_db.clone(),
            file_store: file_store.clone(),
            sync_engine: sync_engine.clone(),
        };

        let ws_state = websocket::WsState {
            config: config.clone(),
            sync_engine: sync_engine.clone(),
        };

        let auth_state = AuthState {
            jwt_service: Arc::new(JwtService::new(&config.auth)),
            db: cached_db.clone(),
        };

        let rate_limit_state = RateLimitState {
            limiter: rate_limiter,
        };

        // 构建路由
        let router = Self::build_router(
            app_state,
            ws_state,
            auth_state,
            rate_limit_state,
        );

        Ok(Self { config, router })
    }

    fn build_router(
        app_state: rest::AppState,
        ws_state: websocket::WsState,
        auth_state: AuthState,
        rate_limit_state: RateLimitState,
    ) -> Router {
        Router::new()
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
            // WebSocket
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
                        crate::auth::auth_middleware,
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
            .layer(TraceLayer::new_for_http())
    }

    /// 启动服务器
    pub async fn run(self) -> AppResult<()> {
        let addr = format!("{}:{}", self.config.server.host, self.config.server.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        
        tracing::info!("Server listening on {}", addr);

        let shutdown_signal = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");
            tracing::info!("Shutdown signal received, starting graceful shutdown...");
        };

        axum::serve(listener, self.router)
            .with_graceful_shutdown(shutdown_signal)
            .await?;

        tracing::info!("Server shutdown complete");
        Ok(())
    }

    /// 获取路由（用于测试）
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// 获取配置
    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    // 集成测试示例
    #[tokio::test]
    async fn test_health_endpoint() {
        // 这个测试需要完整的服务器环境
        // 实际测试中可以使用 testcontainers 或 mock
    }
}
