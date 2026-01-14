// crates/vfs-service/src/services/mod.rs

//! 业务服务层
//!
//! 这一层封装了所有业务逻辑，与 HTTP 层解耦。
//! 每个服务都可以独立测试。

pub mod admin_service;
pub mod auth_service;
pub mod sync_service;
pub mod token_service;
pub mod user_service;

pub use admin_service::AdminService;
pub use auth_service::AuthService;
pub use sync_service::SyncService;
pub use token_service::TokenService;
pub use user_service::UserService;

use std::sync::Arc;
use vfs_storage::{CachedDatabase, FileStore};
use vfs_sync::SyncEngine;
use vfs_core::config::Config;

/// 服务容器，持有所有业务服务的实例
#[derive(Clone)]
pub struct ServiceContainer {
    pub user: UserService,
    pub auth: AuthService,
    pub token: TokenService,
    pub sync: SyncService,
    pub admin: AdminService,
}

impl ServiceContainer {
    /// 创建服务容器
    pub fn new(
        db: CachedDatabase,
        file_store: Arc<FileStore>,
        sync_engine: Arc<SyncEngine>,
        config: Arc<Config>,
    ) -> Self {
        let user = UserService::new(db.clone());
        let auth = AuthService::new(db.clone(), config.clone());
        let token = TokenService::new(db.clone());
        let sync = SyncService::new(db.clone(), file_store.clone(), sync_engine.clone());
        let admin = AdminService::new(db.clone(), sync_engine.clone());

        Self {
            user,
            auth,
            token,
            sync,
            admin,
        }
    }
}

/// 服务构建器，用于测试时注入 mock 依赖
pub struct ServiceBuilder {
    db: Option<CachedDatabase>,
    file_store: Option<Arc<FileStore>>,
    sync_engine: Option<Arc<SyncEngine>>,
    config: Option<Arc<Config>>,
}

impl ServiceBuilder {
    pub fn new() -> Self {
        Self {
            db: None,
            file_store: None,
            sync_engine: None,
            config: None,
        }
    }

    pub fn with_db(mut self, db: CachedDatabase) -> Self {
        self.db = Some(db);
        self
    }

    pub fn with_file_store(mut self, file_store: Arc<FileStore>) -> Self {
        self.file_store = Some(file_store);
        self
    }

    pub fn with_sync_engine(mut self, sync_engine: Arc<SyncEngine>) -> Self {
        self.sync_engine = Some(sync_engine);
        self
    }

    pub fn with_config(mut self, config: Arc<Config>) -> Self {
        self.config = Some(config);
        self
    }

    pub fn build(self) -> Result<ServiceContainer, &'static str> {
        let db = self.db.ok_or("Database is required")?;
        let file_store = self.file_store.ok_or("FileStore is required")?;
        let sync_engine = self.sync_engine.ok_or("SyncEngine is required")?;
        let config = self.config.ok_or("Config is required")?;

        Ok(ServiceContainer::new(db, file_store, sync_engine, config))
    }
}

impl Default for ServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}
