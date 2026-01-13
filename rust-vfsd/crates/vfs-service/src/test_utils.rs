// crates/vfs-service/src/test_utils.rs

//! 测试辅助工具
//! 
//! 提供创建测试环境的工具函数

#![cfg(test)]

use std::sync::Arc;
use tempfile::TempDir;
use uuid::Uuid;

use vfs_core::config::{Config, DatabaseConfig, StorageConfig};
use vfs_core::models::User;
use vfs_core::utils::CryptoUtils;
use vfs_storage::{Database, CacheService, CacheServiceConfig, CachedDatabase, FileStore};
use vfs_sync::SyncEngine;

use crate::services::ServiceContainer;

/// 测试环境
pub struct TestEnv {
    pub config: Arc<Config>,
    pub db: CachedDatabase,
    pub file_store: Arc<FileStore>,
    pub sync_engine: Arc<SyncEngine>,
    pub services: ServiceContainer,
    _temp_dir: TempDir, // 保持 TempDir 存活
}

impl TestEnv {
    /// 创建新的测试环境
    pub async fn new() -> Self {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let data_dir = temp_dir.path().join("data");

        let config = Arc::new(Config {
            database: DatabaseConfig {
                path: db_path.to_string_lossy().to_string(),
                max_connections: 1,
            },
            storage: StorageConfig {
                data_dir: data_dir.clone(),
                content_dir: "content".to_string(),
                chunks_dir: "chunks".to_string(),
            },
            ..Config::default()
        });

        let db = Database::new(&config.database).await.unwrap();
        db.run_migrations().await.unwrap();

        let cache = Arc::new(CacheService::new(CacheServiceConfig::default()));
        let cached_db = CachedDatabase::new(db.clone(), cache.clone());

        let file_store = Arc::new(FileStore::new(&config.storage).await.unwrap());

        let sync_engine = Arc::new(
            SyncEngine::new(db, file_store.clone(), cache, config.clone())
                .await
                .unwrap()
        );

        let services = ServiceContainer::new(
            cached_db.clone(),
            file_store.clone(),
            sync_engine.clone(),
            config.clone(),
        );

        Self {
            config,
            db: cached_db,
            file_store,
            sync_engine,
            services,
            _temp_dir: temp_dir,
        }
    }

    /// 创建测试用户
    pub async fn create_test_user(&self, username: &str) -> User {
        let password_hash = CryptoUtils::hash_password("password123").unwrap();
        let now = chrono::Utc::now();

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            password_hash,
            email: Some(format!("{}@test.com", username)),
            display_name: Some(format!("Test User {}", username)),
            storage_quota: 10 * 1024 * 1024 * 1024,
            storage_used: 0,
            is_active: true,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };

        self.db.create_user(&user).await.unwrap();
        user
    }
}

/// 创建简单的测试数据库
pub async fn create_test_db() -> CachedDatabase {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");

    let config = DatabaseConfig {
        path: db_path.to_string_lossy().to_string(),
        max_connections: 1,
    };

    let db = Database::new(&config).await.unwrap();
    db.run_migrations().await.unwrap();

    let cache = Arc::new(CacheService::new(CacheServiceConfig::default()));
    CachedDatabase::new(db, cache)
}
