// crates/vfs-service/src/services/user_service.rs

use uuid::Uuid;
use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{User, CreateUserRequest, UpdateUserRequest};
use vfs_core::utils::CryptoUtils;
use vfs_storage::CachedDatabase;

/// 用户服务
/// 
/// 处理用户相关的业务逻辑，包括创建、查询、更新用户。
#[derive(Clone)]
pub struct UserService {
    db: CachedDatabase,
}

impl UserService {
    pub fn new(db: CachedDatabase) -> Self {
        Self { db }
    }

    /// 根据 ID 获取用户
    pub async fn get_by_id(&self, user_id: Uuid) -> AppResult<Option<User>> {
        self.db.get_user_by_id(user_id).await
    }

    /// 根据用户名获取用户
    pub async fn get_by_username(&self, username: &str) -> AppResult<Option<User>> {
        self.db.get_user_by_username(username).await
    }

    /// 创建新用户
    pub async fn create(&self, req: CreateUserRequest) -> AppResult<User> {
        // 检查用户名是否已存在
        if self.db.get_user_by_username(&req.username).await?.is_some() {
            return Err(AppError::Conflict("Username already exists".to_string()));
        }

        let password_hash = CryptoUtils::hash_password(&req.password)?;
        let now = chrono::Utc::now();

        let user = User {
            id: Uuid::new_v4().to_string(),
            username: req.username,
            password_hash,
            email: req.email,
            display_name: req.display_name,
            storage_quota: 10 * 1024 * 1024 * 1024, // 10GB 默认配额
            storage_used: 0,
            is_active: true,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };

        self.db.create_user(&user).await?;

        Ok(user)
    }

    /// 更新用户信息
    pub async fn update(&self, user_id: Uuid, req: UpdateUserRequest) -> AppResult<User> {
        let mut user = self.db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if let Some(email) = req.email {
            user.email = Some(email);
        }
        if let Some(display_name) = req.display_name {
            user.display_name = Some(display_name);
        }
        if let Some(password) = req.password {
            user.password_hash = CryptoUtils::hash_password(&password)?;
        }
        user.updated_at = chrono::Utc::now().to_rfc3339();

        self.db.update_user(&user).await?;

        Ok(user)
    }

    /// 更新用户存储使用量
    pub async fn update_storage(&self, user_id: Uuid, delta: i64) -> AppResult<()> {
        self.db.update_user_storage(user_id, delta).await
    }

    /// 验证密码
    pub fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        CryptoUtils::verify_password(password, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vfs_storage::{Database, CacheService, CacheServiceConfig};
    use tempfile::tempdir;

    async fn create_test_db() -> CachedDatabase {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        
        let config = vfs_core::config::DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            max_connections: 1,
        };
        
        let db = Database::new(&config).await.unwrap();
        db.run_migrations().await.unwrap();
        
        let cache = Arc::new(CacheService::new(CacheServiceConfig::default()));
        CachedDatabase::new(db, cache)
    }

    #[tokio::test]
    async fn test_create_user() {
        let db = create_test_db().await;
        let service = UserService::new(db);

        let req = CreateUserRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            email: Some("test@example.com".to_string()),
            display_name: Some("Test User".to_string()),
        };

        let user = service.create(req).await.unwrap();
        
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, Some("test@example.com".to_string()));
        assert!(user.is_active);
    }

    #[tokio::test]
    async fn test_create_duplicate_user() {
        let db = create_test_db().await;
        let service = UserService::new(db);

        let req = CreateUserRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            email: None,
            display_name: None,
        };

        // 第一次创建成功
        service.create(req.clone()).await.unwrap();
        
        // 第二次创建应该失败
        let result = service.create(req).await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let db = create_test_db().await;
        let service = UserService::new(db);

        let req = CreateUserRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            email: None,
            display_name: None,
        };

        let created_user = service.create(req).await.unwrap();
        let user_id = created_user.id_as_uuid();

        let found_user = service.get_by_id(user_id).await.unwrap();
        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_update_user() {
        let db = create_test_db().await;
        let service = UserService::new(db);

        let req = CreateUserRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            email: None,
            display_name: None,
        };

        let created_user = service.create(req).await.unwrap();
        let user_id = created_user.id_as_uuid();

        let update_req = UpdateUserRequest {
            email: Some("updated@example.com".to_string()),
            display_name: Some("Updated Name".to_string()),
            password: None,
        };

        let updated_user = service.update(user_id, update_req).await.unwrap();
        assert_eq!(updated_user.email, Some("updated@example.com".to_string()));
        assert_eq!(updated_user.display_name, Some("Updated Name".to_string()));
    }

    #[tokio::test]
    async fn test_verify_password() {
        let db = create_test_db().await;
        let service = UserService::new(db);

        let req = CreateUserRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            email: None,
            display_name: None,
        };

        let user = service.create(req).await.unwrap();
        
        assert!(service.verify_password("password123", &user.password_hash).unwrap());
        assert!(!service.verify_password("wrongpassword", &user.password_hash).unwrap());
    }
}
