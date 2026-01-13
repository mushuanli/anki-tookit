// crates/vfs-service/src/services/auth_service.rs

use std::sync::Arc;
use uuid::Uuid;

use vfs_core::config::Config;
use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{PermissionLevel, User, UserResponse};
use vfs_core::utils::CryptoUtils;
use vfs_storage::CachedDatabase;

use crate::auth::JwtService;

/// 登录请求
#[derive(Debug, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}

/// 登录响应
#[derive(Debug, Clone)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
}

/// 认证服务
/// 
/// 处理用户认证相关的业务逻辑，包括登录、Token 验证等。
#[derive(Clone)]
pub struct AuthService {
    db: CachedDatabase,
    jwt_service: Arc<JwtService>,
}

impl AuthService {
    pub fn new(db: CachedDatabase, config: Arc<Config>) -> Self {
        Self {
            db,
            jwt_service: Arc::new(JwtService::new(&config.auth)),
        }
    }

    /// 用户登录
    pub async fn login(&self, req: LoginRequest) -> AppResult<LoginResponse> {
        // 获取用户
        let user = self.db
            .get_user_by_username(&req.username)
            .await?
            .ok_or_else(|| AppError::AuthError("Invalid credentials".to_string()))?;

        // 验证密码
        if !CryptoUtils::verify_password(&req.password, &user.password_hash)? {
            return Err(AppError::AuthError("Invalid credentials".to_string()));
        }

        // 检查账户状态
        if !user.is_active {
            return Err(AppError::AuthError("Account is disabled".to_string()));
        }

        // 生成 JWT
        let token = self.jwt_service.generate_token(
            user.id_as_uuid(),
            &user.username,
            req.device_id,
            PermissionLevel::ReadWrite,
            None,
        )?;

        Ok(LoginResponse { token, user })
    }

    /// 验证 JWT Token
    pub fn validate_jwt(&self, token: &str) -> AppResult<crate::auth::Claims> {
        let token_data = self.jwt_service.validate_token(token)?;
        Ok(token_data.claims)
    }

    /// 验证 API Token
    pub async fn validate_api_token(&self, token: &str) -> AppResult<crate::auth::Claims> {
        let token_hash = CryptoUtils::hash_token(token);
        
        let api_token = self.db
            .get_token_by_hash(&token_hash)
            .await?
            .ok_or_else(|| AppError::AuthError("Invalid API token".to_string()))?;

        // 检查 token 是否被撤销
        if api_token.is_revoked {
            return Err(AppError::AuthError("Token has been revoked".to_string()));
        }

        // 检查 token 是否过期
        if let Some(expires_at) = api_token.expires_at {
            if expires_at < chrono::Utc::now() {
                return Err(AppError::AuthError("Token has expired".to_string()));
            }
        }

        // 异步更新最后使用时间
        let db = self.db.clone();
        let token_id = api_token.id;
        tokio::spawn(async move {
            if let Err(e) = db.update_token_last_used(token_id).await {
                tracing::warn!("Failed to update token last used time: {}", e);
            }
        });

        // 构造 Claims
        Ok(crate::auth::Claims {
            sub: api_token.user_id,
            username: String::new(),
            device_id: api_token.device_id,
            permission_level: api_token.permission_level,
            path_permissions: api_token.path_permissions,
            exp: api_token.expires_at
                .map(|dt| dt.timestamp())
                .unwrap_or(i64::MAX),
            iat: api_token.created_at.timestamp(),
        })
    }

    /// 获取 JWT 服务实例（用于中间件）
    pub fn jwt_service(&self) -> Arc<JwtService> {
        self.jwt_service.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs_core::models::CreateUserRequest;
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

    async fn create_test_user(db: &CachedDatabase) -> User {
        let password_hash = CryptoUtils::hash_password("password123").unwrap();
        let now = chrono::Utc::now();
        
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: "testuser".to_string(),
            password_hash,
            email: None,
            display_name: None,
            storage_quota: 10 * 1024 * 1024 * 1024,
            storage_used: 0,
            is_active: true,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };
        
        db.create_user(&user).await.unwrap();
        user
    }

    #[tokio::test]
    async fn test_login_success() {
        let db = create_test_db().await;
        let config = Arc::new(Config::default());
        let service = AuthService::new(db.clone(), config);
        
        create_test_user(&db).await;

        let req = LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            device_id: None,
            device_name: None,
        };

        let response = service.login(req).await.unwrap();
        assert!(!response.token.is_empty());
        assert_eq!(response.user.username, "testuser");
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let db = create_test_db().await;
        let config = Arc::new(Config::default());
        let service = AuthService::new(db.clone(), config);
        
        create_test_user(&db).await;

        let req = LoginRequest {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
            device_id: None,
            device_name: None,
        };

        let result = service.login(req).await;
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        let db = create_test_db().await;
        let config = Arc::new(Config::default());
        let service = AuthService::new(db, config);

        let req = LoginRequest {
            username: "nonexistent".to_string(),
            password: "password123".to_string(),
            device_id: None,
            device_name: None,
        };

        let result = service.login(req).await;
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }

    #[tokio::test]
    async fn test_validate_jwt() {
        let db = create_test_db().await;
        let config = Arc::new(Config::default());
        let service = AuthService::new(db.clone(), config);
        
        create_test_user(&db).await;

        let req = LoginRequest {
            username: "testuser".to_string(),
            password: "password123".to_string(),
            device_id: Some("device1".to_string()),
            device_name: None,
        };

        let response = service.login(req).await.unwrap();
        
        let claims = service.validate_jwt(&response.token).unwrap();
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.device_id, Some("device1".to_string()));
    }
}
