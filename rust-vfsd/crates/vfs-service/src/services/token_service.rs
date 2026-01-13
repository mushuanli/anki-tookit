// crates/vfs-service/src/services/token_service.rs

use chrono::{Duration, Utc};
use uuid::Uuid;

use vfs_core::error::{AppError, AppResult};
use vfs_core::models::{
    ApiToken, CreateTokenRequest, CreateTokenResponse, PermissionLevel, TokenInfo,
};
use vfs_core::utils::CryptoUtils;
use vfs_storage::CachedDatabase;

/// Token 服务
/// 
/// 处理 API Token 的创建、查询、撤销等操作。
#[derive(Clone)]
pub struct TokenService {
    db: CachedDatabase,
}

impl TokenService {
    pub fn new(db: CachedDatabase) -> Self {
        Self { db }
    }

    /// 创建新的 API Token
    pub async fn create(
        &self,
        user_id: Uuid,
        req: CreateTokenRequest,
    ) -> AppResult<CreateTokenResponse> {
        // 生成随机 token
        let raw_token = CryptoUtils::generate_token();
        let token_hash = CryptoUtils::hash_token(&raw_token);

        let expires_at = req.expires_in_days.map(|days| {
            Utc::now() + Duration::days(days)
        });

        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id,
            name: req.name.clone(),
            token_hash,
            permission_level: req.permission_level.clone(),
            path_permissions: req.path_permissions.clone(),
            device_id: req.device_id.clone(),
            device_name: req.device_name.clone(),
            last_used_at: None,
            expires_at,
            is_revoked: false,
            created_at: Utc::now(),
        };

        self.db.create_token(&token).await?;

        Ok(CreateTokenResponse {
            id: token.id,
            name: req.name,
            token: raw_token, // 只在创建时返回明文
            expires_at,
        })
    }

    /// 获取用户的所有 Token
    pub async fn list_by_user(&self, user_id: Uuid) -> AppResult<Vec<TokenInfo>> {
        let tokens = self.db.get_user_tokens(user_id).await?;
        Ok(tokens.into_iter().map(TokenInfo::from).collect())
    }

    /// 撤销 Token
    pub async fn revoke(&self, token_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        self.db.revoke_token(token_id, user_id).await
    }

    /// 根据哈希获取 Token
    pub async fn get_by_hash(&self, token_hash: &str) -> AppResult<Option<ApiToken>> {
        self.db.get_token_by_hash(token_hash).await
    }

    /// 更新 Token 最后使用时间
    pub async fn update_last_used(&self, token_id: Uuid) -> AppResult<()> {
        self.db.update_token_last_used(token_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vfs_core::models::User;
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

    async fn create_test_user(db: &CachedDatabase) -> Uuid {
        let now = chrono::Utc::now();
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            email: None,
            display_name: None,
            storage_quota: 10 * 1024 * 1024 * 1024,
            storage_used: 0,
            is_active: true,
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
        };
        
        db.create_user(&user).await.unwrap();
        user.id_as_uuid()
    }

    #[tokio::test]
    async fn test_create_token() {
        let db = create_test_db().await;
        let service = TokenService::new(db.clone());
        let user_id = create_test_user(&db).await;

        let req = CreateTokenRequest {
            name: "Test Token".to_string(),
            permission_level: PermissionLevel::ReadWrite,
            path_permissions: None,
            device_id: Some("device1".to_string()),
            device_name: Some("My Device".to_string()),
            expires_in_days: Some(30),
        };

        let response = service.create(user_id, req).await.unwrap();
        
        assert_eq!(response.name, "Test Token");
        assert!(!response.token.is_empty());
        assert!(response.expires_at.is_some());
    }

    #[tokio::test]
    async fn test_list_tokens() {
        let db = create_test_db().await;
        let service = TokenService::new(db.clone());
        let user_id = create_test_user(&db).await;

        // 创建多个 token
        for i in 0..3 {
            let req = CreateTokenRequest {
                name: format!("Token {}", i),
                permission_level: PermissionLevel::ReadOnly,
                path_permissions: None,
                device_id: None,
                device_name: None,
                expires_in_days: None,
            };
            service.create(user_id, req).await.unwrap();
        }

        let tokens = service.list_by_user(user_id).await.unwrap();
        assert_eq!(tokens.len(), 3);
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let db = create_test_db().await;
        let service = TokenService::new(db.clone());
        let user_id = create_test_user(&db).await;

        let req = CreateTokenRequest {
            name: "To Revoke".to_string(),
            permission_level: PermissionLevel::ReadWrite,
            path_permissions: None,
            device_id: None,
            device_name: None,
            expires_in_days: None,
        };

        let response = service.create(user_id, req).await.unwrap();
        
        let revoked = service.revoke(response.id, user_id).await.unwrap();
        assert!(revoked);

        // 验证 token 已被撤销
        let tokens = service.list_by_user(user_id).await.unwrap();
        let token = tokens.iter().find(|t| t.id == response.id).unwrap();
        assert!(token.is_revoked);
    }
}
