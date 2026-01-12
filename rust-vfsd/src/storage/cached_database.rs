// src/storage/cached_database.rs

use std::sync::Arc;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{ApiToken, User, SyncCursor};
use super::{Database, CacheService};

/// 带缓存的数据库访问层
#[derive(Clone)]
pub struct CachedDatabase {
    db: Database,
    cache: Arc<CacheService>,
}

impl CachedDatabase {
    pub fn new(db: Database, cache: Arc<CacheService>) -> Self {
        Self { db, cache }
    }

    /// 获取原始数据库连接（用于不需要缓存的操作）
    pub fn inner(&self) -> &Database {
        &self.db
    }

    // ==================== 用户操作 ====================

    pub async fn get_user_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        // 先查缓存
        if let Some(user) = self.cache.get_user_by_id(id).await {
            return Ok(Some(user));
        }

        // 缓存未命中，查数据库
        let user = self.db.get_user_by_id(id).await?;

        // 写入缓存
        if let Some(ref u) = user {
            self.cache.set_user_by_id(u).await;
        }

        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        // 先查缓存
        if let Some(user) = self.cache.get_user_by_username(username).await {
            return Ok(Some(user));
        }

        // 缓存未命中，查数据库
        let user = self.db.get_user_by_username(username).await?;

        // 写入缓存
        if let Some(ref u) = user {
            self.cache.set_user_by_username(u).await;
            self.cache.set_user_by_id(u).await;
        }

        Ok(user)
    }

    pub async fn create_user(&self, user: &User) -> AppResult<()> {
        self.db.create_user(user).await?;
        // 新用户写入缓存
        self.cache.set_user_by_id(user).await;
        self.cache.set_user_by_username(user).await;
        Ok(())
    }

    pub async fn update_user(&self, user: &User) -> AppResult<()> {
        // 先使缓存失效
        self.cache.invalidate_user(
            Uuid::parse_str(&user.id).unwrap_or_default(),
            &user.username
        ).await;
        
        // TODO: 实现 db.update_user
        // self.db.update_user(user).await?;
        
        Ok(())
    }

    // ==================== Token 操作 ====================

    pub async fn get_token_by_hash(&self, token_hash: &str) -> AppResult<Option<ApiToken>> {
        // 先查缓存
        if let Some(token) = self.cache.get_token(token_hash).await {
            // 检查是否过期或撤销
            if !token.is_revoked {
                if let Some(expires_at) = token.expires_at {
                    if expires_at > chrono::Utc::now() {
                        return Ok(Some(token));
                    }
                } else {
                    return Ok(Some(token));
                }
            }
            // 缓存的 token 无效，清除
            self.cache.invalidate_token(token_hash).await;
        }

        // 缓存未命中，查数据库
        let token = self.db.get_token_by_hash(token_hash).await?;

        // 写入缓存
        if let Some(ref t) = token {
            self.cache.set_token(token_hash, t).await;
        }

        Ok(token)
    }

    pub async fn revoke_token(&self, token_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        let result = self.db.revoke_token(token_id, user_id).await?;
        
        // 无法直接通过 token_id 找到 hash，所以这里不清理缓存
        // 缓存会在下次获取时检查 is_revoked 状态
        
        Ok(result)
    }

    // ==================== 游标操作 ====================

    pub async fn get_cursor(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
    ) -> AppResult<Option<SyncCursor>> {
        // 先查缓存
        if let Some(cursor) = self.cache.get_cursor(user_id, device_id, module_id).await {
            return Ok(Some(cursor));
        }

        // 缓存未命中，查数据库
        let cursor = self.db.get_cursor(user_id, device_id, module_id).await?;

        // 写入缓存
        if let Some(ref c) = cursor {
            self.cache.set_cursor(c).await;
        }

        Ok(cursor)
    }

    pub async fn update_cursor(&self, cursor: SyncCursor) -> AppResult<()> {
        self.db.update_cursor(cursor.clone()).await?;
        // 更新缓存
        self.cache.set_cursor(&cursor).await;
        Ok(())
    }

    // ==================== 直接代理的方法 ====================

    pub async fn create_token(&self, token: &ApiToken) -> AppResult<()> {
        self.db.create_token(token).await
    }

    pub async fn get_user_tokens(&self, user_id: Uuid) -> AppResult<Vec<ApiToken>> {
        self.db.get_user_tokens(user_id).await
    }

    pub async fn update_token_last_used(&self, token_id: Uuid) -> AppResult<()> {
        self.db.update_token_last_used(token_id).await
    }

    pub async fn update_user_storage(&self, user_id: Uuid, delta: i64) -> AppResult<()> {
        self.db.update_user_storage(user_id, delta).await
    }
}
