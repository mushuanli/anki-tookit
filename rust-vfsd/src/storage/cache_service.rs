// src/storage/cache_service.rs

use bytes::Bytes;
use moka::future::Cache;
use std::time::Duration;
use uuid::Uuid;

use crate::models::{ApiToken, User, SyncCursor};

/// 缓存键前缀
mod keys {
    pub const USER_BY_ID: &str = "user:id:";
    pub const USER_BY_USERNAME: &str = "user:name:";
    pub const TOKEN_BY_HASH: &str = "token:hash:";
    pub const CONTENT: &str = "content:";
    pub const CURSOR: &str = "cursor:";
    pub const ONLINE_DEVICES: &str = "devices:";
}

/// 缓存配置
#[derive(Clone)]
pub struct CacheServiceConfig {
    /// 最大缓存条目数
    pub max_capacity: u64,
    /// 默认 TTL
    pub default_ttl: Duration,
    /// 内容缓存最大大小（字节）
    pub max_content_size: usize,
    /// 内容缓存 TTL
    pub content_ttl: Duration,
}

impl Default for CacheServiceConfig {
    fn default() -> Self {
        Self {
            max_capacity: 10_000,
            default_ttl: Duration::from_secs(300),      // 5分钟
            max_content_size: 1024 * 1024,              // 1MB
            content_ttl: Duration::from_secs(600),      // 10分钟
        }
    }
}

/// 缓存服务
pub struct CacheService {
    /// 通用对象缓存
    object_cache: Cache<String, Bytes>,
    /// 内容缓存（较大的数据）
    content_cache: Cache<String, Bytes>,
    /// 配置
    #[allow(dead_code)]
    config: CacheServiceConfig,
}

impl CacheService {
    pub fn new(config: CacheServiceConfig) -> Self {
        let object_cache = Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(config.default_ttl)
            .time_to_idle(Duration::from_secs(60))
            .build();

        let content_cache = Cache::builder()
            .max_capacity(1000)  // 内容缓存条目数较少
            .time_to_live(config.content_ttl)
            .weigher(|_key: &String, value: &Bytes| -> u32 {
                // 按大小计算权重
                value.len().try_into().unwrap_or(u32::MAX)
            })
            .max_capacity(100 * 1024 * 1024)  // 最大 100MB
            .build();

        Self {
            object_cache,
            content_cache,
            config,
        }
    }

    // ==================== 用户缓存 ====================

    /// 缓存用户（按 ID）
    pub async fn set_user_by_id(&self, user: &User) {
        let key = format!("{}{}", keys::USER_BY_ID, user.id);
        if let Ok(data) = serde_json::to_vec(user) {
            self.object_cache.insert(key, Bytes::from(data)).await;
        }
    }

    /// 获取缓存的用户（按 ID）
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Option<User> {
        let key = format!("{}{}", keys::USER_BY_ID, user_id);
        self.object_cache.get(&key).await.and_then(|data| {
            serde_json::from_slice(&data).ok()
        })
    }

    /// 缓存用户（按用户名）
    pub async fn set_user_by_username(&self, user: &User) {
        let key = format!("{}{}", keys::USER_BY_USERNAME, user.username);
        if let Ok(data) = serde_json::to_vec(user) {
            self.object_cache.insert(key, Bytes::from(data)).await;
        }
    }

    /// 获取缓存的用户（按用户名）
    pub async fn get_user_by_username(&self, username: &str) -> Option<User> {
        let key = format!("{}{}", keys::USER_BY_USERNAME, username);
        self.object_cache.get(&key).await.and_then(|data| {
            serde_json::from_slice(&data).ok()
        })
    }

    /// 使用户缓存失效
    #[allow(dead_code)]
    pub async fn invalidate_user(&self, user_id: Uuid, username: &str) {
        let id_key = format!("{}{}", keys::USER_BY_ID, user_id);
        let name_key = format!("{}{}", keys::USER_BY_USERNAME, username);
        self.object_cache.remove(&id_key).await;
        self.object_cache.remove(&name_key).await;
    }

    // ==================== Token 缓存 ====================

    /// 缓存 API Token
    pub async fn set_token(&self, token_hash: &str, token: &ApiToken) {
        let key = format!("{}{}", keys::TOKEN_BY_HASH, token_hash);
        if let Ok(data) = serde_json::to_vec(token) {
            self.object_cache.insert(key, Bytes::from(data)).await;
        }
    }

    /// 获取缓存的 API Token
    pub async fn get_token(&self, token_hash: &str) -> Option<ApiToken> {
        let key = format!("{}{}", keys::TOKEN_BY_HASH, token_hash);
        self.object_cache.get(&key).await.and_then(|data| {
            serde_json::from_slice(&data).ok()
        })
    }

    /// 使 Token 缓存失效
    #[allow(dead_code)]
    pub async fn invalidate_token(&self, token_hash: &str) {
        let key = format!("{}{}", keys::TOKEN_BY_HASH, token_hash);
        self.object_cache.remove(&key).await;
    }

    // ==================== 内容缓存 ====================

    /// 缓存内容（仅小于阈值的内容）
    pub async fn set_content(&self, user_id: Uuid, content_hash: &str, data: &[u8]) {
        if data.len() <= self.config.max_content_size {
            let key = format!("{}{}:{}", keys::CONTENT, user_id, content_hash);
            self.content_cache.insert(key, Bytes::copy_from_slice(data)).await;
        }
    }

    /// 获取缓存的内容
    pub async fn get_content(&self, user_id: Uuid, content_hash: &str) -> Option<Vec<u8>> {
        let key = format!("{}{}:{}", keys::CONTENT, user_id, content_hash);
        self.content_cache.get(&key).await.map(|b| b.to_vec())
    }

    /// 使内容缓存失效
    #[allow(dead_code)]
    pub async fn invalidate_content(&self, user_id: Uuid, content_hash: &str) {
        let key = format!("{}{}:{}", keys::CONTENT, user_id, content_hash);
        self.content_cache.remove(&key).await;
    }

    // ==================== 游标缓存 ====================

    /// 缓存同步游标
    pub async fn set_cursor(&self, cursor: &SyncCursor) {
        let key = format!(
            "{}{}:{}:{}",
            keys::CURSOR,
            cursor.user_id,
            cursor.device_id,
            cursor.module_id
        );
        if let Ok(data) = serde_json::to_vec(cursor) {
            self.object_cache.insert(key, Bytes::from(data)).await;
        }
    }

    /// 获取缓存的同步游标
    #[allow(dead_code)]
    pub async fn get_cursor(
        &self,
        user_id: Uuid,
        device_id: &str,
        module_id: &str,
    ) -> Option<SyncCursor> {
        let key = format!("{}{}:{}:{}", keys::CURSOR, user_id, device_id, module_id);
        self.object_cache.get(&key).await.and_then(|data| {
            serde_json::from_slice(&data).ok()
        })
    }

    // ==================== 统计 ====================

    /// 获取缓存统计
    #[allow(dead_code)]
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            object_cache_size: self.object_cache.entry_count(),
            content_cache_size: self.content_cache.entry_count(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheStats {
    pub object_cache_size: u64,
    pub content_cache_size: u64,
}
