// src/storage/cache.rs

use async_trait::async_trait;
use bytes::Bytes;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

use crate::error::AppResult;

/// 缓存配置
#[derive(Clone)]
pub struct CacheConfig {
    pub max_capacity: u64,
    pub time_to_live: Duration,
    pub time_to_idle: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 10_000,
            time_to_live: Duration::from_secs(3600),    // 1小时
            time_to_idle: Duration::from_secs(600),     // 10分钟
        }
    }
}

/// 内存缓存
pub struct MemoryCache {
    cache: Cache<String, Bytes>,
}

impl MemoryCache {
    pub fn new(config: CacheConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(config.time_to_live)
            .time_to_idle(config.time_to_idle)
            .build();

        Self { cache }
    }

    pub async fn get(&self, key: &str) -> Option<Bytes> {
        self.cache.get(key).await
    }

    pub async fn set(&self, key: String, value: Bytes) {
        self.cache.insert(key, value).await;
    }

    pub async fn delete(&self, key: &str) {
        self.cache.remove(key).await;
    }

    pub async fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

/// 带缓存的对象存储包装器
pub struct CachedObjectStore<S> {
    store: S,
    cache: Arc<MemoryCache>,
}

impl<S> CachedObjectStore<S> {
    pub fn new(store: S, cache: Arc<MemoryCache>) -> Self {
        Self { store, cache }
    }
}

#[async_trait]
impl<S: super::object_store::ObjectStore> super::object_store::ObjectStore for CachedObjectStore<S> {
    async fn put(&self, key: &str, data: Bytes) -> AppResult<()> {
        // 先写入存储
        self.store.put(key, data.clone()).await?;
        // 更新缓存
        self.cache.set(key.to_string(), data).await;
        Ok(())
    }

    async fn get(&self, key: &str) -> AppResult<Option<Bytes>> {
        // 先查缓存
        if let Some(data) = self.cache.get(key).await {
            return Ok(Some(data));
        }

        // 缓存未命中，查询存储
        if let Some(data) = self.store.get(key).await? {
            // 写入缓存
            self.cache.set(key.to_string(), data.clone()).await;
            return Ok(Some(data));
        }

        Ok(None)
    }

    async fn delete(&self, key: &str) -> AppResult<()> {
        self.store.delete(key).await?;
        self.cache.delete(key).await;
        Ok(())
    }

    async fn exists(&self, key: &str) -> AppResult<bool> {
        // 缓存中有就直接返回
        if self.cache.get(key).await.is_some() {
            return Ok(true);
        }
        self.store.exists(key).await
    }

    async fn list(&self, prefix: &str) -> AppResult<Vec<String>> {
        // list 不走缓存
        self.store.list(prefix).await
    }
}

/// Redis 缓存（可选）
#[cfg(feature = "redis")]
pub struct RedisCache {
    client: redis::Client,
    prefix: String,
    ttl: u64,
}

#[cfg(feature = "redis")]
impl RedisCache {
    pub async fn new(url: &str, prefix: &str, ttl: u64) -> AppResult<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis connection failed: {}", e)))?;

        Ok(Self {
            client,
            prefix: prefix.to_string(),
            ttl,
        })
    }

    fn get_key(&self, key: &str) -> String {
        format!("{}:{}", self.prefix, key)
    }

    pub async fn get(&self, key: &str) -> AppResult<Option<Bytes>> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        let result: Option<Vec<u8>> = redis::cmd("GET")
            .arg(self.get_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        Ok(result.map(Bytes::from))
    }

    pub async fn set(&self, key: &str, value: Bytes) -> AppResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        redis::cmd("SET")
            .arg(self.get_key(key))
            .arg(value.as_ref())
            .arg("EX")
            .arg(self.ttl)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        Ok(())
    }

    pub async fn delete(&self, key: &str) -> AppResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        redis::cmd("DEL")
            .arg(self.get_key(key))
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| crate::error::AppError::InternalError(format!("Redis error: {}", e)))?;

        Ok(())
    }
}
