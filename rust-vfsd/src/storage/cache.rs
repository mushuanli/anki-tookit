// src/storage/cache.rs

use bytes::Bytes;
use moka::future::Cache;
use std::time::Duration;

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
