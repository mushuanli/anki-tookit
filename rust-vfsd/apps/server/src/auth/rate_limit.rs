// src/auth/rate_limit.rs

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use vfs_core::error::AppError;

/// 速率限制配置
#[derive(Clone)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 200,
        }
    }
}

/// 令牌桶
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    rate: f64,
    capacity: f64,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            rate,
            capacity,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        
        // 补充令牌
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// 速率限制器
pub struct RateLimiter {
    buckets: RwLock<HashMap<String, TokenBucket>>,
    
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            config,
        }
    }

    pub async fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.requests_per_second as f64,
                self.config.burst_size as f64,
            )
        });

        bucket.try_consume()
    }

    /// 清理过期的令牌桶
    pub async fn cleanup(&self, max_idle: Duration) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        buckets.retain(|_, bucket| {
            now.duration_since(bucket.last_update) < max_idle
        });
    }

    /// 启动清理任务
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                self.cleanup(Duration::from_secs(300)).await;
            }
        });
    }
}

/// 速率限制中间件状态
#[derive(Clone)]
pub struct RateLimitState {
    pub limiter: Arc<RateLimiter>,
}

/// 速率限制中间件
pub async fn rate_limit_middleware(
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 获取客户端标识（IP 或用户 ID）
    let key = extract_client_key(&request);

    if !state.limiter.check(&key).await {
        return Err(AppError::RateLimitExceeded);
    }

    Ok(next.run(request).await)
}

fn extract_client_key(request: &Request) -> String {
    // 优先使用 X-Forwarded-For 头
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(ip) = value.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // 使用连接信息
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}
