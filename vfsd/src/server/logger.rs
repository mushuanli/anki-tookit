// src/server/logger.rs
use axum::{
    extract::{ConnectInfo, State},
    http::{Request},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use crate::types::{AppState};

pub async fn access_log_middleware(
    State(state): State<Arc<AppState>>,
    connect_info: ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let remote_ip = connect_info.0.ip().to_string();

    // 逻辑修正：目前架构下，这里拿不到 Extractor 注入的 ID，因为 Extractor 还没跑。
    // 但为了修复编译/类型逻辑：
    // let user_id = req.extensions().get::<RequestUserId>().cloned().unwrap_or(None);
    let user_id: Option<i64> = None; 

    // Run the inner handler
    let response = next.run(req).await;
    
    let latency_ms = start.elapsed().as_millis() as i64;
    let status = response.status().as_u16();

    // Try to extract user_id from response extensions (if handlers inserted it)
    // Or from request extensions (if extractor ran).
    // 由于 Axum 的提取器顺序问题，我们通常无法在中间件 response 阶段直接拿到 extractor 的数据
    // 除非我们在 Handler 里手动 insert 到 extensions。
    // 为了简化，这里我们假设如果在 Handler 中验证成功，Claims 会被放在 request extensions 中。
    // (注意：这需要 Claims 提取器实现中不仅返回 Claims，还要将其 insert 到 extensions 中，这在之前的代码中未做)
    // *Phase 3 修正*：为了能记录 User ID，我们暂且记录为 0 (匿名) 或在后续优化 Auth 提取器。
    
    // 异步写入日志，不阻塞主线程
    let db = state.db.clone();
    tokio::spawn(async move {
        let _ = sqlx::query("INSERT INTO access_logs (timestamp, remote_ip, method, path, status, user_id, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(chrono::Utc::now().timestamp())
            .bind(remote_ip)
            .bind(method)
            .bind(path)
            .bind(status)
            .bind(user_id) // 记录 user_id
            .bind(latency_ms)
            .execute(&db).await;
    });

    response
}
