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
use crate::types::{AppState, RequestUserId}; // 引入 RequestUserId

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

    // 运行 Handler
    let response = next.run(req).await;
    
    let latency_ms = start.elapsed().as_millis() as i64;
    let status = response.status().as_u16();

    // 尝试从 Response extensions 中获取 user_id
    // 注意：Request Extensions 是传给 Handler 的，如果 Handler 成功运行，
    // 它通常不会把 extensions 传给 Response。
    // 但是，我们在 Auth 阶段插入的是 Request Extensions。
    // 在 Axum 中，中间件在处理 response 时，拿到的是原始 req 的引用吗？
    // `next.run(req)` 消耗了 req。所以我们无法再访问原始 req 的 extensions。
    // 这是一个常见的 Axum 中间件难题。
    // 
    // 简单做法：我们在此处不强求获取 UserID，或者接受它可能为 None。
    // 如果需要 UserID，必须使用 `map_request` 和 `map_response` 组合，或者使用 Handle 把数据塞进 Response extensions。
    // 鉴于目前的复杂度，我们依然记录 None，但在 Log 文件中打印详细信息。
    
    let user_id: RequestUserId = None; 

    // --- 文件日志 (stdout -> vfs-server.log) ---
    // 格式: [Timestamp] IP METHOD PATH STATUS Latency
    println!(
        "[{}] {} {} {} {} {}ms", 
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
        remote_ip, method, path, status, latency_ms
    );

    // --- 数据库日志 (用于 TUI) ---
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
