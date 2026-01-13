// src/metrics.rs

use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec,
    CounterVec, Gauge, HistogramVec, TextEncoder,
};
use std::time::Instant;

// 定义指标
static HTTP_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    )
    .unwrap()
});

static HTTP_REQUEST_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .unwrap()
});

static WEBSOCKET_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "websocket_connections_active",
        "Number of active WebSocket connections"
    )
    .unwrap()
});

static SYNC_OPERATIONS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "sync_operations_total",
        "Total number of sync operations",
        &["operation", "status"]
    )
    .unwrap()
});

static SYNC_CONFLICTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "sync_conflicts_total",
        "Total number of sync conflicts",
        &["type"]
    )
    .unwrap()
});

static STORAGE_BYTES_TOTAL: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "storage_bytes_total",
        "Total storage used in bytes"
    )
    .unwrap()
});

/// 初始化指标（确保所有指标都被注册）
pub fn init_metrics() {
    Lazy::force(&HTTP_REQUESTS_TOTAL);
    Lazy::force(&HTTP_REQUEST_DURATION);
    Lazy::force(&WEBSOCKET_CONNECTIONS);
    Lazy::force(&SYNC_OPERATIONS_TOTAL);
    Lazy::force(&SYNC_CONFLICTS_TOTAL);
    Lazy::force(&STORAGE_BYTES_TOTAL);
}

/// 指标中间件
pub async fn metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();

    let response = next.run(request).await;

    let duration = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();

    HTTP_REQUEST_DURATION
        .with_label_values(&[&method, &path])
        .observe(duration);

    response
}

/// 获取指标端点处理器
pub async fn metrics_handler() -> Result<String, StatusCode> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    
    encoder
        .encode_to_string(&metric_families)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// 指标记录辅助函数
pub struct MetricsRecorder;

impl MetricsRecorder {
    pub fn record_ws_connect() {
        WEBSOCKET_CONNECTIONS.inc();
    }

    pub fn record_ws_disconnect() {
        WEBSOCKET_CONNECTIONS.dec();
    }

    pub fn record_sync_operation(operation: &str, success: bool) {
        let status = if success { "success" } else { "failure" };
        SYNC_OPERATIONS_TOTAL
            .with_label_values(&[operation, status])
            .inc();
    }

    pub fn record_conflict(conflict_type: &str) {
        SYNC_CONFLICTS_TOTAL
            .with_label_values(&[conflict_type])
            .inc();
    }

    pub fn set_storage_bytes(bytes: f64) {
        STORAGE_BYTES_TOTAL.set(bytes);
    }
}
