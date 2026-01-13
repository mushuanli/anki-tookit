// crates/vfs-service/src/handlers/health.rs

use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

pub async fn health_check() -> (StatusCode, Json<Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "status": "healthy",
            "version": env!("CARGO_PKG_VERSION"),
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
}

pub async fn ready_check() -> StatusCode {
    // TODO: 检查数据库连接等
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let (status, json) = health_check().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json.0["status"], "healthy");
    }

    #[tokio::test]
    async fn test_ready_check() {
        let status = ready_check().await;
        assert_eq!(status, StatusCode::OK);
    }
}
