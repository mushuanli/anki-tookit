use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use proxy_core::models::WsMessage;
use serde_json::json;

use crate::AppState;

pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .fallback(mcp_handler)
        .with_state(state)
}

async fn mcp_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let dest = state.mcp_destination.read().await;
    let destination = match dest.as_ref() {
        Some(d) => d.clone(),
        None => {
            drop(dest);
            return mcp_not_configured().into_response();
        }
    };
    drop(dest);

    // Parse JSON-RPC method for display
    let method_str = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
        json.get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        "parse_error".to_string()
    };

    // Build captured request (reuse ProxiedRequest model)
    let mut captured = proxy_core::models::ProxiedRequest::new("POST", "/mcp");
    captured.request_body = Some(String::from_utf8_lossy(&body).to_string());
    captured.model = Some(method_str);

    // Forward to MCP destination
    let upstream_url = format!("{}/", destination.trim_end_matches('/'));
    let upstream_req = match state
        .client
        .post(&upstream_url)
        .headers(filter_mcp_headers(&headers))
        .body(body)
        .build()
    {
        Ok(req) => req,
        Err(e) => {
            captured.error = Some(format!("Failed to build MCP request: {}", e));
            let _ = state.db.insert_mcp(&captured);
            let _ = state.broadcast_send(WsMessage::NewMcp(captured));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": e.to_string()},
                    "id": null
                })),
            )
                .into_response();
        }
    };

    match state.client.execute(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            match resp.bytes().await {
                Ok(resp_bytes) => {
                    captured.status_code = Some(status.as_u16());
                    captured.response_body =
                        Some(String::from_utf8_lossy(&resp_bytes).to_string());

                    let _ = state.db.insert_mcp(&captured);
                    let _ = state.broadcast_send(WsMessage::NewMcp(captured));

                    let mut response = Response::builder().status(status);
                    for (k, v) in resp_headers.iter() {
                        if k.as_str().to_lowercase() != "transfer-encoding" {
                            response = response.header(k.clone(), v.clone());
                        }
                    }
                    response.body(Body::from(resp_bytes)).unwrap()
                }
                Err(e) => {
                    captured.error = Some(format!("Failed to read MCP response: {}", e));
                    let _ = state.db.insert_mcp(&captured);
                    let _ = state.broadcast_send(WsMessage::NewMcp(captured));
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32603, "message": e.to_string()},
                            "id": null
                        })),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            captured.error = Some(format!("MCP upstream error: {}", e));
            let _ = state.db.insert_mcp(&captured);
            let _ = state.broadcast_send(WsMessage::NewMcp(captured));
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": format!("Upstream error: {}", e)},
                    "id": null
                })),
            )
                .into_response()
        }
    }
}

fn mcp_not_configured() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::OK,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32603,
                "message": "MCP proxy destination not configured. Set it at http://localhost:5000"
            },
            "id": null
        })),
    )
}

fn filter_mcp_headers(headers: &HeaderMap) -> HeaderMap {
    let mut fwd = HeaderMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        if key == "host"
            || key == "connection"
            || key == "transfer-encoding"
            || key == "accept-encoding"
        {
            continue;
        }
        fwd.insert(k.clone(), v.clone());
    }
    fwd
}
