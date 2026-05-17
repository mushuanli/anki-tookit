use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::Response;
use bytes::Bytes;
use futures::StreamExt;
use proxy_core::models::{ProxiedRequest, WsMessage};
use proxy_core::sse::SseParser;
use tokio_stream::wrappers::ReceiverStream;

use crate::AppState;

const REDACTED_HEADERS: &[&str] = &["x-api-key", "authorization"];

fn redact_headers(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            let key = k.as_str().to_lowercase();
            let value = if REDACTED_HEADERS.contains(&key.as_str()) {
                "[REDACTED]".to_string()
            } else {
                v.to_str().unwrap_or("[binary]").to_string()
            };
            (k.to_string(), value)
        })
        .collect()
}

fn forward_headers(headers: &HeaderMap) -> HeaderMap {
    let mut fwd = HeaderMap::new();
    for (k, v) in headers.iter() {
        let key = k.as_str().to_lowercase();
        // Skip hop-by-hop and problematic headers
        if key == "host"
            || key == "connection"
            || key == "transfer-encoding"
            || key == "accept-encoding"
        {
            continue;
        }
        fwd.insert(k.clone(), v.clone());
    }
    fwd.insert("accept-encoding", HeaderValue::from_static("identity"));
    fwd
}

pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state)
}

async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let start = Instant::now();

    // Build captured request
    let mut captured = ProxiedRequest::new(method.as_str(), uri.path());
    captured.request_headers = redact_headers(&headers);
    captured.request_body = Some(String::from_utf8_lossy(&body).to_string());

    // Parse request body for metadata
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
        captured.model = json.get("model").and_then(|v| v.as_str()).map(String::from);
        captured.is_streaming = json.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
        captured.max_tokens = json.get("max_tokens").and_then(|v| v.as_u64()).map(|v| v as u32);
    }

    // Build upstream URL
    let upstream_url = format!("{}{}", state.config.proxy.api_target, uri.path());

    // Build upstream request
    let upstream_req = match state
        .client
        .request(method.clone(), &upstream_url)
        .headers(forward_headers(&headers))
        .body(body)
        .build()
    {
        Ok(req) => req,
        Err(e) => {
            captured.error = Some(format!("Failed to build upstream request: {}", e));
            captured.duration_ms = Some(start.elapsed().as_millis() as u64);
            let _ = state.request_store.push(captured.clone());
            let _ = state.broadcast_send(WsMessage::NewRequest(captured));
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(e.to_string()))
                .unwrap();
        }
    };

    // Execute upstream request
    let upstream_resp = match state.client.execute(upstream_req).await {
        Ok(resp) => resp,
        Err(e) => {
            captured.error = Some(format!("Upstream error: {}", e));
            captured.duration_ms = Some(start.elapsed().as_millis() as u64);
            let _ = state.request_store.push(captured.clone());
            let _ = state.broadcast_send(WsMessage::NewRequest(captured));
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Upstream error: {}", e)))
                .unwrap();
        }
    };

    let status = upstream_resp.status();
    captured.status_code = Some(status.as_u16());
    captured.response_headers = redact_headers(upstream_resp.headers());

    // Determine content type
    let content_type = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if content_type.contains("text/event-stream") || captured.is_streaming {
        handle_streaming_response(state, captured, upstream_resp, start).await
    } else {
        handle_non_streaming_response(state, captured, upstream_resp, start).await
    }
}

async fn handle_non_streaming_response(
    state: Arc<AppState>,
    mut captured: ProxiedRequest,
    upstream_resp: reqwest::Response,
    start: Instant,
) -> Response<Body> {
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    match upstream_resp.bytes().await {
        Ok(body_bytes) => {
            captured.response_body = Some(String::from_utf8_lossy(&body_bytes).to_string());
            // Parse response for token usage
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                captured.message_id = json
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                captured.stop_reason = json
                    .get("stop_reason")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                if let Some(usage) = json.get("usage") {
                    captured.input_tokens =
                        usage.get("input_tokens").and_then(|v| v.as_u64()).map(|v| v as u32);
                    captured.output_tokens =
                        usage.get("output_tokens").and_then(|v| v.as_u64()).map(|v| v as u32);
                    captured.cache_creation_input_tokens = usage
                        .get("cache_creation_input_tokens")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                    captured.cache_read_input_tokens = usage
                        .get("cache_read_input_tokens")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32);
                }
            }
            captured.duration_ms = Some(start.elapsed().as_millis() as u64);

            let _ = state.request_store.push(captured.clone());
            let _ = state.broadcast_send(WsMessage::NewRequest(captured));

            // Record in active sessions
            record_in_sessions(&state).await;

            let mut resp = Response::builder().status(status);
            for (k, v) in resp_headers.iter() {
                if k.as_str().to_lowercase() != "transfer-encoding" {
                    resp = resp.header(k.clone(), v.clone());
                }
            }
            resp.body(Body::from(body_bytes)).unwrap()
        }
        Err(e) => {
            captured.error = Some(format!("Failed to read response: {}", e));
            captured.duration_ms = Some(start.elapsed().as_millis() as u64);
            let _ = state.request_store.push(captured.clone());
            let _ = state.broadcast_send(WsMessage::NewRequest(captured));
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("Failed to read response: {}", e)))
                .unwrap()
        }
    }
}

async fn handle_streaming_response(
    state: Arc<AppState>,
    mut captured: ProxiedRequest,
    upstream_resp: reqwest::Response,
    start: Instant,
) -> Response<Body> {
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Channel to forward response body to client while capturing
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, String>>(64);

    let state_clone = state.clone();
    let req_id = captured.id.clone();

    tokio::spawn(async move {
        let mut stream = upstream_resp.bytes_stream();
        let mut parser = SseParser::new();
        let mut first_token = true;
        let stream_start = Instant::now();

        let mut accumulated_body = String::new();

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if first_token {
                        captured.time_to_first_token_ms =
                            Some(stream_start.elapsed().as_millis() as u64);
                        first_token = false;
                    }
                    accumulated_body.push_str(&String::from_utf8_lossy(&bytes));

                    // Parse SSE events
                    let events = parser.feed(&bytes);
                    for ev in &events {
                        // Broadcast each SSE event
                        let _ = state_clone.broadcast_send(WsMessage::SseEvent {
                            request_id: req_id.clone(),
                            event: ev.clone(),
                        });
                    }
                    captured.sse_events.extend(events);

                    // Update tracking fields from events
                    for ev in &captured.sse_events {
                        if let Some(ref data_str) = ev.data {
                            if let Some(data) = parser.parse_message_data(data_str) {
                                match parser.event_kind(&data) {
                                    Some("message_start") => {
                                        if captured.message_id.is_none() {
                                            captured.message_id = parser
                                                .message_id(&data)
                                                .map(String::from);
                                        }
                                        if captured.model.is_none() {
                                            captured.model = parser
                                                .model_from_start(&data)
                                                .map(String::from);
                                        }
                                        if captured.input_tokens.is_none() {
                                            captured.input_tokens =
                                                parser.input_tokens_from_start(&data);
                                        }
                                    }
                                    Some("message_delta") => {
                                        if let Some((in_tok, out_tok)) =
                                            parser.usage_from_delta(&data)
                                        {
                                            captured.input_tokens = Some(in_tok);
                                            captured.output_tokens = Some(out_tok);
                                        }
                                        if captured.stop_reason.is_none() {
                                            captured.stop_reason = parser
                                                .stop_reason(&data)
                                                .map(String::from);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if tx.send(Ok(bytes)).await.is_err() {
                        break; // Client disconnected
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(format!("Stream error: {}", e)))
                        .await;
                    break;
                }
            }
        }

        // Finalize
        captured.response_body = Some(accumulated_body);
        captured.duration_ms = Some(start.elapsed().as_millis() as u64);

        let _ = state_clone.request_store.push(captured.clone());
        let _ = state_clone.broadcast_send(WsMessage::RequestUpdated(captured));
        record_in_sessions(&state_clone).await;
    });

    let body = Body::from_stream(ReceiverStream::new(rx));

    let mut resp = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        let key = k.as_str().to_lowercase();
        if key != "transfer-encoding" && key != "content-encoding" {
            resp = resp.header(k.clone(), v.clone());
        }
    }
    // Ensure streaming content type
    resp = resp.header("content-type", "text/event-stream");
    resp.body(body).unwrap()
}

async fn record_in_sessions(state: &AppState) {
    let mut sessions = state.sessions.write().await;
    for session in sessions.iter_mut() {
        if session.status == proxy_core::models::SessionStatus::Recording {
            // Add last request id from store
            if let Some(last) = state.request_store.get_all().last() {
                if session.request_ids.last() != Some(&last.id) {
                    session.request_ids.push(last.id.clone());
                }
            }
        }
    }
}
