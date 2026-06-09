use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use chrono::{Duration, Utc};
use proxy_core::config::{ModelInfo, Provider, TierRule, UpstreamConfig};
use proxy_core::export::{export_har, export_json, export_markdown, export_yaml};
use proxy_core::models::{HookEvent, WsMessage};
use serde::Deserialize;

use crate::AppState;

pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        // WebSocket
        .route("/ws", get(crate::ws::ws_handler))
        // Hooks
        .route("/api/hook-event", post(hook_event).put(update_hook_event))
        .route("/api/hook-event/:id", put(update_hook_event_by_id))
        // Clear
        .route("/api/clear", post(clear_all))
        .route("/api/clear-mcp", post(clear_mcp))
        .route("/api/clear-hooks", post(clear_hooks))
        // MCP
        .route("/api/mcp-destination", get(get_mcp_dest).put(set_mcp_dest))
        // Providers CRUD
        .route("/api/providers", get(list_providers).post(add_provider))
        .route(
            "/api/providers/:name",
            put(update_provider).delete(delete_provider),
        )
        // Upstreams CRUD
        .route("/api/upstreams", get(list_upstreams).post(add_upstream))
        .route("/api/upstreams/:name/activate", post(activate_upstream))
        .route(
            "/api/upstreams/:name",
            put(update_upstream).delete(delete_upstream),
        )
        // Health
        .route("/api/health", get(health))
        // Sessions
        .route("/api/sessions", get(list_sessions))
        .route(
            "/api/session/:id",
            get(get_session).put(rename_session).delete(delete_session),
        )
        .route("/api/session/:id/export", get(export_session))
        // Requests
        .route("/api/request/:id", get(get_request).delete(delete_single_request))
        .route("/api/requests", get(list_requests).delete(delete_requests_batch))
        // Capture
        .route("/api/capture", post(toggle_capture))
        .route("/api/capture/status", get(capture_status))
        // Retention & cleanup
        .route("/api/retention", get(get_retention).put(update_retention))
        .route("/api/cleanup", post(trigger_cleanup))
        // Effort
        .route("/api/effort", get(get_effort).put(set_effort))
        // Costs
        .route("/api/costs", get(get_costs))
        // Static files
        .fallback(get(serve_static))
        .with_state(state)
}

// ── Embedded static files ──

#[derive(rust_embed::RustEmbed)]
#[folder = "../../wwwroot/"]
struct WwwRoot;

async fn serve_static(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match WwwRoot::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", mime.as_ref())
                .header("cache-control", "no-cache, no-store, must-revalidate")
                .body(Body::from(file.data.into_owned()))
                .unwrap()
        }
        None => match WwwRoot::get("index.html") {
            Some(file) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .header("cache-control", "no-cache, no-store, must-revalidate")
                .body(Body::from(file.data.into_owned()))
                .unwrap(),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not found"))
                .unwrap(),
        },
    }
}

// ── Hook events ──

async fn hook_event(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut event = HookEvent::new(
        payload["hookEventName"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
        payload["sessionId"].as_str().unwrap_or("").to_string(),
        payload["cwd"].as_str().unwrap_or("").to_string(),
    );
    event.permission_mode = payload["permissionMode"].as_str().unwrap_or("").to_string();
    event.transcript_path = payload["transcriptPath"].as_str().unwrap_or("").to_string();
    event.hook_input = payload["hookInput"].clone();
    if let Some(env) = payload["environmentVariables"].as_object() {
        for (k, v) in env {
            event
                .environment_variables
                .insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }
    let _ = state.db.insert_hook(&event);
    let _ = state.broadcast_send(WsMessage::NewHook(event.clone()));
    Json(serde_json::json!({"exitCode": event.exit_code, "stdout": event.stdout, "stderr": event.stderr}))
}

async fn update_hook_event(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = payload["id"].as_str().unwrap_or("");
    let hooks = state.db.list_hooks().unwrap_or_default();
    if let Some(mut event) = hooks.into_iter().find(|h| h.id == id) {
        apply_hook_update(&mut event, &payload);
        let _ = state.db.insert_hook(&event);
    }
    Json(serde_json::json!({"ok": true}))
}

async fn update_hook_event_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let hooks = state.db.list_hooks().unwrap_or_default();
    if let Some(mut event) = hooks.into_iter().find(|h| h.id == id) {
        apply_hook_update(&mut event, &payload);
        let _ = state.db.insert_hook(&event);
    }
    Json(serde_json::json!({"ok": true}))
}

fn apply_hook_update(event: &mut HookEvent, payload: &serde_json::Value) {
    if let Some(code) = payload["exitCode"].as_i64() {
        event.exit_code = code as i32;
    }
    if let Some(s) = payload["stdout"].as_str() {
        event.stdout = s.to_string();
    }
    if let Some(s) = payload["stderr"].as_str() {
        event.stderr = s.to_string();
    }
}

// ── Clear ──

async fn clear_all(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state.db.clear_requests();
    let _ = state.db.clear_hooks();
    let _ = state.broadcast_send(WsMessage::Cleared);
    Json(serde_json::json!({"ok": true}))
}

async fn clear_mcp(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state.db.clear_mcp();
    let _ = state.broadcast_send(WsMessage::McpCleared);
    Json(serde_json::json!({"ok": true}))
}

async fn clear_hooks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state.db.clear_hooks();
    Json(serde_json::json!({"ok": true}))
}

// ── MCP ──

async fn get_mcp_dest(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dest = state.mcp_destination.read().await.clone();
    Json(serde_json::json!({"destinationUrl": dest}))
}

async fn set_mcp_dest(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let new_dest = payload["destinationUrl"].as_str().map(String::from);
    *state.mcp_destination.write().await = new_dest.clone();
    let _ = state.broadcast_send(WsMessage::McpConfigChanged { destination_url: new_dest });
    Json(serde_json::json!({"ok": true}))
}

// ── Providers CRUD ──

async fn list_providers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "providers": state.provider_info_list().await
    }))
}

async fn add_provider(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let name = match payload["name"].as_str().filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return bad_request("Name is required"),
    };
    let url = match payload["url"].as_str().filter(|s| !s.is_empty()) {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => return bad_request("URL is required"),
    };
    let token = payload["token"].as_str().filter(|s| !s.is_empty()).map(String::from);
    let models = parse_model_list(&payload["models"]);

    let mut providers = state.providers.write().await;
    if providers.iter().any(|p| p.name == name) {
        return conflict(&format!("Provider '{name}' already exists"));
    }
    providers.push(Provider { name, url, token, models });
    drop(providers);

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn update_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let new_url = match payload["url"].as_str().filter(|s| !s.is_empty()) {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => return bad_request("URL is required"),
    };

    let mut providers = state.providers.write().await;
    let p = match providers.iter_mut().find(|p| p.name == name) {
        Some(p) => p,
        None => return not_found(&format!("Provider '{name}' not found")),
    };
    p.url = new_url;
    // Only update token if provided; empty string clears it
    if let Some(tok) = payload.get("token") {
        p.token = tok.as_str().filter(|s| !s.is_empty()).map(String::from);
    }
    if let Some(mods) = payload.get("models") {
        p.models = parse_model_list(mods);
    }
    drop(providers);

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn delete_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response<Body> {
    let mut providers = state.providers.write().await;
    let idx = match providers.iter().position(|p| p.name == name) {
        Some(i) => i,
        None => return not_found(&format!("Provider '{name}' not found")),
    };
    providers.remove(idx);
    drop(providers);

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

// ── Upstreams CRUD ──

async fn list_upstreams(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "active_upstream": *state.active_upstream.read().await,
        "upstreams": state.upstream_info_list().await,
        "providers": state.provider_info_list().await,
        "active_effort": *state.active_effort.read().await,
    }))
}

async fn add_upstream(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let name = match payload["name"].as_str().filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return bad_request("Name is required"),
    };

    let mut upstreams = state.upstreams.write().await;
    if upstreams.iter().any(|u| u.name == name) {
        return conflict(&format!("Upstream '{name}' already exists"));
    }
    upstreams.push(parse_upstream_config(name, &payload));
    drop(upstreams);

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn update_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let mut upstreams = state.upstreams.write().await;
    let idx = match upstreams.iter().position(|u| u.name == name) {
        Some(i) => i,
        None => return not_found(&format!("Upstream '{name}' not found")),
    };
    upstreams[idx] = parse_upstream_config(name, &payload);
    drop(upstreams);

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn delete_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response<Body> {
    let mut upstreams = state.upstreams.write().await;
    if upstreams.len() <= 1 {
        return bad_request("Cannot delete the only upstream");
    }
    let idx = match upstreams.iter().position(|u| u.name == name) {
        Some(i) => i,
        None => return not_found(&format!("Upstream '{name}' not found")),
    };
    let was_active = upstreams[idx].name == *state.active_upstream.read().await;
    upstreams.remove(idx);
    let first_name = upstreams[0].name.clone();
    drop(upstreams);

    if was_active {
        *state.active_upstream.write().await = first_name;
    }

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn activate_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response<Body> {
    let exists = state.upstreams.read().await.iter().any(|u| u.name == name);
    if !exists {
        return not_found(&format!("Upstream '{name}' not found"));
    }
    *state.active_upstream.write().await = name.clone();

    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true, "active": name})).into_response()
}

// ── Health ──

async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let req_count = state.db.count_requests().unwrap_or(0);
    let hook_count = state.db.list_hooks().map(|v| v.len() as i64).unwrap_or(0);
    let mcp_count = state.db.list_mcp().map(|v| v.len() as i64).unwrap_or(0);
    Json(serde_json::json!({
        "status": "ok",
        "requests": req_count,
        "hooks": hook_count,
        "mcp": mcp_count,
    }))
}

// ── Sessions ──

#[derive(Deserialize)]
struct SessionQuery {
    q: Option<String>,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SessionQuery>,
) -> impl IntoResponse {
    let sessions = state.db.list_sessions(query.q.as_deref()).unwrap_or_default();
    Json(serde_json::json!(sessions))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_session(&id) {
        Ok(Some(session)) => {
            let requests: Vec<_> = session
                .request_ids
                .iter()
                .filter_map(|rid| state.db.get_request(rid).ok().flatten())
                .collect();
            Json(serde_json::json!({"session": session, "requests": requests})).into_response()
        }
        _ => not_found("Session not found"),
    }
}

#[derive(Deserialize)]
struct RenameSessionPayload {
    label: String,
}

async fn rename_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<RenameSessionPayload>,
) -> impl IntoResponse {
    match state.db.rename_session(&id, &payload.label) {
        Ok(true) => {
            if let Ok(Some(session)) = state.db.get_session(&id) {
                let _ = state.broadcast_send(WsMessage::SessionUpdated {
                    request_id: session.id,
                });
            }
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Ok(false) => not_found("Session not found"),
        Err(e) => internal_error(&e.to_string()),
    }
}

async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_session(&id) {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => not_found("Session not found"),
        Err(e) => internal_error(&e.to_string()),
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    format: Option<String>,
}

async fn export_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> impl IntoResponse {
    let session = match state.db.get_session(&id) {
        Ok(Some(s)) => s,
        _ => return not_found("Session not found"),
    };
    let requests = state
        .db
        .list_requests(Some(&id), None, None, None, None)
        .unwrap_or_default();
    let format = query.format.as_deref().unwrap_or("json");
    match format {
        "json" => {
            let data = export_json(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "application/json"),
                    ("content-disposition", &format!("attachment; filename=\"session_{}.json\"", session.id)),
                ],
                Json(data),
            ).into_response()
        }
        "har" => {
            let data = export_har(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "application/json"),
                    ("content-disposition", &format!("attachment; filename=\"session_{}.har\"", session.id)),
                ],
                Json(data),
            ).into_response()
        }
        "markdown" | "md" => {
            let md = export_markdown(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "text/markdown; charset=utf-8"),
                    ("content-disposition", &format!("attachment; filename=\"session_{}.md\"", session.id)),
                ],
                md,
            ).into_response()
        }
        "yaml" | "yml" => {
            // Pick the latest request by timestamp and load its SSE events.
            let latest = requests
                .iter()
                .max_by_key(|r| &r.timestamp)
                .cloned()
                .map(|mut r| {
                    if let Ok(events) = state.db.get_sse_events(&r.id) {
                        r.sse_events = events;
                    }
                    r
                });
            let yaml_requests: Vec<_> = latest.into_iter().collect();
            let yaml = export_yaml(&session, &yaml_requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "application/x-yaml; charset=utf-8"),
                    ("content-disposition", &format!("attachment; filename=\"request_{}.yaml\"", session.id)),
                ],
                yaml,
            ).into_response()
        }
        _ => bad_request("Unsupported format. Use: json, har, markdown, yaml"),
    }
}

// ── Requests ──

#[derive(Deserialize)]
struct ListRequestsQuery {
    session_id: Option<String>,
    q: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<i64>,
}

async fn list_requests(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListRequestsQuery>,
) -> impl IntoResponse {
    let requests = state
        .db
        .list_requests(
            query.session_id.as_deref(),
            query.q.as_deref(),
            query.from.as_deref(),
            query.to.as_deref(),
            query.limit,
        )
        .unwrap_or_default();
    Json(serde_json::json!(requests))
}

async fn get_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_request(&id) {
        Ok(Some(req)) => Json(serde_json::json!(req)).into_response(),
        _ => not_found("Request not found"),
    }
}

async fn delete_single_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_request(&id) {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => not_found("Request not found"),
        Err(e) => internal_error(&e.to_string()),
    }
}

#[derive(Deserialize)]
struct DeleteRequestsBody {
    ids: Vec<String>,
}

async fn delete_requests_batch(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteRequestsBody>,
) -> impl IntoResponse {
    match state.db.delete_requests(&payload.ids) {
        Ok(n) => Json(serde_json::json!({"ok": true, "deleted": n})).into_response(),
        Err(e) => internal_error(&e.to_string()),
    }
}

// ── Capture ──

#[derive(Deserialize)]
struct CaptureToggle {
    enabled: bool,
}

async fn toggle_capture(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CaptureToggle>,
) -> impl IntoResponse {
    state.tee_writer.set_enabled(payload.enabled);
    if payload.enabled {
        let _ = state.tee_writer.start_new_file().await;
    }
    let _ = state.broadcast_send(WsMessage::TeeStatusChanged { enabled: payload.enabled });
    Json(serde_json::json!({"ok": true, "enabled": payload.enabled}))
}

async fn capture_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({"enabled": state.tee_writer.is_enabled()}))
}

// ── Retention & Cleanup ──

async fn get_retention(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let r = state.retention.read().await.clone();
    Json(serde_json::json!({
        "request_retention_hours": r.request_retention_hours,
        "session_max_count": r.session_max_count,
    }))
}

#[derive(Deserialize)]
struct RetentionPayload {
    request_retention_hours: Option<u32>,
    session_max_count: Option<u32>,
}

async fn update_retention(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RetentionPayload>,
) -> impl IntoResponse {
    let mut r = state.retention.write().await;
    if let Some(h) = payload.request_retention_hours {
        r.request_retention_hours = h;
    }
    if let Some(c) = payload.session_max_count {
        r.session_max_count = c;
    }
    drop(r);
    state.persist_config().await;
    Json(serde_json::json!({"ok": true}))
}

async fn trigger_cleanup(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (reqs, sessions) = crate::run_cleanup(&state).await;
    Json(serde_json::json!({
        "ok": true,
        "deleted_requests": reqs,
        "deleted_sessions": sessions,
    }))
}

// ── Helpers ──

fn parse_model_list(v: &serde_json::Value) -> Vec<ModelInfo> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .map(|x| {
                    if let Some(s) = x.as_str() {
                        ModelInfo::new(s.to_string())
                    } else {
                        ModelInfo {
                            id: x["id"].as_str().unwrap_or("").to_string(),
                            price_per_million_input: x["price_per_million_input"].as_f64(),
                            price_per_million_output: x["price_per_million_output"].as_f64(),
                        }
                    }
                })
                .filter(|m| !m.id.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_string_array(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn parse_tier_rule(v: &serde_json::Value) -> Option<TierRule> {
    if v.is_null() {
        return None;
    }
    let provider = v["provider"].as_str().unwrap_or("").to_string();
    let model = v["model"].as_str().unwrap_or("").to_string();
    if provider.is_empty() && model.is_empty() {
        return None;
    }
    Some(TierRule {
        keywords: parse_string_array(&v["keywords"]),
        provider,
        model,
    })
}

fn parse_upstream_config(name: String, payload: &serde_json::Value) -> UpstreamConfig {
    UpstreamConfig {
        name,
        high: parse_tier_rule(&payload["high"]),
        mid: parse_tier_rule(&payload["mid"]),
        low: parse_tier_rule(&payload["low"]),
        default_provider: payload["default_provider"].as_str().unwrap_or("").to_string(),
        default_model: payload["default_model"].as_str().unwrap_or("").to_string(),
    }
}

fn bad_request(msg: &str) -> Response<Body> {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg}))).into_response()
}

fn conflict(msg: &str) -> Response<Body> {
    (StatusCode::CONFLICT, Json(serde_json::json!({"error": msg}))).into_response()
}

fn not_found(msg: &str) -> Response<Body> {
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": msg}))).into_response()
}

fn internal_error(msg: &str) -> Response<Body> {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": msg}))).into_response()
}

// ── Effort ──

const VALID_EFFORTS: &[&str] = &["auto", "low", "medium", "high", "xhigh", "max", "ultracode"];

async fn get_effort(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({"effort": *state.active_effort.read().await}))
}

async fn set_effort(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let effort = match payload["effort"].as_str() {
        Some(e) => e.to_string(),
        None => return bad_request("Missing 'effort' field"),
    };
    if !VALID_EFFORTS.contains(&effort.as_str()) {
        return bad_request(&format!(
            "Invalid effort '{}'. Valid: {}",
            effort,
            VALID_EFFORTS.join(", ")
        ));
    }
    *state.active_effort.write().await = effort.clone();
    state.persist_config().await;
    let msg = state.upstream_changed_msg().await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true, "effort": effort})).into_response()
}

// ── Costs ──

async fn get_costs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response<Body> {
    let now = Utc::now();
    let default_from = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .to_rfc3339();
    let default_to = (now.date_naive() + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .to_rfc3339();
    let from = params.get("from").map(|s| s.as_str()).unwrap_or(&default_from);
    let to = params.get("to").map(|s| s.as_str()).unwrap_or(&default_to);

    match state.db.get_cost_data(from, to) {
        Ok(data) => Json(data).into_response(),
        Err(e) => internal_error(&format!("Failed to query costs: {e}")),
    }
}
