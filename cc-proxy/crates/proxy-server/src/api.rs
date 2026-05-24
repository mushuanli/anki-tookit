use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use proxy_core::config::UpstreamTarget;
use proxy_core::export::{export_har, export_json, export_markdown};
use proxy_core::models::{HookEvent, WsMessage};
use serde::Deserialize;

use crate::AppState;

pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        // WebSocket upgrade (must be before fallback)
        .route("/ws", get(crate::ws::ws_handler))
        // API routes
        .route("/api/hook-event", post(hook_event).put(update_hook_event))
        .route("/api/hook-event/:id", put(update_hook_event_by_id))
        .route("/api/clear", post(clear_all))
        .route("/api/clear-mcp", post(clear_mcp))
        .route("/api/clear-hooks", post(clear_hooks))
        .route("/api/mcp-destination", get(get_mcp_dest).put(set_mcp_dest))
        .route("/api/upstream", get(get_upstream).put(set_upstream))
        .route("/api/upstreams", get(list_upstreams).post(add_upstream))
        .route("/api/upstreams/:name/activate", post(activate_upstream))
        .route(
            "/api/upstreams/:name",
            put(update_upstream).delete(delete_upstream),
        )
        .route("/api/health", get(health))
        // Sessions
        .route("/api/sessions", get(list_sessions))
        .route("/api/session/:id", get(get_session).put(rename_session).delete(delete_session))
        .route("/api/session/:id/export", get(export_session))
        // Requests
        .route("/api/request/:id", get(get_request).delete(delete_single_request))
        .route("/api/requests", get(list_requests).delete(delete_requests_batch))
        .route("/api/capture", post(toggle_capture))
        .route("/api/capture/status", get(capture_status))
        // Static files + SPA fallback
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
                .body(Body::from(file.data.into_owned()))
                .unwrap()
        }
        None => match WwwRoot::get("index.html") {
            Some(file) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(Body::from(file.data.into_owned()))
                .unwrap(),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not found"))
                .unwrap(),
        },
    }
}

// ── Hook event handlers ──

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
            event.environment_variables.insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    let _ = state.db.insert_hook(&event);
    let _ = state.broadcast_send(WsMessage::NewHook(event.clone()));

    Json(serde_json::json!({
        "exitCode": event.exit_code,
        "stdout": event.stdout,
        "stderr": event.stderr,
    }))
}

async fn update_hook_event(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = payload["id"].as_str().unwrap_or("");
    let hooks = state.db.list_hooks().unwrap_or_default();
    if let Some(mut event) = hooks.into_iter().find(|h| h.id == id) {
        if let Some(exit_code) = payload["exitCode"].as_i64() {
            event.exit_code = exit_code as i32;
        }
        if let Some(stdout) = payload["stdout"].as_str() {
            event.stdout = stdout.to_string();
        }
        if let Some(stderr) = payload["stderr"].as_str() {
            event.stderr = stderr.to_string();
        }
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
        if let Some(exit_code) = payload["exitCode"].as_i64() {
            event.exit_code = exit_code as i32;
        }
        if let Some(stdout) = payload["stdout"].as_str() {
            event.stdout = stdout.to_string();
        }
        if let Some(stderr) = payload["stderr"].as_str() {
            event.stderr = stderr.to_string();
        }
        let _ = state.db.insert_hook(&event);
    }
    Json(serde_json::json!({"ok": true}))
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

// ── MCP configuration ──

async fn get_mcp_dest(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dest = state.mcp_destination.read().await.clone();
    Json(serde_json::json!({"destinationUrl": dest}))
}

async fn set_mcp_dest(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let new_dest = payload["destinationUrl"].as_str().map(|s| s.to_string());
    {
        let mut dest = state.mcp_destination.write().await;
        *dest = new_dest.clone();
    }
    let _ = state.broadcast_send(WsMessage::McpConfigChanged {
        destination_url: new_dest,
    });
    Json(serde_json::json!({"ok": true}))
}

// ── Upstream targets ──

async fn upstream_changed_msg(state: &AppState) -> WsMessage {
    WsMessage::UpstreamChanged {
        active_url: state.upstream_target.read().await.clone(),
        upstreams: state.upstream_info_list().await,
    }
}

async fn get_upstream(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let url = state.upstream_target.read().await.clone();
    let name = state.active_upstream.read().await.clone();
    Json(serde_json::json!({"targetUrl": url, "name": name}))
}

async fn set_upstream(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(input_url) = payload["targetUrl"].as_str() {
        let input_url = input_url.trim_end_matches('/').to_string();
        let upstreams = state.upstreams.read().await.clone();
        if let Some(u) = upstreams.iter().find(|u| u.url == input_url) {
            let name = u.name.clone();
            drop(upstreams);
            *state.active_upstream.write().await = name;
            *state.upstream_target.write().await = input_url.clone();
            state.persist_upstreams().await;
            let msg = upstream_changed_msg(&state).await;
            let _ = state.broadcast_send(msg);
        } else {
            *state.upstream_target.write().await = input_url.clone();
            *state.active_upstream.write().await = String::new();
            let msg = upstream_changed_msg(&state).await;
            let _ = state.broadcast_send(msg);
        }
    }
    let target = state.upstream_target.read().await.clone();
    let name = state.active_upstream.read().await.clone();
    Json(serde_json::json!({"ok": true, "targetUrl": target, "name": name}))
}

// ── Multi-upstream CRUD ──

async fn list_upstreams(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "upstreams": state.upstream_info_list().await,
        "activeUrl": state.upstream_target.read().await.clone(),
    }))
}

async fn add_upstream(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let name = match payload["name"].as_str() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Name is required"}))).into_response(),
    };
    let url = match payload["url"].as_str() {
        Some(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "URL is required"}))).into_response(),
    };
    let token = payload["token"].as_str().filter(|t| !t.is_empty()).map(|t| t.to_string());
    let model_map: HashMap<String, String> = payload["model_map"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut upstreams = state.upstreams.write().await;
    if upstreams.iter().any(|u| u.name == name) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("Upstream '{name}' already exists")}))).into_response();
    }
    upstreams.push(UpstreamTarget { name, url, token, model_map });
    drop(upstreams);

    state.persist_upstreams().await;
    let msg = upstream_changed_msg(&state).await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn update_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Response<Body> {
    let new_url = match payload["url"].as_str() {
        Some(u) if !u.is_empty() => u.trim_end_matches('/').to_string(),
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "URL is required"}))).into_response(),
    };
    let token_update = payload.get("token").map(|v| {
        v.as_str().filter(|t| !t.is_empty()).map(|t| t.to_string())
    });
    let model_map_update: Option<HashMap<String, String>> = payload.get("model_map").map(|v| {
        v.as_object()
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    });

    let mut upstreams = state.upstreams.write().await;
    let is_active = state.active_upstream.read().await.clone() == name;
    if let Some(u) = upstreams.iter_mut().find(|u| u.name == name) {
        u.url = new_url.clone();
        if let Some(ref tok) = token_update {
            u.token = tok.clone();
        }
        if let Some(ref map) = model_map_update {
            u.model_map = map.clone();
        }
    } else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("Upstream '{name}' not found")}))).into_response();
    }
    drop(upstreams);

    if is_active {
        *state.upstream_target.write().await = new_url;
    }

    state.persist_upstreams().await;
    let msg = upstream_changed_msg(&state).await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn delete_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response<Body> {
    let mut upstreams = state.upstreams.write().await;
    if upstreams.len() <= 1 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot delete the only upstream"}))).into_response();
    }

    let idx = match upstreams.iter().position(|u| u.name == name) {
        Some(i) => i,
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("Upstream '{name}' not found")}))).into_response(),
    };
    let was_active = upstreams[idx].name == *state.active_upstream.read().await;
    upstreams.remove(idx);

    if was_active {
        let new_active = upstreams[0].clone();
        *state.active_upstream.write().await = new_active.name.clone();
        *state.upstream_target.write().await = new_active.url;
    }
    drop(upstreams);

    state.persist_upstreams().await;
    let msg = upstream_changed_msg(&state).await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn activate_upstream(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response<Body> {
    let upstreams = state.upstreams.read().await;
    let target = match upstreams.iter().find(|u| u.name == name) {
        Some(u) => u.clone(),
        None => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("Upstream '{name}' not found")}))).into_response(),
    };
    drop(upstreams);

    let url = target.url;
    *state.active_upstream.write().await = name;
    *state.upstream_target.write().await = url.clone();

    state.persist_upstreams().await;
    let msg = upstream_changed_msg(&state).await;
    let _ = state.broadcast_send(msg);
    Json(serde_json::json!({"ok": true, "activeUrl": url})).into_response()
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
            Json(serde_json::json!({
                "session": session,
                "requests": requests
            }))
            .into_response()
        }
        _ => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"})))
                .into_response()
        }
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
                    request_id: session.id.clone(),
                });
            }
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"})))
                .into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
                .into_response()
        }
    }
}

async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_session(&id) {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"})))
                .into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
                .into_response()
        }
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
        _ => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Session not found"})))
                .into_response();
        }
    };

    let requests: Vec<_> = session
        .request_ids
        .iter()
        .filter_map(|rid| state.db.get_request(rid).ok().flatten())
        .collect();

    let format = query.format.as_deref().unwrap_or("json");

    match format {
        "json" => {
            let exported = export_json(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "application/json"),
                    (
                        "content-disposition",
                        &format!("attachment; filename=\"session_{}.json\"", session.id),
                    ),
                ],
                Json(exported),
            )
                .into_response()
        }
        "har" => {
            let har = export_har(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "application/json"),
                    (
                        "content-disposition",
                        &format!("attachment; filename=\"session_{}.har\"", session.id),
                    ),
                ],
                Json(har),
            )
                .into_response()
        }
        "markdown" | "md" => {
            let md = export_markdown(&session, &requests);
            (
                StatusCode::OK,
                [
                    ("content-type", "text/markdown; charset=utf-8"),
                    (
                        "content-disposition",
                        &format!("attachment; filename=\"session_{}.md\"", session.id),
                    ),
                ],
                md,
            )
                .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Unsupported format. Use: json, har, markdown"})),
        )
            .into_response(),
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
        _ => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Request not found"})))
                .into_response()
        }
    }
}

async fn delete_single_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.delete_request(&id) {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Request not found"})))
                .into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
                .into_response()
        }
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
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
                .into_response()
        }
    }
}

// ── Tee writer (packet capture) ──

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
    let _ = state.broadcast_send(WsMessage::TeeStatusChanged {
        enabled: payload.enabled,
    });
    Json(serde_json::json!({"ok": true, "enabled": payload.enabled}))
}

async fn capture_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let enabled = state.tee_writer.is_enabled();
    Json(serde_json::json!({"enabled": enabled}))
}
