use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
use proxy_core::config::UpstreamTarget;
use proxy_core::export::{export_har, export_json, export_markdown};
use proxy_core::models::{HookEvent, Session, WsMessage};
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
        .route("/api/mcp-destination", get(get_mcp_dest).put(set_mcp_dest))
        .route("/api/upstream", get(get_upstream).put(set_upstream))
        .route("/api/upstreams", get(list_upstreams).post(add_upstream))
        .route("/api/upstreams/:name/activate", post(activate_upstream))
        .route(
            "/api/upstreams/:name",
            put(update_upstream).delete(delete_upstream),
        )
        .route("/api/health", get(health))
        .route("/api/sessions", get(list_sessions))
        .route("/api/session/start", post(start_session))
        .route("/api/session/:id", get(get_session))
        .route("/api/session/:id/stop", post(stop_session))
        .route("/api/session/:id/export", get(export_session))
        .route("/api/request/:id", get(get_request))
        .route("/api/capture", post(toggle_capture))
        .route("/api/capture/status", get(capture_status))
        .route("/api/requests", get(list_requests))
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
        // SPA fallback: return index.html for unknown paths
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

    event.permission_mode = payload["permissionMode"]
        .as_str()
        .unwrap_or("")
        .to_string();
    event.transcript_path = payload["transcriptPath"]
        .as_str()
        .unwrap_or("")
        .to_string();
    event.hook_input = payload["hookInput"].clone();
    if let Some(env) = payload["environmentVariables"].as_object() {
        for (k, v) in env {
            event
                .environment_variables
                .insert(k.clone(), v.as_str().unwrap_or("").to_string());
        }
    }

    let _ = state.hook_store.push(event.clone());
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
    if let Some(mut event) = state.hook_store.get_by_id(id) {
        if let Some(exit_code) = payload["exitCode"].as_i64() {
            event.exit_code = exit_code as i32;
        }
        if let Some(stdout) = payload["stdout"].as_str() {
            event.stdout = stdout.to_string();
        }
        if let Some(stderr) = payload["stderr"].as_str() {
            event.stderr = stderr.to_string();
        }
        let _ = state.hook_store.push(event.clone());
    }
    Json(serde_json::json!({"ok": true}))
}

async fn update_hook_event_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(mut event) = state.hook_store.get_by_id(&id) {
        if let Some(exit_code) = payload["exitCode"].as_i64() {
            event.exit_code = exit_code as i32;
        }
        if let Some(stdout) = payload["stdout"].as_str() {
            event.stdout = stdout.to_string();
        }
        if let Some(stderr) = payload["stderr"].as_str() {
            event.stderr = stderr.to_string();
        }
        let _ = state.hook_store.push(event.clone());
    }
    Json(serde_json::json!({"ok": true}))
}

// ── Clear ──

async fn clear_all(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.request_store.clear();
    state.hook_store.clear();
    let _ = state.broadcast_send(WsMessage::Cleared);
    Json(serde_json::json!({"ok": true}))
}

async fn clear_mcp(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.mcp_store.clear();
    let _ = state.broadcast_send(WsMessage::McpCleared);
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
    let new_dest = payload["destinationUrl"]
        .as_str()
        .map(|s| s.to_string());
    {
        let mut dest = state.mcp_destination.write().await;
        *dest = new_dest.clone();
    }
    // Notify clients (YARP-like config reload)
    let _ = state.broadcast_send(WsMessage::McpConfigChanged {
        destination_url: new_dest,
    });
    Json(serde_json::json!({"ok": true}))
}

// ── Upstream targets ──

/// Build UpstreamChanged message from current state.
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
        // Check if URL matches a named upstream → activate it
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
            // Ad-hoc: memory only, no persistence
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

    let mut upstreams = state.upstreams.write().await;
    if upstreams.iter().any(|u| u.name == name) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": format!("Upstream '{name}' already exists")}))).into_response();
    }
    upstreams.push(UpstreamTarget { name, url, token });
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
    // token: if key is present, update (empty string = clear)
    let token_update = payload.get("token").map(|v| {
        v.as_str().filter(|t| !t.is_empty()).map(|t| t.to_string())
    });

    let mut upstreams = state.upstreams.write().await;
    let is_active = state.active_upstream.read().await.clone() == name;
    if let Some(u) = upstreams.iter_mut().find(|u| u.name == name) {
        u.url = new_url.clone();
        if let Some(ref tok) = token_update {
            u.token = tok.clone();
        }
    } else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": format!("Upstream '{name}' not found")}))).into_response();
    }
    drop(upstreams);

    // Keep upstream_target in sync if this is the active upstream
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

    // If we deleted the active one, switch to the first remaining
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
    Json(serde_json::json!({
        "status": "ok",
        "requests": state.request_store.len(),
        "hooks": state.hook_store.len(),
        "mcp": state.mcp_store.len(),
    }))
}

// ── Sessions ──

async fn list_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let sessions = state.sessions.read().await;
    Json(serde_json::json!(sessions.clone()))
}

#[derive(Deserialize)]
struct StartSessionPayload {
    label: Option<String>,
}

async fn start_session(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<StartSessionPayload>,
) -> impl IntoResponse {
    let session = Session::new(payload.label);
    let _ = state.broadcast_send(WsMessage::SessionStarted(session.clone()));
    state.sessions.write().await.push(session.clone());
    Json(serde_json::json!(session))
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let sessions = state.sessions.read().await;
    if let Some(session) = sessions.iter().find(|s| s.id == id) {
        let requests: Vec<_> = session
            .request_ids
            .iter()
            .filter_map(|rid| state.request_store.get_by_id(rid))
            .collect();
        Json(serde_json::json!({
            "session": session,
            "requests": requests
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session not found"})),
        )
            .into_response()
    }
}

async fn stop_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
        session.stop();
        let _ = state.broadcast_send(WsMessage::SessionStopped(session.clone()));
        Json(serde_json::json!(session.clone())).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session not found"})),
        )
            .into_response()
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
    let sessions = state.sessions.read().await;
    let session = match sessions.iter().find(|s| s.id == id) {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Session not found"})),
            )
                .into_response();
        }
    };

    // Resolve requests
    let requests: Vec<_> = session
        .request_ids
        .iter()
        .filter_map(|rid| state.request_store.get_by_id(rid))
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

// ── Request detail ──

async fn get_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(req) = state.request_store.get_by_id(&id) {
        Json(serde_json::json!(req)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Request not found"})),
        )
            .into_response()
    }
}

async fn list_requests(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let requests = state.request_store.get_all();
    Json(serde_json::json!(requests))
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
